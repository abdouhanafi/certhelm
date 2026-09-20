"""
Automatic certificate renewal workflow (controller side).

A renewal job walks through these states:

    awaiting_csr -> csr_ready -> ordering -> ordered -> installing -> installed
        (agent builds     (controller   (DigiCert order   (waiting for     (agent installs)
         key + CSR)        claims it)    being placed)     issuance)
    ... any step can end in: failed | cancelled | uncertain

Safety rules baked in here:
  * A global switch, stored in the database (NOT config.json, which the Settings
    form rewrites): off / live. Nothing contacts DigiCert or an agent when it is
    'off'. Even when 'live', a renewal only starts after an explicit click and
    confirmation, and only on servers whose administrator opted in
    (allow_cert_management in the agent's own config).
  * The step that places a DigiCert order is claimed with a compare-and-swap
    (csr_ready -> ordering), so one job can never place two orders.
  * If the outcome of an order request is ambiguous (timeout, 5xx) the job is
    'uncertain' and blocks any new job for that certificate until a human
    cancels it - an ambiguous failure must not become a double purchase.
  * The private key never leaves the server: the agent generates it and only
    sends the CSR. Before an issued certificate is handed back to the agent
    we check that it matches that CSR's public key.
"""

import datetime
import re
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

import database as db
import digicert_api as dc

MODES = ('off', 'live')
DEFAULT_MODE = 'live'
SETTING_MODE = 'renewal_mode'
SETTING_BASE_URL = 'digicert_base_url'

AGENT_LIVE_SECONDS = 180
MIN_CERT_MGMT_VERSION = (2, 1)

CSR_TIMEOUT_MIN = 15
ORDERING_TIMEOUT_MIN = 5
INSTALL_TIMEOUT_MIN = 30
ORDER_MAX_WAIT_DAYS = 14
ORDER_POLL_SECONDS = 60
WORKER_TICK_SECONDS = 20

_FAILED_ORDER_STATUSES = ('rejected', 'canceled', 'cancelled', 'revoked', 'denied', 'expired')
_PEM_CERT_RE = re.compile(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.S)


def get_mode():
    mode = db.get_setting(SETTING_MODE, DEFAULT_MODE)
    if mode == 'dry_run':
        return 'off'  # the removed Simulation mode: a database from that era must not silently go live
    return mode if mode in MODES else DEFAULT_MODE


def set_mode(mode):
    if mode not in MODES:
        raise ValueError(f'Mode invalide: {mode}')
    db.set_setting(SETTING_MODE, mode)


def get_base_url():
    return db.get_setting(SETTING_BASE_URL, dc.DEFAULT_BASE_URL) or dc.DEFAULT_BASE_URL


def parse_version(version):
    try:
        return tuple(int(p) for p in str(version).split('.'))
    except (TypeError, ValueError):
        return (0,)


def supports_cert_management(agent_version):
    return parse_version(agent_version) >= MIN_CERT_MGMT_VERSION


def _minutes_since(iso, now):
    try:
        return (now - datetime.datetime.fromisoformat(iso)).total_seconds() / 60
    except Exception:
        return 0


def _spki(public_key):
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _names_of(cert):
    names = set()
    try:
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        names.update(a.value.lower() for a in cn)
    except Exception:
        pass
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names.update(n.lower() for n in san.get_values_for_type(x509.DNSName))
    except Exception:
        pass
    return names


def normalize_csr(csr_pem):
    """Windows' certreq labels its output 'NEW CERTIFICATE REQUEST'."""
    return csr_pem.replace('NEW CERTIFICATE REQUEST', 'CERTIFICATE REQUEST').strip() + '\n'


def validate_csr(csr_pem, domain):
    """Parses the CSR the agent produced; returns the normalized PEM or raises ValueError."""
    try:
        csr = x509.load_pem_x509_csr(normalize_csr(csr_pem).encode())
    except Exception:
        raise ValueError("CSR illisible")
    if not csr.is_signature_valid:
        raise ValueError("Signature du CSR invalide")
    if domain.lower() not in _names_of_csr(csr):
        raise ValueError(f"Le CSR ne correspond pas au domaine {domain}")
    key = csr.public_key()
    if isinstance(key, rsa.RSAPublicKey):
        if key.key_size < 2048:
            raise ValueError("Clé RSA trop courte (< 2048 bits)")
    elif not isinstance(key, ec.EllipticCurvePublicKey):
        raise ValueError("Type de clé non pris en charge")
    return normalize_csr(csr_pem)


def _names_of_csr(csr):
    names = set(a.value.lower() for a in csr.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME))
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names.update(n.lower() for n in san.get_values_for_type(x509.DNSName))
    except Exception:
        pass
    return names


def validate_issued_chain(chain_pem, csr_pem, domain, now=None):
    """The certificate DigiCert issued must be for our CSR's key and our domain,
    and must not be expired. Returns the leaf's (not_after 'YYYY-MM-DD')."""
    blocks = _PEM_CERT_RE.findall(chain_pem)
    if not blocks:
        raise ValueError("Aucun certificat dans la réponse")
    leaf = x509.load_pem_x509_certificate(blocks[0].encode())
    csr = x509.load_pem_x509_csr(normalize_csr(csr_pem).encode())
    if _spki(leaf.public_key()) != _spki(csr.public_key()):
        raise ValueError("Le certificat émis ne correspond pas à la clé générée par l'agent")
    if domain.lower() not in _names_of(leaf):
        raise ValueError(f"Le certificat émis ne couvre pas {domain}")
    not_after = getattr(leaf, 'not_valid_after_utc', None) or leaf.not_valid_after
    now = now or datetime.datetime.now(datetime.timezone.utc)
    if not_after.tzinfo is None:
        now = now.replace(tzinfo=None)
    if not_after <= now:
        raise ValueError("Le certificat émis est déjà expiré")
    return not_after.strftime('%Y-%m-%d')


def _ok(**extra):
    return {"status": "success", **extra}


def _err(message):
    return {"status": "error", "message": message}


class RenewalManager:
    def __init__(self, get_api_key, get_orders, http=dc.default_http, now=datetime.datetime.now):
        self.get_api_key = get_api_key
        self.get_orders = get_orders       # callable returning the DigiCert order list (loads it if empty)
        self.http = http
        self.now = now
        self._last_poll = {}
        self._stop = threading.Event()

    # ---------- starting a renewal (user clicked "Renouveler" and confirmed) ----------

    def _prepare(self, hostname, thumbprint):
        """Every check that must pass before a renewal can start. Returns
        (context, None) or (None, error_response); places nothing anywhere."""
        if get_mode() == 'off':
            return None, _err("Le renouvellement automatique est désactivé (Paramètres → Renouvellement).")

        thumbprint = (thumbprint or '').upper()
        cert = next((c for c in db.get_all_discovered_certs()
                     if c['hostname'] == hostname and (c['thumbprint'] or '').upper() == thumbprint), None)
        if not cert:
            return None, _err("Certificat introuvable dans les derniers scans de cet agent.")
        agent = next((a for a in db.get_all_agents() if a['hostname'] == hostname), None)
        if not agent:
            return None, _err("Agent inconnu.")
        if not supports_cert_management(agent.get('agent_version')):
            return None, _err("Cet agent est trop ancien pour gérer les certificats (v2.1 minimum). Réinstallez-le.")
        if agent.get('cert_management') is False:
            return None, _err("L'administrateur de ce serveur n'a pas autorisé le renouvellement automatique "
                              "(case à cocher de l'installateur de l'agent, ou allow_cert_management dans "
                              "agent_config.json).")

        order = dc.find_order_for_domain(self.get_orders(), cert['domain'])
        if not order:
            return None, _err(f"« {cert['domain']} » n'a pas de commande émise dans votre compte DigiCert : "
                              "impossible de le renouveler depuis cet outil.")
        try:
            name_id, payload = dc.build_renewal_request(order, dc.CSR_PLACEHOLDER)
        except dc.DigiCertError as e:
            return None, _err(str(e))
        return {"cert": cert, "agent": agent, "order": order, "name_id": name_id, "payload": payload}, None

    def preview(self, hostname, thumbprint):
        """What starting this renewal would do, for the confirmation dialog.
        Nothing is sent or stored."""
        ctx, error = self._prepare(hostname, thumbprint)
        if error:
            return error
        payload = ctx['payload']
        return _ok(domain=ctx['cert']['domain'], hostname=hostname, product=ctx['name_id'],
                   dns_names=payload['certificate']['dns_names'],
                   validity_years=payload.get('validity_years'),
                   original_order_id=ctx['order'].get('id'),
                   install_path=ctx['cert']['install_path'])

    def start(self, hostname, thumbprint):
        ctx, error = self._prepare(hostname, thumbprint)
        if error:
            return error
        cert, agent = ctx['cert'], ctx['agent']

        seen = agent.get('last_seen')
        live = False
        if seen:
            try:
                live = (self.now() - datetime.datetime.fromisoformat(seen)).total_seconds() < AGENT_LIVE_SECONDS
            except Exception:
                pass
        if not live:
            return _err("L'agent n'est pas en ligne : impossible de lui faire préparer la demande de certificat.")

        dns_names = ctx['payload']['certificate']['dns_names']
        job_id, created = db.create_renewal_job(
            hostname, cert['domain'], cert['thumbprint'], cert['install_path'], cert['valid_till'],
            'awaiting_csr', "Demande envoyée à l'agent : génération de la clé et du CSR sur le serveur.",
            'live', dns_names, dc.describe_request(ctx['name_id'], ctx['payload']))
        if not created:
            return _err(f"Un renouvellement est déjà en cours pour ce certificat (n° {job_id}).")
        db.queue_command(hostname, 'generate_csr', {
            "job_id": job_id, "domain": cert['domain'], "dns_names": dns_names,
            "old_thumbprint": cert['thumbprint'],
        })
        return _ok(job_id=job_id)

    def cancel(self, job_id):
        job = db.get_renewal_job(job_id)
        if not job:
            return _err("Renouvellement introuvable.")
        if job['status'] in db.RENEWAL_TERMINAL:
            return _err("Ce renouvellement est déjà terminé.")
        note = ""
        if job.get('digicert_order_id') or job['status'] in ('ordering', 'uncertain'):
            note = (" Annulé ici seulement : si une commande existe chez DigiCert"
                    f"{' (n° ' + str(job['digicert_order_id']) + ')' if job.get('digicert_order_id') else ''}"
                    ", annulez-la depuis le portail DigiCert.")
        db.update_renewal_job(job_id, status='cancelled', message="Annulé manuellement." + note)
        db.withdraw_pending_commands_for_job(job_id)
        return _ok()

    # ---------- results reported by the agent ----------

    def on_command_result(self, hostname, command_id, status, message, data):
        cmd = db.get_command(command_id)
        if not cmd or cmd['hostname'] != hostname or cmd['type'] not in ('generate_csr', 'install_cert'):
            return
        job = db.get_renewal_job(cmd['params'].get('job_id'))
        if not job or job['hostname'] != hostname:
            return
        if cmd['type'] == 'generate_csr':
            self._on_csr_result(job, status, message, data or {})
        else:
            self._on_install_result(job, status, message, data or {})

    def _fail(self, job, message, expected=None):
        db.update_renewal_job(job['id'], expected_status=expected or job['status'], status='failed', message=message)
        db.withdraw_pending_commands_for_job(job['id'])

    def _on_csr_result(self, job, status, message, data):
        if job['status'] != 'awaiting_csr':
            return
        if status != 'done':
            self._fail(job, f"L'agent n'a pas pu préparer la demande : {message}. Aucune commande DigiCert n'a été passée.")
            return
        try:
            csr = validate_csr(str(data.get('csr', '')), job['domain'])
        except ValueError as e:
            self._fail(job, f"CSR refusé : {e}. Aucune commande DigiCert n'a été passée.")
            return
        db.update_renewal_job(job['id'], expected_status='awaiting_csr', status='csr_ready', csr_pem=csr,
                              message="CSR reçu de l'agent - commande DigiCert en préparation.")

    def _on_install_result(self, job, status, message, data):
        if job['status'] != 'installing':
            return
        if status == 'done':
            db.update_renewal_job(job['id'], expected_status='installing', status='installed',
                                  new_thumbprint=str(data.get('new_thumbprint', ''))[:64],
                                  new_valid_till=str(data.get('new_valid_till', ''))[:20],
                                  message=message or "Certificat installé.")
        else:
            self._fail(job, f"Le certificat a été ÉMIS chez DigiCert (commande n° {job.get('digicert_order_id')}) "
                            f"mais son installation a échoué : {message}. Installez-le manuellement depuis le "
                            "portail DigiCert ; l'ancien certificat reste en place.")

    # ---------- background worker ----------

    def step(self):
        """One pass over every unfinished job. Safe to call repeatedly."""
        for job in db.list_renewal_jobs(limit=200):
            if job['status'] in db.RENEWAL_TERMINAL:
                continue
            try:
                self._advance(job)
            except Exception as e:  # never let one job stop the worker
                print(f"[renewal] job {job['id']}: {e}")

    def _advance(self, job):
        status, now = job['status'], self.now()
        age_min = _minutes_since(job['updated_at'], now)
        if status == 'awaiting_csr' and age_min > CSR_TIMEOUT_MIN:
            self._fail(job, "L'agent n'a pas répondu à temps. Aucune commande DigiCert n'a été passée.")
        elif status == 'csr_ready':
            self._place_order(job)
        elif status == 'ordering' and age_min > ORDERING_TIMEOUT_MIN:
            db.update_renewal_job(job['id'], expected_status='ordering', status='uncertain',
                                  message="Statut incertain : la commande a peut-être été passée chez DigiCert. "
                                          "Vérifiez sur le portail DigiCert avant de relancer, puis annulez ce renouvellement.")
        elif status == 'ordered':
            self._check_order(job, now)
        elif status == 'installing' and age_min > INSTALL_TIMEOUT_MIN:
            self._fail(job, f"L'agent n'a pas confirmé l'installation. Le certificat est émis chez DigiCert "
                            f"(commande n° {job.get('digicert_order_id')}) : installez-le manuellement si besoin.")

    def _place_order(self, job):
        if get_mode() != 'live':
            self._fail(job, "Renouvellement automatique désactivé entre-temps : aucune commande passée.",
                       expected='csr_ready')
            return
        order = dc.find_order_for_domain(self.get_orders(), job['domain'])
        try:
            if not order:
                raise dc.DigiCertError("commande d'origine introuvable dans le compte DigiCert", definitive=True)
            name_id, payload = dc.build_renewal_request(order, job['csr_pem'])
        except dc.DigiCertError as e:
            self._fail(job, f"Commande impossible : {e}. Rien n'a été envoyé à DigiCert.", expected='csr_ready')
            return

        # Claim BEFORE any network call: only one caller can win this swap.
        if not db.update_renewal_job(job['id'], expected_status='csr_ready', status='ordering',
                                     message="Commande de renouvellement envoyée à DigiCert..."):
            return
        try:
            result = dc.place_order(get_base_url(), self.get_api_key(), name_id, payload, self.http)
        except dc.DigiCertError as e:
            if e.definitive:
                self._fail(job, f"DigiCert a refusé la commande : {e}. Aucune commande n'a été créée.", expected='ordering')
            else:
                self._mark_uncertain(job, str(e))
            return
        except Exception as e:
            self._mark_uncertain(job, str(e))
            return
        db.update_renewal_job(job['id'], expected_status='ordering', status='ordered',
                              digicert_order_id=str(result['id']),
                              message=f"Commande n° {result['id']} passée chez DigiCert. En attente d'émission "
                                      "(validation éventuelle du domaine côté DigiCert).")

    def _mark_uncertain(self, job, detail):
        db.update_renewal_job(job['id'], expected_status='ordering', status='uncertain',
                              message=f"Statut incertain ({detail}) : la commande a peut-être été créée chez DigiCert. "
                                      "Vérifiez sur le portail DigiCert avant de relancer, puis annulez ce renouvellement.")

    def _check_order(self, job, now):
        if _minutes_since(job['created_at'], now) > ORDER_MAX_WAIT_DAYS * 24 * 60:
            self._fail(job, f"Commande n° {job['digicert_order_id']} toujours non émise après {ORDER_MAX_WAIT_DAYS} jours.")
            return
        last = self._last_poll.get(job['id'])
        if last is not None and time.monotonic() - last < ORDER_POLL_SECONDS:
            return
        self._last_poll[job['id']] = time.monotonic()
        try:
            info = dc.get_order(get_base_url(), self.get_api_key(), job['digicert_order_id'], self.http)
        except Exception as e:
            print(f"[renewal] job {job['id']}: statut de commande indisponible: {e}")
            return  # transient - try again next tick
        if info['status'] in _FAILED_ORDER_STATUSES:
            self._fail(job, f"DigiCert a clos la commande n° {job['digicert_order_id']} (statut : {info['status']}).")
            return
        if info['status'] != 'issued' or not info['certificate_id']:
            db.update_renewal_job(job['id'], expected_status='ordered',
                                  message=f"Commande n° {job['digicert_order_id']} : statut DigiCert « {info['status'] or 'inconnu'} »."
                                          " En attente d'émission.")
            return
        try:
            chain = dc.download_chain(get_base_url(), self.get_api_key(), info['certificate_id'], self.http)
            new_valid_till = validate_issued_chain(chain, job['csr_pem'], job['domain'], now=None)
        except dc.DigiCertError as e:
            print(f"[renewal] job {job['id']}: téléchargement impossible: {e}")
            return
        except ValueError as e:
            self._fail(job, f"Certificat émis rejeté par les contrôles de sécurité : {e}. Rien n'a été installé.")
            return
        # Claim the hand-off to the agent, then queue the install exactly once.
        if not db.update_renewal_job(job['id'], expected_status='ordered', status='installing', cert_pem=chain,
                                     digicert_cert_id=str(info['certificate_id']), new_valid_till=new_valid_till,
                                     message="Certificat émis et vérifié - installation par l'agent en cours."):
            return
        db.queue_command(job['hostname'], 'install_cert', {"job_id": job['id'], "certificate_pem": chain})

    def run_forever(self):
        while not self._stop.is_set():
            self.step()
            self._stop.wait(WORKER_TICK_SECONDS)

    def stop(self):
        self._stop.set()

    # ---------- what the UI shows ----------

    def certificates_overview(self):
        """Every certificate agents found, with whether it can be renewed from here."""
        orders = self.get_orders() or []
        agents = {a['hostname']: a for a in db.get_all_agents()}
        active = {}
        for job in db.list_renewal_jobs(limit=500):
            key = (job['hostname'], (job['old_thumbprint'] or '').upper())
            if key not in active:  # newest job first
                active[key] = job
        today = datetime.date.today()
        mode = get_mode()
        rows = []
        for c in db.get_all_discovered_certs():
            try:
                days_left = (datetime.date.fromisoformat(c['valid_till'][:10]) - today).days
            except Exception:
                days_left = None
            agent = agents.get(c['hostname'])
            in_digicert = dc.find_order_for_domain(orders, c['domain']) is not None
            job = active.get((c['hostname'], (c['thumbprint'] or '').upper()))
            reason = ''
            if mode == 'off':
                reason = "Renouvellement désactivé"
            elif not agent or not supports_cert_management(agent.get('agent_version')):
                reason = "Agent < 2.1"
            elif agent.get('cert_management') is False:
                reason = "Non autorisé sur ce serveur"
            elif not in_digicert:
                reason = "Absent du compte DigiCert"
            elif job and job['status'] not in db.RENEWAL_TERMINAL:
                reason = "Renouvellement en cours"
            rows.append({
                "hostname": c['hostname'], "domain": c['domain'], "issuer": c['issuer'],
                "valid_till": c['valid_till'], "days_left": days_left, "thumbprint": c['thumbprint'],
                "install_path": c['install_path'],
                "can_renew": reason == '', "reason": reason,
                "job": self.public_job(job) if job else None,
            })
        rows.sort(key=lambda r: (r['days_left'] is None, r['days_left'] if r['days_left'] is not None else 0))
        return rows

    @staticmethod
    def public_job(job):
        """Job without the bulky PEM fields (the UI never needs them)."""
        return {k: v for k, v in job.items() if k not in ('csr_pem', 'cert_pem')}

    def list_jobs(self, limit=30):
        return [self.public_job(j) for j in db.list_renewal_jobs(limit=limit)]
