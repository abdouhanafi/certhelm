#!/usr/bin/env python3
"""
CertHelm - agent de decouverte de certificats.

Scanne UNIQUEMENT en lecture les certificats installes localement sur ce
serveur (magasin de certificats Windows, fichiers .pem/.crt courants sous
Linux/RedHat, et sondage optionnel des ports locaux en ecoute) et envoie un
resume (domaine, emetteur, expiration, empreinte, emplacement) au serveur
CertHelm central.

Ne lit et n'exfiltre AUCUNE cle privee. L'agent n'ouvre aucun port : c'est
toujours lui qui appelle le controleur. En mode --daemon ou --tray il
l'interroge regulierement (toutes les 30s) pour recuperer ses reglages
(frequence, actif/inactif) et d'eventuelles commandes. Il n'execute QUE les
commandes d'une liste fixe (KNOWN_COMMANDS) - tout le reste est refuse.

Mode par defaut : zero dependance externe, uniquement la bibliotheque
standard Python 3, pour rester deployable sur des serveurs de production
sans acces pip. C'est le mode a utiliser sur de vrais serveurs Linux/RedHat.

Usage:
    python3 certhelm_agent.py --controller-url http://CONTROLEUR:8765 --token VOTRE_TOKEN
    (ou renseigner agent_config.json a cote de ce script - voir agent_config.example.json)

Sans option, le script fait un scan puis se termine (tache cron / planifiee),
mais CertHelm ne peut alors pas le piloter a distance.

Mode --daemon : tourne en continu sans interface, scanne selon la frequence
reglee dans CertHelm et repond aux commandes (ex: "Scanner
maintenant"). Journal dans agent.log a cote de l'agent. C'est le mode a
utiliser sur un serveur (tache Windows au demarrage, service systemd sous
Linux).

Mode --tray (Windows uniquement, necessite pystray + Pillow - voir
requirements-tray.txt) : tourne en continu avec une icone dans la barre
des taches (vert = dernier check-in OK, rouge = erreur, gris = pas encore
scanne). Reserve aux postes/serveurs ou une session utilisateur reste
ouverte - inutile sur un serveur Linux/RedHat headless.
"""

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
import datetime
import urllib.request
import urllib.error

AGENT_VERSION = "2.1"
DEFAULT_PROBE_PORTS = [443, 8443]

# Once compiled with PyInstaller, __file__ points inside the temporary
# extraction folder (_MEIxxxxx), not next to the real .exe on disk - so the
# config lookup has to use sys.executable's directory when frozen.
if getattr(sys, "frozen", False):
    _APP_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    _APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(_APP_DIR, "agent_config.json")


def load_file_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"[INFO] Pas de fichier de config trouve a cet emplacement: {CONFIG_FILE}")
        return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[WARN] Impossible de lire {CONFIG_FILE}: {e}")
    return {}


def extract_cn(subject_or_issuer):
    """Pulls the CN=... value out of an X.509 subject/issuer string."""
    if not subject_or_issuer:
        return ""
    match = re.search(r"CN\s*=\s*([^,/]+)", subject_or_issuer)
    return match.group(1).strip() if match else subject_or_issuer.strip()


# ===================== WINDOWS DISCOVERY =====================

def discover_windows():
    certs = []
    ps_command = (
        "Get-ChildItem Cert:\\LocalMachine\\My | "
        "Select-Object "
        "@{N='Subject';E={$_.Subject}}, "
        "@{N='Issuer';E={$_.Issuer}}, "
        "@{N='NotAfter';E={$_.NotAfter.ToString('yyyy-MM-dd')}}, "
        "@{N='Thumbprint';E={$_.Thumbprint}} | "
        "ConvertTo-Json -Depth 3"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_command],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            parsed = json.loads(result.stdout)
            if isinstance(parsed, dict):
                parsed = [parsed]
            for item in parsed:
                domain = extract_cn(item.get("Subject", ""))
                if not domain:
                    continue
                certs.append({
                    "domain": domain,
                    "issuer": extract_cn(item.get("Issuer", "")),
                    "valid_till": item.get("NotAfter", ""),
                    "thumbprint": item.get("Thumbprint", ""),
                    "install_path": "Cert:\\LocalMachine\\My"
                })
    except Exception as e:
        print(f"[WARN] Scan du magasin de certificats Windows echoue: {e}")

    # Best-effort: bindings SSL IIS (netsh) - donne le port lie, pas le CN
    # directement, donc on l'associe seulement si le thumbprint correspond
    # a un certificat deja trouve ci-dessus.
    try:
        result = subprocess.run(["netsh", "http", "show", "sslcert"], capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            thumb_by_hash = {c["thumbprint"].upper(): c for c in certs}
            current_ip_port = None
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("IP:port"):
                    current_ip_port = line.split(":", 1)[1].strip()
                elif line.startswith("Certificate Hash") and current_ip_port:
                    hash_val = line.split(":", 1)[1].strip().replace(" ", "").upper()
                    if hash_val in thumb_by_hash:
                        thumb_by_hash[hash_val]["install_path"] = f"IIS binding {current_ip_port}"
    except Exception as e:
        print(f"[INFO] netsh sslcert non disponible ou vide: {e}")

    return certs


# ===================== LINUX / REDHAT DISCOVERY =====================

LINUX_SCAN_DIRS = [
    "/etc/ssl/certs", "/etc/ssl/private", "/etc/pki/tls/certs",
    "/etc/nginx/ssl", "/etc/httpd/ssl", "/etc/letsencrypt/live",
    "/etc/pki/ca-trust/source", "/opt/certs"
]
CERT_EXTENSIONS = (".pem", ".crt", ".cer")


def parse_cert_with_openssl(path):
    try:
        result = subprocess.run(
            ["openssl", "x509", "-in", path, "-noout", "-subject", "-issuer", "-enddate", "-fingerprint", "-sha256"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode != 0:
            return None
        out = result.stdout
        subject = re.search(r"subject\s*=\s*(.+)", out)
        issuer = re.search(r"issuer\s*=\s*(.+)", out)
        enddate = re.search(r"notAfter\s*=\s*(.+)", out)
        fingerprint = re.search(r"Fingerprint\s*=\s*(.+)", out)
        if not subject:
            return None

        domain = extract_cn(subject.group(1))
        valid_till = ""
        if enddate:
            # openssl gives e.g. "Dec 31 23:59:59 2026 GMT" - reformat to ISO via date if possible
            try:
                conv = subprocess.run(["date", "-d", enddate.group(1), "+%Y-%m-%d"], capture_output=True, text=True, timeout=5)
                valid_till = conv.stdout.strip() if conv.returncode == 0 else enddate.group(1)
            except Exception:
                valid_till = enddate.group(1)

        return {
            "domain": domain,
            "issuer": extract_cn(issuer.group(1)) if issuer else "",
            "valid_till": valid_till,
            "thumbprint": (fingerprint.group(1).replace(":", "") if fingerprint else ""),
            "install_path": path
        }
    except Exception:
        return None


def discover_linux():
    certs = []
    seen_thumbprints = set()

    for base_dir in LINUX_SCAN_DIRS:
        if not os.path.isdir(base_dir):
            continue
        for root, _dirs, files in os.walk(base_dir):
            for fname in files:
                if not fname.lower().endswith(CERT_EXTENSIONS):
                    continue
                full_path = os.path.join(root, fname)
                parsed = parse_cert_with_openssl(full_path)
                if parsed and parsed["domain"] and parsed["thumbprint"] not in seen_thumbprints:
                    seen_thumbprints.add(parsed["thumbprint"])
                    certs.append(parsed)

    # Best-effort: probe a short list of locally listening ports to capture
    # whatever certificate is actually being served right now, even if its
    # file lives somewhere not covered by LINUX_SCAN_DIRS.
    for port in DEFAULT_PROBE_PORTS:
        try:
            pem = ssl.get_server_certificate(("127.0.0.1", port), timeout=3)
            import tempfile
            with tempfile.NamedTemporaryFile(mode="w", suffix=".pem", delete=False) as tmp:
                tmp.write(pem)
                tmp_path = tmp.name
            parsed = parse_cert_with_openssl(tmp_path)
            os.unlink(tmp_path)
            if parsed and parsed["thumbprint"] not in seen_thumbprints:
                seen_thumbprints.add(parsed["thumbprint"])
                parsed["install_path"] = f"Servi sur le port {port} (localhost)"
                certs.append(parsed)
        except Exception:
            pass  # port not listening or not TLS - not an error worth reporting

    return certs


# ===================== TRANSPORT =====================

POLL_SECONDS = 30
# Whole list of things the controller can ask this agent to do. Anything else
# received is refused and reported as failed - never executed.
KNOWN_COMMANDS = {"scan_now", "generate_csr", "install_cert"}


def _base_url(controller_url):
    base = controller_url.rstrip("/")
    for suffix in ("/agent/checkin", "/agent/poll"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]  # tolerate pasting the full URL shown in Settings
    return base


def _post_json(controller_url, token, path, payload, timeout=15):
    """POSTs JSON to the controller and returns the parsed JSON reply.
    Raises urllib errors - callers decide how loudly to report them."""
    req = urllib.request.Request(_base_url(controller_url) + path,
                                 data=json.dumps(payload).encode("utf-8"), method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def send_checkin(controller_url, token, hostname, os_name, certs):
    """Returns the controller's reply (a non-empty dict) on success, None on failure."""
    url = _base_url(controller_url) + "/agent/checkin"
    try:
        body = _post_json(controller_url, token, "/agent/checkin", {
            "hostname": hostname,
            "os": os_name,
            "agent_version": AGENT_VERSION,
            "certs": certs
        })
        print(f"[OK] Check-in reussi: {body}")
        return body or None
    except urllib.error.HTTPError as e:
        print(f"[ERREUR] Le serveur a refuse le check-in ({e.code}): {e.read().decode('utf-8', 'ignore')}")
    except urllib.error.URLError as e:
        print(f"[ERREUR] Impossible de joindre le serveur CertHelm ({url}): {e.reason}")
    except Exception as e:
        print(f"[ERREUR] Echec inattendu du check-in: {e}")
    return None


def run_single_scan():
    """Runs the OS-appropriate discovery once and returns (os_label, certs)."""
    if platform.system() == "Windows":
        os_label = f"Windows ({platform.win32_ver()[0]})"
        certs = discover_windows()
    else:
        os_label = f"{platform.system()} {platform.release()}"
        certs = discover_linux()
    return os_label, certs


# ===================== CERTIFICATE MANAGEMENT (renew: new key + CSR, then install) =====================
#
# Opt-in: nothing below runs unless agent_config.json contains
#   "allow_cert_management": true
# so a server's administrator - not the controller - decides whether this
# machine may ever have a certificate replaced remotely.
#
# Rules that hold for every step:
#   * The private key is generated HERE and never leaves this machine; only the
#     CSR (public) is sent back.
#   * The controller never supplies a file path or a command to run. The target
#     certificate is found by this agent from its own scan, using the thumbprint.
#   * A certificate is only installed if it matches the key generated for that
#     exact job (Windows enforces it in certreq -accept, Linux is checked with openssl).
#   * Every request is checked BEFORE the controller orders anything, so a server
#     that cannot be updated fails early instead of after a purchase.

PENDING_FILE = os.path.join(_APP_DIR, "pending_renewals.json")
PENDING_DIR = os.path.join(_APP_DIR, "pending")  # Linux: private keys waiting for their certificate
PENDING_MAX_AGE_DAYS = 30

_DNS_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_DNS_NAME_RE = re.compile(rf"^(?:\*\.)?{_DNS_LABEL}(?:\.{_DNS_LABEL})*$")
_THUMBPRINT_RE = re.compile(r"^[0-9A-Fa-f]{40}(?:[0-9A-Fa-f]{24})?$")  # SHA-1 (Windows) or SHA-256 (Linux)
_CERT_BLOCK_RE = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\r\n]+?-----END CERTIFICATE-----")


class CertOpError(Exception):
    """A problem the administrator should read verbatim (it is reported to CertHelm)."""


def _run(cmd, timeout=60):
    """The only place subprocesses are launched for certificate work: no shell,
    fixed argv, and one spot to replace in tests."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except FileNotFoundError as e:
        return subprocess.CompletedProcess(cmd, 127, "", f"commande introuvable: {e}")
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(cmd, 124, "", "delai depasse")


def _out(result):
    return ((result.stdout or "") + (result.stderr or "")).strip()


def _valid_dns(name):
    return isinstance(name, str) and 0 < len(name) <= 253 and bool(_DNS_NAME_RE.match(name))


def _validated_request(params):
    """Re-validates everything the controller sent - it is treated as untrusted input."""
    job_id = params.get("job_id")
    if isinstance(job_id, bool) or not isinstance(job_id, int) or job_id <= 0:
        raise CertOpError("Identifiant de renouvellement invalide")
    return job_id


def _pem_blocks(pem):
    if not isinstance(pem, str) or len(pem) > 60000:
        raise CertOpError("Certificat recu invalide")
    stripped = _CERT_BLOCK_RE.sub("", pem)
    if stripped.strip():
        raise CertOpError("Le certificat recu contient autre chose que des certificats PEM")
    blocks = _CERT_BLOCK_RE.findall(pem)
    if not blocks or len(blocks) > 6:
        raise CertOpError("Chaine de certificats vide ou trop longue")
    return [b.replace("\r", "").strip() + "\n" for b in blocks]


def _pem_to_der(block):
    body = "".join(line for line in block.splitlines() if not line.startswith("-----"))
    return base64.b64decode(body)


def _load_pending():
    try:
        with open(PENDING_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_pending(pending):
    tmp = PENDING_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(pending, f)
    os.replace(tmp, PENDING_FILE)


def _prune_pending(pending):
    """Drops requests nobody completed, together with their orphaned private keys."""
    cutoff = time.time() - PENDING_MAX_AGE_DAYS * 86400
    for job_id in [j for j, p in pending.items() if p.get("created", 0) < cutoff]:
        key = pending[job_id].get("pending_key")
        if key and os.path.isfile(key):
            try:
                os.remove(key)
            except OSError:
                pass
        del pending[job_id]


def _local_cert(thumbprint):
    """Finds the certificate to replace in THIS machine's own scan."""
    if not isinstance(thumbprint, str) or not _THUMBPRINT_RE.match(thumbprint):
        raise CertOpError("Empreinte du certificat invalide")
    _os_label, certs = run_single_scan()
    for cert in certs:
        if (cert.get("thumbprint") or "").upper() == thumbprint.upper():
            return cert
    raise CertOpError("Certificat introuvable sur ce serveur (deja remplace ou supprime ?)")


def cert_management_enabled():
    """Explicit opt-in read from this machine's own agent_config.json - the controller cannot switch it on."""
    return load_file_config().get("allow_cert_management") is True


def generate_csr(params):
    """Step 1 of a renewal. Returns (message, data) where data carries the CSR."""
    job_id = _validated_request(params)
    domain = params.get("domain")
    dns_names = params.get("dns_names") or [domain]
    if not _valid_dns(domain) or not isinstance(dns_names, list) or len(dns_names) > 100 \
            or not all(_valid_dns(n) for n in dns_names):
        raise CertOpError("Nom de domaine invalide dans la demande")

    pending = _load_pending()
    _prune_pending(pending)
    old_thumbprint = params.get("old_thumbprint")
    if platform.system() == "Windows":
        csr, detail, state = _windows_generate_csr(job_id, domain, dns_names, old_thumbprint)
    else:
        csr, detail, state = _linux_generate_csr(job_id, domain, dns_names, old_thumbprint)
    state.update({"domain": domain, "old_thumbprint": old_thumbprint.upper(), "created": time.time()})
    pending[str(job_id)] = state
    _save_pending(pending)
    return f"CSR genere, la cle privee reste sur ce serveur. {detail}", {"csr": csr}


def install_cert(params):
    """Step 2. Returns (message, data) where data carries the new thumbprint and expiry."""
    job_id = _validated_request(params)
    pending = _load_pending()
    state = pending.get(str(job_id))
    if not state:
        raise CertOpError("Aucune demande en attente pour ce renouvellement sur ce serveur (cle introuvable)")
    blocks = _pem_blocks(params.get("certificate_pem"))
    if state.get("os") == "windows":
        if platform.system() != "Windows":
            raise CertOpError("Demande creee pour Windows")
        message, data = _windows_install(state, blocks)
    else:
        message, data = _linux_install(job_id, state, blocks)
    pending.pop(str(job_id), None)
    _save_pending(pending)
    return message, data


# ---------- Windows ----------

def _is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _powershell(script, timeout=60):
    return _run(["powershell", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script], timeout)


def _ps_quote(value):
    return "'" + str(value).replace("'", "''") + "'"


_IIS_PRELUDE = ("$ErrorActionPreference='Stop';"
                "if (-not (Get-Module -ListAvailable WebAdministration)) { 'NOIIS'; exit 0 };"
                "Import-Module WebAdministration;")


def _build_inf(domain, dns_names):
    names = [domain] + [n for n in dns_names if n.lower() != domain.lower()]
    san = [f'_continue_ = "dns={n}&"' for n in names[:-1]] + [f'_continue_ = "dns={names[-1]}"']
    return "\r\n".join([
        "[Version]", 'Signature="$Windows NT$"', "",
        "[NewRequest]", f'Subject = "CN={domain}"', "KeySpec = 1", "KeyLength = 2048",
        # Non-exportable, machine-scoped key: it can be used by IIS but never copied out.
        "Exportable = FALSE", "MachineKeySet = TRUE", "SMIME = FALSE", "PrivateKeyArchive = FALSE",
        "UserProtected = FALSE", "UseExistingKeySet = FALSE",
        'ProviderName = "Microsoft RSA SChannel Cryptographic Provider"', "ProviderType = 12",
        "RequestType = PKCS10", "KeyUsage = 0xa0", "HashAlgorithm = SHA256", "",
        "[Extensions]", '2.5.29.17 = "{text}"', *san, "",
        "[EnhancedKeyUsageExtension]", "OID=1.3.6.1.5.5.7.3.1", "",
    ])


def _iis_binding_count(thumbprint):
    script = _IIS_PRELUDE + (f"@(Get-WebBinding -Protocol https | "
                             f"Where-Object {{ $_.certificateHash -ieq {_ps_quote(thumbprint)} }}).Count")
    result = _powershell(script)
    if result.returncode != 0:
        raise CertOpError(f"Lecture des bindings IIS impossible : {_out(result)[:300]}")
    text = result.stdout.strip()
    return 0 if "NOIIS" in text else int(text.splitlines()[-1])


def _iis_rebind(old_thumbprint, new_thumbprint):
    script = _IIS_PRELUDE + ("$n=0; Get-WebBinding -Protocol https | "
                             f"Where-Object {{ $_.certificateHash -ieq {_ps_quote(old_thumbprint)} }} | "
                             f"ForEach-Object {{ $_.AddSslCertificate({_ps_quote(new_thumbprint)}, 'My'); $n++ }}; $n")
    result = _powershell(script)
    if result.returncode != 0:
        raise CertOpError(_out(result)[:300])
    text = result.stdout.strip()
    return 0 if "NOIIS" in text else int(text.splitlines()[-1])


def _windows_generate_csr(job_id, domain, dns_names, old_thumbprint):
    if not _is_admin():
        raise CertOpError("Droits administrateur requis : l'agent doit tourner sous SYSTEM (tache en arriere-plan) "
                          "ou dans une session administrateur")
    _local_cert(old_thumbprint)  # preflight: the certificate to replace must really be here
    bindings = _iis_binding_count(old_thumbprint)
    with tempfile.TemporaryDirectory() as tmp:
        inf, req = os.path.join(tmp, "request.inf"), os.path.join(tmp, "request.csr")
        with open(inf, "w", encoding="ascii", newline="") as f:
            f.write(_build_inf(domain, dns_names))
        result = _run(["certreq", "-new", "-machine", "-q", inf, req])
        if result.returncode != 0 or not os.path.isfile(req):
            raise CertOpError(f"certreq -new a echoue : {_out(result)[:300]}")
        with open(req, "r", encoding="ascii", errors="ignore") as f:
            csr = f.read()
    detail = f"{bindings} binding(s) IIS utilisent le certificat actuel."
    return csr, detail, {"os": "windows"}


def _windows_install(state, blocks):
    old_thumbprint = state["old_thumbprint"]
    leaf = blocks[0]
    new_thumbprint = hashlib.sha1(_pem_to_der(leaf)).hexdigest().upper()
    with tempfile.TemporaryDirectory() as tmp:
        leaf_path = os.path.join(tmp, "leaf.cer")
        with open(leaf_path, "w", encoding="ascii", newline="") as f:
            f.write(leaf)
        # Windows only binds a certificate to the private key generated for it: this
        # fails if the certificate does not match a pending request on this machine.
        result = _run(["certreq", "-accept", "-machine", "-q", leaf_path])
        if result.returncode != 0:
            raise CertOpError("Windows a refuse le certificat (il ne correspond a aucune demande en attente "
                              f"sur cette machine) : {_out(result)[:300]}")

        check = _powershell(f"$c=Get-Item {_ps_quote('Cert:\\LocalMachine\\My\\' + new_thumbprint)}; "
                            "@{hasKey=$c.HasPrivateKey; notAfter=$c.NotAfter.ToString('yyyy-MM-dd')} | ConvertTo-Json -Compress")
        try:
            info = json.loads(check.stdout)
        except ValueError:
            info = {}
        if check.returncode != 0 or not info.get("hasKey"):
            raise CertOpError("Certificat present dans le magasin mais sans cle privee associee - installation abandonnee")

        chain_warning = ""
        for i, block in enumerate(blocks[1:], start=1):
            path = os.path.join(tmp, f"intermediate{i}.cer")
            with open(path, "w", encoding="ascii", newline="") as f:
                f.write(block)
            imported = _powershell(f"Import-Certificate -FilePath {_ps_quote(path)} "
                                   "-CertStoreLocation Cert:\\LocalMachine\\CA | Out-Null")
            if imported.returncode != 0:
                chain_warning = " Avertissement : un certificat intermediaire n'a pas pu etre importe."

    try:
        rebound = _iis_rebind(old_thumbprint, new_thumbprint)
    except CertOpError as e:
        try:
            _iis_rebind(new_thumbprint, old_thumbprint)  # put back anything already switched
        except CertOpError:
            pass
        raise CertOpError(f"Mise a jour des bindings IIS echouee, ancien certificat remis en place : {e}")
    message = (f"Certificat installe dans le magasin de l'ordinateur ({new_thumbprint[:8]}...). "
               f"{rebound} binding(s) IIS mis a jour. L'ancien certificat n'a pas ete supprime.{chain_warning}")
    return message, {"new_thumbprint": new_thumbprint, "new_valid_till": info.get("notAfter", "")}


# ---------- Linux / RedHat ----------

def _pubkey_of_cert(path):
    result = _run(["openssl", "x509", "-in", path, "-noout", "-pubkey"], 15)
    return "".join(result.stdout.split()) if result.returncode == 0 else None


def _pubkey_of_key(path):
    result = _run(["openssl", "pkey", "-in", path, "-pubout", "-passin", "pass:"], 15)
    return "".join(result.stdout.split()) if result.returncode == 0 else None


def _find_private_key(cert_path):
    """The private key that goes with a certificate, found by comparing public keys
    (files next to the certificate first, then the usual key directories)."""
    wanted = _pubkey_of_cert(cert_path)
    if not wanted:
        return None
    seen = {cert_path}
    for directory in [os.path.dirname(cert_path)] + [d for d in LINUX_SCAN_DIRS if os.path.isdir(d)]:
        try:
            names = sorted(os.listdir(directory))
        except OSError:
            continue
        for name in names:
            full = os.path.join(directory, name)
            if full in seen or not name.lower().endswith((".key", ".pem")) or not os.path.isfile(full):
                continue
            seen.add(full)
            if _pubkey_of_key(full) == wanted:
                return full
    return None


def _as_argv(value, label):
    if value is None:
        return None
    if not isinstance(value, list) or not value or not all(isinstance(x, str) for x in value):
        raise CertOpError(f"{label} doit etre une liste (ex: [\"nginx\", \"-t\"]) dans agent_config.json")
    return value


def _web_service_commands():
    """(name, test_argv, reload_argv) - from agent_config.json if set there, else auto-detected.
    The controller never influences this."""
    config = load_file_config()
    reload_cmd = _as_argv(config.get("reload_command"), "reload_command")
    test_cmd = _as_argv(config.get("test_command"), "test_command")
    if reload_cmd:
        return "configure", test_cmd, reload_cmd
    for service, test in (("nginx", ["nginx", "-t"]), ("httpd", ["apachectl", "configtest"]),
                          ("apache2", ["apache2ctl", "configtest"])):
        active = _run(["systemctl", "is-active", service], 10)
        if active.returncode == 0 and active.stdout.strip() == "active":
            return service, test, ["systemctl", "reload", service]
    return None


def _linux_generate_csr(job_id, domain, dns_names, old_thumbprint):
    cert = _local_cert(old_thumbprint)
    cert_path = cert.get("install_path", "")
    if not os.path.isabs(cert_path) or not os.path.isfile(cert_path):
        raise CertOpError("Ce certificat n'est pas un fichier remplacable (servi sur un port ?) - renouvellement automatique impossible")
    with open(cert_path, "r", errors="ignore") as f:
        if "PRIVATE KEY" in f.read():
            raise CertOpError("Cle et certificat dans le meme fichier : non pris en charge")
    key_path = _find_private_key(cert_path)
    if not key_path:
        raise CertOpError("Cle privee actuelle introuvable (ou protegee par mot de passe) : installation automatique impossible")
    for path in (cert_path, key_path):
        if os.path.islink(path):
            raise CertOpError(f"{path} est un lien symbolique : non pris en charge")
        if not (os.access(path, os.W_OK) and os.access(os.path.dirname(path), os.W_OK)):
            raise CertOpError(f"Pas de droit d'ecriture sur {path}")
    service = _web_service_commands()
    if not service:
        raise CertOpError("Aucun service web actif detecte (nginx/httpd/apache2). Renseignez "
                          "reload_command (et test_command) dans agent_config.json")

    os.makedirs(PENDING_DIR, mode=0o700, exist_ok=True)
    pending_key = os.path.join(PENDING_DIR, f"{job_id}.key")
    with tempfile.TemporaryDirectory() as tmp:
        conf, csr_path = os.path.join(tmp, "req.cnf"), os.path.join(tmp, "req.csr")
        names = [domain] + [n for n in dns_names if n.lower() != domain.lower()]
        with open(conf, "w", encoding="ascii") as f:
            f.write("[req]\ndistinguished_name=dn\nreq_extensions=v3\nprompt=no\n[dn]\n"
                    f"CN={domain}\n[v3]\nsubjectAltName=@alt\n[alt]\n"
                    + "".join(f"DNS.{i}={n}\n" for i, n in enumerate(names, start=1)))
        old_umask = os.umask(0o077)
        try:
            result = _run(["openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", pending_key,
                           "-out", csr_path, "-config", conf], 60)
        finally:
            os.umask(old_umask)
        if result.returncode != 0 or not os.path.isfile(csr_path):
            raise CertOpError(f"openssl req a echoue : {_out(result)[:300]}")
        with open(csr_path, "r") as f:
            csr = f.read()
    try:
        os.chmod(pending_key, 0o600)
    except OSError:
        pass
    detail = f"Fichiers cibles : {cert_path} et {key_path} ; service : {service[0]}."
    return csr, detail, {"os": "linux", "cert_path": cert_path, "key_path": key_path, "pending_key": pending_key}


def _atomic_write(path, data, mode, uid=None, gid=None):
    tmp = path + ".digicert-new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as f:
        f.write(data)
    if uid is not None and hasattr(os, "chown"):
        try:
            os.chown(tmp, uid, gid)
        except OSError:
            pass
    os.replace(tmp, path)


def _linux_install(job_id, state, blocks):
    cert_path, key_path, pending_key = state.get("cert_path"), state.get("key_path"), state.get("pending_key")
    domain = state["domain"]
    if not (cert_path and key_path and pending_key and os.path.isfile(pending_key)):
        raise CertOpError("Etat de la demande incomplet ou cle en attente absente")
    if os.path.islink(cert_path) or os.path.islink(key_path):
        raise CertOpError("Un des fichiers cibles est devenu un lien symbolique : abandon")

    with tempfile.TemporaryDirectory() as tmp:
        leaf_path = os.path.join(tmp, "leaf.pem")
        with open(leaf_path, "w") as f:
            f.write(blocks[0])
        # The certificate must be for the key generated for THIS job...
        cert_pub, key_pub = _pubkey_of_cert(leaf_path), _pubkey_of_key(pending_key)
        if not cert_pub or cert_pub != key_pub:
            raise CertOpError("Le certificat recu ne correspond pas a la cle generee sur ce serveur - rien n'a ete modifie")
        # ...cover this domain, and not be expired.
        text = _run(["openssl", "x509", "-in", leaf_path, "-noout", "-text"], 15).stdout.lower()
        if domain.lower() not in text:
            raise CertOpError(f"Le certificat recu ne mentionne pas {domain} - rien n'a ete modifie")
        if _run(["openssl", "x509", "-in", leaf_path, "-noout", "-checkend", "0"], 15).returncode != 0:
            raise CertOpError("Le certificat recu est deja expire - rien n'a ete modifie")
        info = parse_cert_with_openssl(leaf_path) or {}

    service = _web_service_commands()
    if not service:
        raise CertOpError("Aucun service web actif detecte : rien n'a ete modifie")
    _name, test_cmd, reload_cmd = service

    stamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    backups = {}
    for path in (cert_path, key_path):
        backups[path] = f"{path}.bak-{stamp}"
        shutil.copy2(path, backups[path])
    key_stat = os.stat(key_path)
    cert_stat = os.stat(cert_path)
    with open(pending_key, "r") as f:
        new_key = f.read()

    def restore():
        # Put the originals back, then delete the backups: after a rollback they are
        # redundant, and one of them is a copy of the old private key.
        for path, backup in backups.items():
            shutil.copy2(backup, path)
            try:
                os.remove(backup)
            except OSError:
                pass

    try:
        _atomic_write(cert_path, "".join(blocks), stat.S_IMODE(cert_stat.st_mode), cert_stat.st_uid, cert_stat.st_gid)
        _atomic_write(key_path, new_key, stat.S_IMODE(key_stat.st_mode), key_stat.st_uid, key_stat.st_gid)
        if test_cmd:
            tested = _run(test_cmd, 60)
            if tested.returncode != 0:
                raise CertOpError(f"Le test de configuration du service a echoue ({_out(tested)[:200]})")
        reloaded = _run(reload_cmd, 60)
        if reloaded.returncode != 0:
            raise CertOpError(f"Le rechargement du service a echoue ({_out(reloaded)[:200]})")
    except CertOpError as e:
        restore()
        raise CertOpError(f"{e}. Anciens fichiers restaures ({os.path.basename(backups[cert_path])}).")
    except Exception as e:
        restore()
        raise CertOpError(f"Erreur pendant le remplacement ({e}). Anciens fichiers restaures.")

    try:
        os.remove(pending_key)
    except OSError:
        pass
    message = (f"Certificat installe dans {cert_path}, cle dans {key_path}, service recharge. "
               f"Sauvegardes : *.bak-{stamp}.")
    return message, {"new_thumbprint": info.get("thumbprint", ""), "new_valid_till": info.get("valid_till", "")}


# ===================== RUNNER (poll + scan loop, shared by --tray and --daemon) =====================

class AgentRunner:
    """Keeps an agent alive: scans on a schedule, and every POLL_SECONDS asks the
    controller whether there is anything to do (settings changes, 'scan now').
    The agent always initiates the connection - the controller never reaches in."""

    def __init__(self, controller_url, token, hostname, interval_hours, on_state=None, allow_cert_management=False):
        self.controller_url = controller_url
        self.token = token
        self.hostname = hostname
        self.allow_cert_management = allow_cert_management
        self.interval_hours = max(1.0, float(interval_hours))
        self.enabled = True
        self.on_state = on_state or (lambda status, message: None)
        self.last_scan = None          # time.monotonic() of the last scan attempt
        self.last_run = None           # wall-clock label of the last scan, for display
        self.last_count = 0
        self._scan_lock = threading.Lock()
        self._last_poll_error = None

    def apply_settings(self, settings):
        if not isinstance(settings, dict):
            return
        try:
            self.interval_hours = max(1.0, float(settings.get("interval_hours", self.interval_hours)))
        except (TypeError, ValueError):
            pass
        was_enabled = self.enabled
        self.enabled = bool(settings.get("enabled", True))
        if was_enabled and not self.enabled:
            self.on_state("disabled", "Desactive depuis CertHelm")
        elif not was_enabled and self.enabled:
            self.on_state("unknown", "Reactive - prochain scan imminent")

    def do_scan(self):
        """Scans and checks in. Returns True if the controller accepted it."""
        with self._scan_lock:
            self.on_state("running", "Scan en cours...")
            os_label, certs = run_single_scan()
            reply = send_checkin(self.controller_url, self.token, self.hostname, os_label, certs)
            self.last_scan = time.monotonic()
            self.last_run = datetime.datetime.now().strftime("%H:%M:%S")
            self.last_count = len(certs)
            if reply:
                self.apply_settings(reply.get("settings"))
                if self.enabled:
                    self.on_state("ok", f"OK - {len(certs)} certificat(s) - {self.last_run}")
                return True
            self.on_state("error", f"Echec du check-in - dernier essai {self.last_run}")
            return False

    def _report(self, command_id, status, message, data=None):
        try:
            _post_json(self.controller_url, self.token, "/agent/command_result", {
                "hostname": self.hostname, "command_id": command_id, "status": status, "message": message,
                "data": data or {}
            })
        except Exception as e:
            print(f"[WARN] Impossible de rapporter le resultat de la commande {command_id}: {e}")

    def _handle_cert_command(self, command_id, command_type, params):
        if not self.allow_cert_management:
            print(f"[WARN] Commande {command_type} refusee : allow_cert_management n'est pas active")
            self._report(command_id, "failed",
                         "Gestion des certificats non autorisee sur ce serveur : ajoutez "
                         "\"allow_cert_management\": true dans agent_config.json de l'agent")
            return
        print(f"[INFO] Commande recue: {command_type} (renouvellement n° {params.get('job_id')})")
        try:
            action = generate_csr if command_type == "generate_csr" else install_cert
            message, data = action(params if isinstance(params, dict) else {})
        except CertOpError as e:
            print(f"[ERREUR] {command_type}: {e}")
            self._report(command_id, "failed", str(e))
            return
        except Exception as e:
            print(f"[ERREUR] {command_type}: erreur inattendue: {e}")
            self._report(command_id, "failed", f"Erreur inattendue : {e}")
            return
        print(f"[OK] {command_type}: {message}")
        self._report(command_id, "done", message, data)
        if command_type == "install_cert":
            self.do_scan()  # so CertHelm immediately sees the new certificate

    def handle_command(self, command):
        command_id = command.get("id")
        command_type = command.get("type")
        if command_type not in KNOWN_COMMANDS:
            print(f"[WARN] Commande refusee (type non autorise): {command_type!r}")
            self._report(command_id, "failed", f"Commande non autorisee: {command_type}")
            return
        if command_type == "scan_now":
            if not self.enabled:
                self._report(command_id, "failed", "Agent desactive")
                return
            print("[INFO] Commande recue: scan immediat")
            if self.do_scan():
                self._report(command_id, "done", f"Scan termine: {self.last_count} certificat(s)")
            else:
                self._report(command_id, "failed", "Scan effectue mais le check-in a echoue")
        elif command_type in ("generate_csr", "install_cert"):
            self._handle_cert_command(command_id, command_type, command.get("params") or {})

    def poll_once(self):
        try:
            reply = _post_json(self.controller_url, self.token, "/agent/poll", {
                "hostname": self.hostname, "agent_version": AGENT_VERSION
            })
        except Exception as e:
            # Log a given failure once, not every 30s for as long as the controller is down.
            if str(e) != self._last_poll_error:
                print(f"[WARN] Controleur injoignable ou refus: {e}")
                self._last_poll_error = str(e)
            return
        self._last_poll_error = None
        self.apply_settings(reply.get("settings"))
        for command in reply.get("commands", []):
            if isinstance(command, dict):
                self.handle_command(command)

    def scan_due(self):
        if not self.enabled:
            return False
        return self.last_scan is None or (time.monotonic() - self.last_scan) >= self.interval_hours * 3600

    def loop(self):
        while True:
            self.poll_once()
            if self.scan_due():
                self.do_scan()
            time.sleep(POLL_SECONDS)


class _TimestampedWriter:
    """Prefixes each line with a timestamp - the daemon has no console, so its
    log file is the only way to see what happened and when."""

    def __init__(self, stream):
        self.stream = stream
        self.at_line_start = True

    def write(self, text):
        for chunk in text.splitlines(True):
            if self.at_line_start and chunk.strip():
                self.stream.write(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S "))
            self.stream.write(chunk)
            self.at_line_start = chunk.endswith("\n")

    def flush(self):
        self.stream.flush()


def redirect_output_to_log():
    """Sends stdout/stderr to agent.log next to the agent (kept under ~1MB)."""
    path = os.path.join(_APP_DIR, "agent.log")
    try:
        if os.path.exists(path) and os.path.getsize(path) > 1_000_000:
            os.replace(path, path + ".1")
        writer = _TimestampedWriter(open(path, "a", encoding="utf-8", buffering=1))
        sys.stdout = writer
        sys.stderr = writer
    except Exception:
        pass  # logging is best-effort; never stop the agent over it


def run_daemon_mode(controller_url, token, hostname, interval_hours):
    redirect_output_to_log()
    print(f"[INFO] Agent {AGENT_VERSION} demarre en mode daemon ({hostname}, scan toutes les {interval_hours}h)")
    allowed = cert_management_enabled()
    print(f"[INFO] Gestion des certificats (renouvellement automatique) : {'ACTIVEE' if allowed else 'desactivee'}")
    AgentRunner(controller_url, token, hostname, interval_hours, allow_cert_management=allowed).loop()


# ===================== TRAY MODE (Windows, interactive sessions only) =====================

def run_tray_mode(controller_url, token, hostname, interval_hours):
    try:
        import pystray
        from PIL import Image, ImageDraw
    except ImportError:
        print("[ERREUR] Le mode --tray necessite les paquets 'pystray' et 'Pillow'.")
        print("         pip install pystray Pillow  (ou utilisez l'exe compile qui les inclut deja)")
        sys.exit(1)

    def make_dot(rgb):
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.ellipse([6, 6, 58, 58], fill=rgb)
        return img

    icons = {
        "unknown": make_dot((148, 163, 184, 255)),
        "disabled": make_dot((100, 116, 139, 255)),
        "running": make_dot((0, 159, 223, 255)),
        "ok": make_dot((16, 185, 129, 255)),
        "error": make_dot((239, 68, 68, 255)),
    }

    tray_icon = pystray.Icon("certhelm_agent", icons["unknown"], "CertHelm Agent - pas encore scanne")

    def set_state(status, message):
        tray_icon.icon = icons[status]
        tray_icon.title = f"CertHelm Agent - {message}"[:127]  # Windows tooltip length limit

    runner = AgentRunner(controller_url, token, hostname, interval_hours, on_state=set_state,
                         allow_cert_management=cert_management_enabled())

    def on_scan_now(icon_obj, item):
        threading.Thread(target=runner.do_scan, daemon=True).start()

    def on_quit(icon_obj, item):
        tray_icon.stop()

    def status_label(item):
        if not runner.enabled:
            return "Statut : desactive depuis CertHelm"
        if runner.last_run is None:
            return "Statut : pas encore scanne"
        return f"Dernier scan : {runner.last_run} ({runner.last_count} certificat(s))"

    tray_icon.menu = pystray.Menu(
        pystray.MenuItem(status_label, None, enabled=False),
        pystray.MenuItem("Scanner maintenant", on_scan_now),
        pystray.MenuItem("Quitter", on_quit)
    )

    threading.Thread(target=runner.loop, daemon=True).start()
    tray_icon.run()


def main():
    file_config = load_file_config()

    parser = argparse.ArgumentParser(description="Agent de decouverte de certificats CertHelm")
    parser.add_argument("--controller-url", default=file_config.get("controller_url"),
                         help="Ex: http://10.0.0.5:8765")
    parser.add_argument("--token", default=file_config.get("token"), help="Jeton d'authentification de l'agent")
    parser.add_argument("--hostname", default=file_config.get("hostname") or socket.gethostname())
    parser.add_argument("--dry-run", action="store_true", help="Scanne et affiche sans envoyer au serveur")
    parser.add_argument("--tray", action="store_true",
                         help="Mode icone barre des taches, tourne en continu (Windows, session interactive)")
    parser.add_argument("--daemon", action="store_true",
                         help="Mode continu sans interface : scanne selon la frequence et execute les commandes "
                              "envoyees depuis CertHelm (journal dans agent.log)")
    parser.add_argument("--interval-hours", type=float, default=float(file_config.get("interval_hours", 6)),
                         help="Frequence des scans automatiques en mode --tray/--daemon (defaut: 6h, "
                              "ensuite pilotee depuis CertHelm)")
    args = parser.parse_args()

    if not args.dry_run and (not args.controller_url or not args.token):
        print("[ERREUR] --controller-url et --token sont requis (ou renseignez agent_config.json).")
        sys.exit(1)

    if args.daemon:
        run_daemon_mode(args.controller_url, args.token, args.hostname, args.interval_hours)
        return

    if args.tray:
        if platform.system() == "Windows":
            try:
                import ctypes
                console_hwnd = ctypes.windll.kernel32.GetConsoleWindow()
                if console_hwnd:
                    ctypes.windll.user32.ShowWindow(console_hwnd, 0)  # SW_HIDE - stays a background icon only
            except Exception:
                pass
        run_tray_mode(args.controller_url, args.token, args.hostname, args.interval_hours)
        return

    os_label, certs = run_single_scan()

    print(f"[INFO] {len(certs)} certificat(s) detecte(s) sur {args.hostname} ({os_label}).")
    for c in certs:
        print(f"  - {c['domain']}  (expire: {c['valid_till']}, {c['install_path']})")

    if args.dry_run:
        print("[INFO] --dry-run: rien envoye au serveur.")
        return

    send_checkin(args.controller_url, args.token, args.hostname, os_label, certs)


if __name__ == "__main__":
    main()
