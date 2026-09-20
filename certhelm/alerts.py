"""
Alerts shown by the bell on the SSL dashboard.

Pure functions (no UI, no network, no keyring) so they can be tested on their own.
An alert is a dict:

    {"category": "certificate" | "domain" | "organization" | "server" | "agent"
                 | "renewal" | "connection" | "discovery",
     "type":     "critical" | "warning" | "info",
     "title":    short subject,
     "message":  what is wrong and how long it has been that way,
     "target":   {"kind": ..., "value": ...} where a click should lead, or None}

Thresholds are deliberately fixed here rather than spread over the code:
  * a certificate is a warning 30 days before expiry and critical 7 days before;
  * something that expired more than 30 days ago is not reported any more - old
    orders for retired domains would otherwise raise alerts for ever;
  * an agent is offline after 10 minutes without a poll (24 hours = critical).
"""

import copy

CRITICAL, WARNING, INFO = 'critical', 'warning', 'info'
_RANK = {CRITICAL: 0, WARNING: 1, INFO: 2}

EXPIRY_WARNING_DAYS = 30
EXPIRY_CRITICAL_DAYS = 7
RECENTLY_EXPIRED_DAYS = 30
AGENT_OFFLINE_SECONDS = 600
AGENT_CRITICAL_SECONDS = 24 * 3600
LEGACY_AGENT_OFFLINE_HOURS = 48
LEGACY_AGENT_CRITICAL_HOURS = 168
RENEWAL_FAILURE_DAYS = 7
RENEWAL_SUCCESS_DAYS = 3


def make(category, severity, title, message, target=None, **extra):
    alert = {"category": category, "type": severity, "title": title, "message": message, "target": target}
    alert.update(extra)
    return alert


def duration_text(seconds):
    seconds = max(0, int(seconds))
    if seconds < 90:
        return "quelques secondes"
    if seconds < 3600:
        return f"{round(seconds / 60)} min"
    if seconds < 86400:
        return f"{round(seconds / 3600)} h"
    return f"{round(seconds / 86400)} j"


def expiry_text(days_left, verb="Expire"):
    if days_left < 0:
        return f"{'Expiré' if verb == 'Expire' else 'Expirée'} depuis {-days_left} jour(s)"
    if days_left == 0:
        return f"{verb} aujourd'hui"
    return f"{verb} dans {days_left} jour(s)"


def expiry_severity(days_left):
    return CRITICAL if days_left <= EXPIRY_CRITICAL_DAYS else WARNING


def in_expiry_window(days_left):
    return -RECENTLY_EXPIRED_DAYS <= days_left <= EXPIRY_WARNING_DAYS


def certificate_alert(domain, days_left, valid_till=''):
    return make('certificate', expiry_severity(days_left), f"Certificat: {domain}", expiry_text(days_left),
                {"kind": "cert", "value": domain}, domain=domain, days_left=days_left,
                valid_till=valid_till, servers=[])


def _validation_text(days_left):
    return f"Validation expire dans {days_left} jour(s)" if days_left > 0 else "Validation expire aujourd'hui"


def domain_alert(name, days_left):
    return make('domain', expiry_severity(days_left), f"Domaine (DCV): {name}", _validation_text(days_left),
                {"kind": "domain", "value": name}, days_left=days_left)


def organization_alert(name, days_left):
    return make('organization', expiry_severity(days_left), f"Organisation: {name}", _validation_text(days_left),
                {"kind": "org", "value": name}, days_left=days_left)


def connection_alerts(api_key_set, api_status, listener_running, listener_port):
    alerts = []
    if not api_key_set:
        alerts.append(make('connection', CRITICAL, "Connexion DigiCert",
                           "Clé API non configurée : les certificats du compte ne sont pas surveillés.",
                           {"kind": "settings", "value": "digicert"}))
    elif str(api_status).startswith('Error'):
        alerts.append(make('connection', CRITICAL, "Connexion DigiCert",
                           "Le compte DigiCert est injoignable ou la clé API est refusée. "
                           f"Détail : {str(api_status)[7:].strip()[:120]}",
                           {"kind": "settings", "value": "digicert"}))
    if not listener_running:
        alerts.append(make('connection', CRITICAL, "Récepteur des agents",
                           f"Le port {listener_port} n'a pas pu être ouvert : aucun agent ne peut se connecter. "
                           "Un autre programme l'utilise peut-être.",
                           {"kind": "settings", "value": "agents"}))
    return alerts


def agent_alerts(agents):
    """agents: rows from Api.get_agents() (they carry the computed liveness fields)."""
    alerts = []
    for a in agents:
        if not a.get('enabled', True):
            continue  # switched off on purpose from the console
        host = a['hostname']
        target = {"kind": "agent", "value": host}
        if a.get('supports_commands'):
            secs = a.get('seconds_since_seen')
            if secs is None and a.get('hours_since_checkin') is not None:
                secs = a['hours_since_checkin'] * 3600
            if secs is None:
                alerts.append(make('agent', WARNING, f"Agent: {host}", "Enregistré mais jamais entendu.", target))
            elif secs >= AGENT_OFFLINE_SECONDS:
                severity = CRITICAL if secs >= AGENT_CRITICAL_SECONDS else WARNING
                alerts.append(make('agent', severity, f"Agent: {host}",
                                   f"Hors ligne : aucun signe de vie depuis {duration_text(secs)}.", target))
        else:
            hours = a.get('hours_since_checkin')
            if hours is None or hours >= LEGACY_AGENT_OFFLINE_HOURS:
                severity = CRITICAL if hours is not None and hours >= LEGACY_AGENT_CRITICAL_HOURS else WARNING
                since = "jamais" if hours is None else f"depuis {duration_text(hours * 3600)}"
                alerts.append(make('agent', severity, f"Agent: {host}",
                                   f"Ancienne version : dernier rapport {since}. Réinstallez l'agent.", target))
    return alerts


def server_certificate_alerts(discovered, days_of, digicert_alerts, disabled_hosts=()):
    """Certificates the agents found installed. When DigiCert's own alert already covers the
    same domain and expiry date, the server is added to that alert instead of raising a twin."""
    by_key = {}
    for al in digicert_alerts:
        if al['category'] == 'certificate':
            by_key[(al['domain'].lower(), al.get('valid_till', '')[:10])] = al
    alerts = []
    for c in discovered:
        if c['hostname'] in disabled_hosts:
            continue
        days = days_of(c.get('valid_till'))
        if days is None or not in_expiry_window(days):
            continue
        twin = by_key.get(((c.get('domain') or '').lower(), (c.get('valid_till') or '')[:10]))
        if twin is not None:
            twin['servers'].append(c['hostname'])
            twin['message'] = f"{expiry_text(days)} · installé sur {', '.join(twin['servers'])}"
            continue
        alerts.append(make('server', expiry_severity(days), f"Serveur {c['hostname']}: {c.get('domain') or '?'}",
                           f"{expiry_text(days)} (certificat installé, {c.get('install_path') or 'emplacement inconnu'})",
                           {"kind": "agent", "value": c['hostname']}, days_left=days))
    return alerts


def renewal_alerts(jobs, age_days_of):
    """jobs: Api-visible renewal jobs (newest first). age_days_of(iso) -> days since that time."""
    alerts = []
    for j in jobs:
        target = {"kind": "agent", "value": j['hostname']}
        label = f"Renouvellement n°{j['id']}: {j['domain']}"
        age = age_days_of(j.get('updated_at'))
        if j['status'] == 'uncertain':
            alerts.append(make('renewal', CRITICAL, label, j.get('message') or "Statut incertain.", target))
        elif j['status'] == 'failed' and age is not None and age <= RENEWAL_FAILURE_DAYS:
            issued_not_installed = 'ÉMIS' in (j.get('message') or '')
            alerts.append(make('renewal', CRITICAL if issued_not_installed else WARNING, label,
                               j.get('message') or "Échec du renouvellement.", target))
        elif j['status'] == 'installed' and age is not None and age <= RENEWAL_SUCCESS_DAYS:
            alerts.append(make('renewal', INFO, label, "Certificat renouvelé et installé sur "
                               f"{j['hostname']}.", target))
    return alerts


def discovery_alert(unknown_count):
    if unknown_count <= 0:
        return []
    return [make('discovery', INFO, "Certificats inconnus de DigiCert",
                 f"{unknown_count} certificat(s) installé(s) sur des serveurs ne figurent pas dans le compte DigiCert.",
                 {"kind": "agent", "value": ""})]


def sort_alerts(alerts):
    """Most severe first; within a severity, system problems (no days_left: connection, agent,
    renewal) before expiries, and the nearest expiry first."""
    return sorted(copy.deepcopy(alerts), key=lambda a: (_RANK[a['type']], a.get('days_left', -10 ** 6)))
