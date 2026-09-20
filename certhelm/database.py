import sqlite3
import os
import datetime
import json

DB_PATH = 'workflow.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS assignments (
            domain TEXT PRIMARY KEY,
            approver TEXT,
            dns_verifier TEXT,
            installer TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cert_notes (
            domain TEXT PRIMARY KEY,
            note TEXT,
            updated_at TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cert_checklist (
            domain TEXT PRIMARY KEY,
            approval_done INTEGER DEFAULT 0,
            dns_done INTEGER DEFAULT 0,
            order_done INTEGER DEFAULT 0,
            installed_done INTEGER DEFAULT 0,
            verified_done INTEGER DEFAULT 0,
            updated_at TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cert_snapshot (
            domain TEXT PRIMARY KEY,
            valid_till TEXT,
            product TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS renewal_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT,
            old_valid_till TEXT,
            new_valid_till TEXT,
            product TEXT,
            detected_at TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agents (
            hostname TEXT PRIMARY KEY,
            os TEXT,
            agent_version TEXT,
            last_checkin TEXT,
            cert_count INTEGER DEFAULT 0,
            first_seen TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS discovered_certs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT,
            domain TEXT,
            issuer TEXT,
            valid_till TEXT,
            thumbprint TEXT,
            install_path TEXT,
            discovered_at TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agent_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT,
            type TEXT,
            params TEXT,
            status TEXT DEFAULT 'pending',
            created_at TEXT,
            delivered_at TEXT,
            finished_at TEXT,
            result TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS renewal_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT,
            domain TEXT,
            old_thumbprint TEXT,
            install_path TEXT,
            old_valid_till TEXT,
            status TEXT,
            message TEXT,
            mode TEXT,
            dns_names TEXT,
            digicert_order_id TEXT,
            digicert_cert_id TEXT,
            csr_pem TEXT,
            cert_pem TEXT,
            payload TEXT,
            new_thumbprint TEXT,
            new_valid_till TEXT,
            created_at TEXT,
            updated_at TEXT
        )
    ''')
    # Older workflow.db files have an agents table without the columns used by
    # the command channel - add them in place rather than recreating the table.
    existing = {row[1] for row in cursor.execute('PRAGMA table_info(agents)')}
    # last_ip: address the agent connected from. cert_management: NULL = the agent never
    # said (older version), 0/1 = whether its administrator allowed remote renewal.
    for column, ddl in (('last_seen', 'TEXT'),
                        ('enabled', 'INTEGER DEFAULT 1'),
                        ('interval_hours', 'REAL DEFAULT 6'),
                        ('last_ip', 'TEXT'),
                        ('cert_management', 'INTEGER')):
        if column not in existing:
            cursor.execute(f'ALTER TABLE agents ADD COLUMN {column} {ddl}')
    # The renewal "Simulation" mode was removed: its leftover jobs never touched
    # anything and would otherwise show up as unfinished renewals forever.
    cursor.execute("DELETE FROM renewal_jobs WHERE mode = 'dry_run' OR status = 'simulated'")
    conn.commit()
    conn.close()

def get_all_assignments():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT domain, approver, dns_verifier, installer FROM assignments')
    rows = cursor.fetchall()
    conn.close()
    return [{"domain": r[0], "approver": r[1], "dns_verifier": r[2], "installer": r[3]} for r in rows]

def get_assignment(domain):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT approver, dns_verifier, installer FROM assignments WHERE domain = ?', (domain,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"approver": row[0], "dns_verifier": row[1], "installer": row[2]}
    return {"approver": "", "dns_verifier": "", "installer": ""}

def save_assignment(domain, approver, dns_verifier, installer):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO assignments (domain, approver, dns_verifier, installer)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(domain) DO UPDATE SET
            approver = excluded.approver,
            dns_verifier = excluded.dns_verifier,
            installer = excluded.installer
    ''', (domain, approver, dns_verifier, installer))
    conn.commit()
    conn.close()

def get_note(domain):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT note FROM cert_notes WHERE domain = ?', (domain,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else ''

def get_all_notes():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT domain, note FROM cert_notes')
    rows = cursor.fetchall()
    conn.close()
    return {r[0]: r[1] for r in rows}

def save_note(domain, note):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO cert_notes (domain, note, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(domain) DO UPDATE SET note = excluded.note, updated_at = excluded.updated_at
    ''', (domain, note, datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()

CHECKLIST_KEYS = ['approval_done', 'dns_done', 'order_done', 'installed_done', 'verified_done']

def get_checklist(domain):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f'SELECT {", ".join(CHECKLIST_KEYS)} FROM cert_checklist WHERE domain = ?', (domain,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return {k: False for k in CHECKLIST_KEYS}
    return {k: bool(v) for k, v in zip(CHECKLIST_KEYS, row)}

def get_all_checklists():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f'SELECT domain, {", ".join(CHECKLIST_KEYS)} FROM cert_checklist')
    rows = cursor.fetchall()
    conn.close()
    return {r[0]: {k: bool(v) for k, v in zip(CHECKLIST_KEYS, r[1:])} for r in rows}

def save_checklist(domain, checklist):
    values = [1 if checklist.get(k) else 0 for k in CHECKLIST_KEYS]
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f'''
        INSERT INTO cert_checklist (domain, {", ".join(CHECKLIST_KEYS)}, updated_at)
        VALUES (?, {", ".join(["?"] * len(CHECKLIST_KEYS))}, ?)
        ON CONFLICT(domain) DO UPDATE SET
            {", ".join(f"{k} = excluded.{k}" for k in CHECKLIST_KEYS)},
            updated_at = excluded.updated_at
    ''', (domain, *values, datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_cert_snapshot(domain):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT valid_till FROM cert_snapshot WHERE domain = ?', (domain,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def set_cert_snapshot(domain, valid_till, product):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO cert_snapshot (domain, valid_till, product)
        VALUES (?, ?, ?)
        ON CONFLICT(domain) DO UPDATE SET valid_till = excluded.valid_till, product = excluded.product
    ''', (domain, valid_till, product))
    conn.commit()
    conn.close()

def record_renewal(domain, old_valid_till, new_valid_till, product):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO renewal_history (domain, old_valid_till, new_valid_till, product, detected_at)
        VALUES (?, ?, ?, ?, ?)
    ''', (domain, old_valid_till, new_valid_till, product, datetime.datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_renewal_history(domain=None, limit=200):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if domain:
        cursor.execute('''
            SELECT domain, old_valid_till, new_valid_till, product, detected_at
            FROM renewal_history WHERE domain = ? ORDER BY detected_at DESC LIMIT ?
        ''', (domain, limit))
    else:
        cursor.execute('''
            SELECT domain, old_valid_till, new_valid_till, product, detected_at
            FROM renewal_history ORDER BY detected_at DESC LIMIT ?
        ''', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [
        {"domain": r[0], "old_valid_till": r[1], "new_valid_till": r[2], "product": r[3], "detected_at": r[4]}
        for r in rows
    ]

def upsert_agent(hostname, os_name, agent_version, cert_count, last_ip=None, cert_management=None):
    now = datetime.datetime.now().isoformat()
    cm = None if cert_management is None else (1 if cert_management else 0)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO agents (hostname, os, agent_version, last_checkin, last_seen, cert_count, first_seen,
                            last_ip, cert_management)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hostname) DO UPDATE SET
            os = excluded.os,
            agent_version = excluded.agent_version,
            last_checkin = excluded.last_checkin,
            last_seen = excluded.last_seen,
            cert_count = excluded.cert_count,
            last_ip = COALESCE(excluded.last_ip, agents.last_ip),
            cert_management = excluded.cert_management
    ''', (hostname, os_name, agent_version, now, now, cert_count, now, last_ip, cm))
    conn.commit()
    conn.close()

def touch_agent(hostname, agent_version, last_ip=None, cert_management=None):
    """Heartbeat from an agent's poll. Only updates an agent that already did
    a real check-in - polling alone never creates an agent row."""
    now = datetime.datetime.now().isoformat()
    cm = None if cert_management is None else (1 if cert_management else 0)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('UPDATE agents SET last_seen = ?, agent_version = ?, last_ip = COALESCE(?, last_ip), '
                   'cert_management = ? WHERE hostname = ?',
                   (now, agent_version, last_ip, cm, hostname))
    conn.commit()
    conn.close()

def get_all_agents():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT a.hostname, a.os, a.agent_version, a.last_checkin, a.cert_count, a.first_seen,
               a.last_seen, COALESCE(a.enabled, 1), COALESCE(a.interval_hours, 6),
               (SELECT COUNT(*) FROM agent_commands c
                 WHERE c.hostname = a.hostname AND c.status IN ('pending', 'delivered')),
               a.last_ip, a.cert_management
        FROM agents a ORDER BY a.last_checkin DESC
    ''')
    rows = cursor.fetchall()
    conn.close()
    return [
        {"hostname": r[0], "os": r[1], "agent_version": r[2], "last_checkin": r[3], "cert_count": r[4],
         "first_seen": r[5], "last_seen": r[6], "enabled": bool(r[7]), "interval_hours": r[8],
         "pending_commands": r[9], "last_ip": r[10],
         "cert_management": None if r[11] is None else bool(r[11])}
        for r in rows
    ]

def delete_agent(hostname):
    """Forgets an agent: its row, the certificates it reported and its command queue.
    Renewal jobs are kept as history. A running agent simply registers again at its
    next check-in. Returns True if the agent existed."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM agents WHERE hostname = ?', (hostname,))
    existed = cursor.rowcount > 0
    cursor.execute('DELETE FROM discovered_certs WHERE hostname = ?', (hostname,))
    cursor.execute('DELETE FROM agent_commands WHERE hostname = ?', (hostname,))
    conn.commit()
    conn.close()
    return existed

def agent_is_registered(hostname):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM agents WHERE hostname = ?', (hostname,))
    found = cursor.fetchone() is not None
    conn.close()
    return found

def get_agent_settings(hostname):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT COALESCE(enabled, 1), COALESCE(interval_hours, 6) FROM agents WHERE hostname = ?', (hostname,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {"enabled": bool(row[0]), "interval_hours": row[1]}
    return {"enabled": True, "interval_hours": 6}

def set_agent_settings(hostname, enabled, interval_hours):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('UPDATE agents SET enabled = ?, interval_hours = ? WHERE hostname = ?',
                   (1 if enabled else 0, interval_hours, hostname))
    changed = cursor.rowcount
    conn.commit()
    conn.close()
    return changed > 0

# ----- Command queue (controller -> agent, delivered only when the agent polls) -----

COMMAND_STALE_MINUTES = 10  # a delivered command with no result after this long is reported as failed

def queue_command(hostname, cmd_type, params=None):
    """Adds a command for an agent. A scan_now already waiting for the same
    host is reused instead of stacking duplicates from repeated clicks."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if cmd_type == 'scan_now':
        cursor.execute("SELECT id FROM agent_commands WHERE hostname = ? AND type = 'scan_now' "
                       "AND status IN ('pending', 'delivered')", (hostname,))
        existing = cursor.fetchone()
        if existing:
            conn.close()
            return existing[0]
    now = datetime.datetime.now().isoformat()
    cursor.execute('INSERT INTO agent_commands (hostname, type, params, status, created_at) VALUES (?, ?, ?, ?, ?)',
                   (hostname, cmd_type, json.dumps(params or {}), 'pending', now))
    cmd_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return cmd_id

def claim_pending_commands(hostname, allowed_types):
    """Returns this agent's pending commands and marks them delivered. Commands
    whose type is not in allowed_types are never sent - they are failed on the
    spot. Also times out commands that were delivered but never acknowledged."""
    now = datetime.datetime.now()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    stale_before = (now - datetime.timedelta(minutes=COMMAND_STALE_MINUTES)).isoformat()
    cursor.execute("UPDATE agent_commands SET status = 'failed', finished_at = ?, result = ? "
                   "WHERE hostname = ? AND status = 'delivered' AND delivered_at < ?",
                   (now.isoformat(), "Pas de réponse de l'agent", hostname, stale_before))
    cursor.execute("SELECT id, type, params FROM agent_commands WHERE hostname = ? AND status = 'pending' ORDER BY id",
                   (hostname,))
    rows = []
    for r in cursor.fetchall():
        if r[1] in allowed_types:
            rows.append(r)
            cursor.execute("UPDATE agent_commands SET status = 'delivered', delivered_at = ? WHERE id = ?",
                           (now.isoformat(), r[0]))
        else:
            cursor.execute("UPDATE agent_commands SET status = 'failed', finished_at = ?, result = ? WHERE id = ?",
                           (now.isoformat(), f"Type de commande non autorisé: {r[1]}", r[0]))
    conn.commit()
    conn.close()
    commands = []
    for r in rows:
        try:
            params = json.loads(r[2]) if r[2] else {}
        except Exception:
            params = {}
        commands.append({"id": r[0], "type": r[1], "params": params})
    return commands

def finish_command(hostname, cmd_id, status, message):
    """Records the agent's outcome. Scoped to hostname so one agent can't
    close out another agent's command."""
    if status not in ('done', 'failed'):
        status = 'failed'
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE agent_commands SET status = ?, finished_at = ?, result = ? "
                   "WHERE id = ? AND hostname = ? AND status = 'delivered'",
                   (status, datetime.datetime.now().isoformat(), message[:500], cmd_id, hostname))
    changed = cursor.rowcount
    conn.commit()
    conn.close()
    return changed > 0

def withdraw_pending_commands_for_job(job_id):
    """When a renewal job ends (failed/cancelled/timed out), commands it queued
    that no agent has picked up yet must not be delivered later - otherwise an
    agent would still generate a key for a renewal nobody wants any more."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, params FROM agent_commands WHERE status = 'pending' "
                   "AND type IN ('generate_csr', 'install_cert')")
    ids = []
    for cmd_id, params in cursor.fetchall():
        try:
            if json.loads(params or '{}').get('job_id') == job_id:
                ids.append(cmd_id)
        except Exception:
            pass
    now = datetime.datetime.now().isoformat()
    for cmd_id in ids:
        cursor.execute("UPDATE agent_commands SET status = 'failed', finished_at = ?, result = ? WHERE id = ?",
                       (now, "Retirée : renouvellement clos avant livraison", cmd_id))
    conn.commit()
    conn.close()
    return len(ids)

def get_command(cmd_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, hostname, type, params, status FROM agent_commands WHERE id = ?', (cmd_id,))
    r = cursor.fetchone()
    conn.close()
    if not r:
        return None
    try:
        params = json.loads(r[3]) if r[3] else {}
    except Exception:
        params = {}
    return {"id": r[0], "hostname": r[1], "type": r[2], "params": params, "status": r[4]}

# ----- App settings (key/value). Kept out of config.json on purpose: the Settings
# form rewrites that whole file, which would silently reset a safety switch. -----

def get_setting(key, default=None):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM app_settings WHERE key = ?', (key,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else default

def set_setting(key, value):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('INSERT INTO app_settings (key, value) VALUES (?, ?) '
                   'ON CONFLICT(key) DO UPDATE SET value = excluded.value', (key, value))
    conn.commit()
    conn.close()

# ----- Certificate renewal jobs -----

# A job in one of these states is finished. Anything else (including 'uncertain',
# where a DigiCert order MAY exist) blocks a new job for the same certificate so
# an ambiguous failure can never turn into a double purchase.
RENEWAL_TERMINAL = ('installed', 'failed', 'cancelled')

_JOB_COLUMNS = ('id', 'hostname', 'domain', 'old_thumbprint', 'install_path', 'old_valid_till', 'status',
                'message', 'mode', 'dns_names', 'digicert_order_id', 'digicert_cert_id', 'csr_pem',
                'cert_pem', 'payload', 'new_thumbprint', 'new_valid_till', 'created_at', 'updated_at')

def _job_from_row(row):
    job = dict(zip(_JOB_COLUMNS, row))
    for key in ('dns_names', 'payload'):
        try:
            job[key] = json.loads(job[key]) if job[key] else None
        except Exception:
            job[key] = None
    return job

def create_renewal_job(hostname, domain, old_thumbprint, install_path, old_valid_till, status, message, mode,
                       dns_names, payload=None):
    """Creates a job unless one is already active for the same certificate.
    Returns (job_id, created). When not created, job_id is the active job."""
    now = datetime.datetime.now().isoformat()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    placeholders = ','.join('?' * len(RENEWAL_TERMINAL))
    cursor.execute(f'SELECT id FROM renewal_jobs WHERE hostname = ? AND old_thumbprint = ? '
                   f'AND status NOT IN ({placeholders})', (hostname, old_thumbprint, *RENEWAL_TERMINAL))
    existing = cursor.fetchone()
    if existing:
        conn.close()
        return existing[0], False
    cursor.execute('''
        INSERT INTO renewal_jobs (hostname, domain, old_thumbprint, install_path, old_valid_till, status, message,
                                  mode, dns_names, payload, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (hostname, domain, old_thumbprint, install_path, old_valid_till, status, message, mode,
          json.dumps(dns_names or []), json.dumps(payload) if payload is not None else None, now, now))
    job_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return job_id, True

def get_renewal_job(job_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(f'SELECT {", ".join(_JOB_COLUMNS)} FROM renewal_jobs WHERE id = ?', (job_id,))
    row = cursor.fetchone()
    conn.close()
    return _job_from_row(row) if row else None

def list_renewal_jobs(statuses=None, limit=100):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    if statuses:
        placeholders = ','.join('?' * len(statuses))
        cursor.execute(f'SELECT {", ".join(_JOB_COLUMNS)} FROM renewal_jobs WHERE status IN ({placeholders}) '
                       f'ORDER BY id DESC LIMIT ?', (*statuses, limit))
    else:
        cursor.execute(f'SELECT {", ".join(_JOB_COLUMNS)} FROM renewal_jobs ORDER BY id DESC LIMIT ?', (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [_job_from_row(r) for r in rows]

_JOB_UPDATABLE = set(_JOB_COLUMNS) - {'id', 'created_at'}

def update_renewal_job(job_id, expected_status=None, **fields):
    """Updates a job. With expected_status the update only applies if the job is
    still in that state - this is the compare-and-swap that stops two threads
    (or two ticks) from both acting on the same step, e.g. ordering twice.
    Returns True if a row was changed."""
    unknown = set(fields) - _JOB_UPDATABLE
    if unknown:
        raise ValueError(f'Unknown renewal job fields: {sorted(unknown)}')
    for key in ('dns_names', 'payload'):
        if key in fields and fields[key] is not None and not isinstance(fields[key], str):
            fields[key] = json.dumps(fields[key])
    fields['updated_at'] = datetime.datetime.now().isoformat()
    assignments = ', '.join(f'{k} = ?' for k in fields)
    params = list(fields.values()) + [job_id]
    sql = f'UPDATE renewal_jobs SET {assignments} WHERE id = ?'
    if expected_status is not None:
        sql += ' AND status = ?'
        params.append(expected_status)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(sql, params)
    changed = cursor.rowcount
    conn.commit()
    conn.close()
    return changed > 0

def get_recent_commands(hostname, limit=10):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id, type, status, created_at, finished_at, result FROM agent_commands '
                   'WHERE hostname = ? ORDER BY id DESC LIMIT ?', (hostname, limit))
    rows = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "type": r[1], "status": r[2], "created_at": r[3], "finished_at": r[4], "result": r[5]}
            for r in rows]

def replace_discovered_certs(hostname, certs):
    """Each agent check-in fully replaces that host's previously discovered certs
    (simplest way to reflect certs that were removed from the server since the
    last scan, without needing a separate reconciliation pass)."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('DELETE FROM discovered_certs WHERE hostname = ?', (hostname,))
    now = datetime.datetime.now().isoformat()
    for c in certs:
        cursor.execute('''
            INSERT INTO discovered_certs (hostname, domain, issuer, valid_till, thumbprint, install_path, discovered_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (hostname, c.get('domain', ''), c.get('issuer', ''), c.get('valid_till', ''), c.get('thumbprint', ''), c.get('install_path', ''), now))
    conn.commit()
    conn.close()

def get_all_discovered_certs():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT hostname, domain, issuer, valid_till, thumbprint, install_path, discovered_at FROM discovered_certs ORDER BY domain')
    rows = cursor.fetchall()
    conn.close()
    return [
        {"hostname": r[0], "domain": r[1], "issuer": r[2], "valid_till": r[3], "thumbprint": r[4], "install_path": r[5], "discovered_at": r[6]}
        for r in rows
    ]

# CREATE TABLE IF NOT EXISTS makes this safe to always run, including against an
# existing workflow.db from an earlier version that only had "assignments".
init_db()
