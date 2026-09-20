import webview
import json
import urllib.request
import urllib.error
import urllib.parse
import datetime
import threading
from plyer import notification
import time
import os
import keyring
import ssl
import socket
import smtplib
import secrets
import hmac
import copy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from email.mime.text import MIMEText
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import alerts as alerts_mod
import renewal
import digicert_api
from database import (
    get_assignment, get_all_assignments, save_assignment,
    get_note, get_all_notes, save_note,
    get_checklist, get_all_checklists, save_checklist,
    get_cert_snapshot, set_cert_snapshot, record_renewal, get_renewal_history,
    upsert_agent, get_all_agents, replace_discovered_certs, get_all_discovered_certs,
    touch_agent, get_agent_settings, set_agent_settings, set_setting as db_set_setting,
    queue_command, claim_pending_commands, finish_command, get_recent_commands,
    delete_agent as db_delete_agent, agent_is_registered, RENEWAL_TERMINAL
)

CONFIG_FILE = "config.json"
KEYRING_SERVICE = "CertHelm"
KEYRING_USERNAME = "api_key"
KEYRING_SMTP_USERNAME = "smtp_password"
KEYRING_AGENT_TOKEN_USERNAME = "agent_token"
DEFAULT_AGENT_PORT = 8765
AGENT_MAX_BODY_BYTES = 2 * 1024 * 1024  # 2MB — a scan result is tiny JSON, this is already generous
AGENT_LIVE_SECONDS = 180  # agents that poll are "online" if they were heard from this recently
# Fixed allowlist of what the controller may ask an agent to do. Agents refuse
# anything else, so this is the whole surface a compromised controller could use.
ALLOWED_AGENT_COMMANDS = {'scan_now', 'generate_csr', 'install_cert'}
MIN_SCAN_INTERVAL_HOURS = 1
MAX_SCAN_INTERVAL_HOURS = 168

def load_config():
    """Load non-sensitive settings from config.json."""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                # Remove api_key from config.json if it exists (migration)
                if 'api_key' in config:
                    api_key = config.pop('api_key')
                    # Migrate to keyring
                    keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, api_key)
                    save_config(config)
                return config
        except:
            pass
    return {"notifications_enabled": True}

def save_config(config_data):
    """Save non-sensitive settings to config.json. API key is never stored here."""
    safe_data = {k: v for k, v in config_data.items() if k != 'api_key'}
    with open(CONFIG_FILE, 'w') as f:
        json.dump(safe_data, f)

def get_api_key():
    """Retrieve API key from Windows Credential Manager."""
    return keyring.get_password(KEYRING_SERVICE, KEYRING_USERNAME) or ""

def set_api_key(api_key):
    """Store API key in Windows Credential Manager."""
    keyring.set_password(KEYRING_SERVICE, KEYRING_USERNAME, api_key)

def get_smtp_password():
    """Retrieve SMTP password from Windows Credential Manager."""
    return keyring.get_password(KEYRING_SERVICE, KEYRING_SMTP_USERNAME) or ""

def set_smtp_password(password):
    """Store SMTP password in Windows Credential Manager (never in config.json)."""
    keyring.set_password(KEYRING_SERVICE, KEYRING_SMTP_USERNAME, password)

def get_agent_token():
    """Retrieve (or lazily generate) the shared secret agents must present to
    the check-in endpoint. Generated once on first use so there's always a
    real token protecting the listener, never a blank/default one."""
    token = keyring.get_password(KEYRING_SERVICE, KEYRING_AGENT_TOKEN_USERNAME)
    if not token:
        token = secrets.token_urlsafe(32)
        keyring.set_password(KEYRING_SERVICE, KEYRING_AGENT_TOKEN_USERNAME, token)
    return token

def set_agent_token(token):
    keyring.set_password(KEYRING_SERVICE, KEYRING_AGENT_TOKEN_USERNAME, token)

URL = "https://www.digicert.com/services/v2/order/certificate"

def pick_reachable_ip(candidates):
    """First address other machines could use to reach this one: not loopback and not the
    169.254.x.x link-local address of an unplugged network card (which hostname lookups often return)."""
    for ip in candidates:
        if ip and not ip.startswith(("127.", "169.254.", "0.")):
            return ip
    return "127.0.0.1"

def guess_local_ip():
    candidates = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))  # documentation-only address: nothing is sent, it only picks the route
            candidates.append(s.getsockname()[0])
    except Exception:
        pass
    try:
        candidates += socket.gethostbyname_ex(socket.gethostname())[2]
    except Exception:
        pass
    return pick_reachable_ip(candidates)

class Api:
    def __init__(self):
        self.orders = []
        self.domains = []
        self.organizations = []
        self.users = []
        self.balance = None
        self.audit_logs = []
        self.last_notified_count = -1
        self.last_certs = []
        self._digicert_alerts = []  # DigiCert-derived alerts, rebuilt on every dashboard load
        self.api_status = "Not Connected"
        self.config = load_config()
        self.api_key = get_api_key()
        # Leading underscore keeps pywebview from exposing the manager's internals to the UI;
        # only the explicit Api methods below are callable from JavaScript.
        global _renewal_manager
        self._renewal = renewal.RenewalManager(get_api_key=lambda: self.api_key, get_orders=self._orders_loaded)
        _renewal_manager = self._renewal

    def fetch_digicert_data(self):
        self.orders = []
        offset = 0
        limit = 1000
        
        try:
            while True:
                filter_query = f"?limit={limit}&offset={offset}"
                req = urllib.request.Request(URL + filter_query)
                req.add_header("X-DC-DEVKEY", self.api_key)
                req.add_header("Content-Type", "application/json")
                with urllib.request.urlopen(req, timeout=10) as response:
                    data = json.loads(response.read().decode())
                    page_orders = data.get('orders', [])
                    self.orders.extend(page_orders)
                    if len(page_orders) < limit:
                        break
                    offset += limit
            
            # Fetch Domains
            self.domains = []
            offset = 0
            while True:
                req = urllib.request.Request(f"https://www.digicert.com/services/v2/domain?limit={limit}&offset={offset}")
                req.add_header("X-DC-DEVKEY", self.api_key)
                req.add_header("Content-Type", "application/json")
                with urllib.request.urlopen(req, timeout=10) as response:
                    data = json.loads(response.read().decode())
                    page_domains = data.get('domains', [])
                    self.domains.extend(page_domains)
                    if len(page_domains) < limit:
                        break
                    offset += limit

            # Fetch Organizations
            self.organizations = []
            offset = 0
            while True:
                req = urllib.request.Request(f"https://www.digicert.com/services/v2/organization?limit={limit}&offset={offset}")
                req.add_header("X-DC-DEVKEY", self.api_key)
                req.add_header("Content-Type", "application/json")
                with urllib.request.urlopen(req, timeout=10) as response:
                    data = json.loads(response.read().decode())
                    page_orgs = data.get('organizations', [])
                    
                    for org in page_orgs:
                        org_id = org.get('id')
                        try:
                            v_req = urllib.request.Request(f"https://www.digicert.com/services/v2/organization/{org_id}/validation")
                            v_req.add_header("X-DC-DEVKEY", self.api_key)
                            v_req.add_header("Content-Type", "application/json")
                            with urllib.request.urlopen(v_req, timeout=5) as v_resp:
                                v_data = json.loads(v_resp.read().decode())
                                org['detailed_validations'] = v_data.get('validations', [])
                        except:
                            org['detailed_validations'] = []
                            
                    self.organizations.extend(page_orgs)
                    if len(page_orgs) < limit:
                        break
                    offset += limit
                    
            # Fetch Users
            self.users = []
            try:
                req = urllib.request.Request("https://www.digicert.com/services/v2/user")
                req.add_header("X-DC-DEVKEY", self.api_key)
                req.add_header("Content-Type", "application/json")
                with urllib.request.urlopen(req, timeout=10) as response:
                    data = json.loads(response.read().decode())
                    self.users = data.get('users', [])
            except Exception as e:
                print(f"Erreur API Users: {e}")
                
            # Fetch Account Balance
            self.balance = None
            try:
                req = urllib.request.Request("https://www.digicert.com/services/v2/account/balance")
                req.add_header("X-DC-DEVKEY", self.api_key)
                req.add_header("Content-Type", "application/json")
                with urllib.request.urlopen(req, timeout=10) as response:
                    data = json.loads(response.read().decode())
                    self.balance = data
            except Exception as e:
                print(f"Erreur API Balance (Peut-être non prépayé): {e}")

            # Fetch Audit Logs
            self.audit_logs = []
            try:
                req = urllib.request.Request("https://www.digicert.com/services/v2/audit")
                req.add_header("X-DC-DEVKEY", self.api_key)
                req.add_header("Content-Type", "application/json")
                with urllib.request.urlopen(req, timeout=10) as response:
                    data = json.loads(response.read().decode())
                    self.audit_logs = data.get('logs', [])
            except Exception as e:
                print(f"Erreur API Audit Logs: {e}")
                    
            self.api_status = "Connected"
        except Exception as e:
            print(f"Erreur API: {e}")
            self.api_status = f"Error: {str(e)}"

    def get_dashboard_data(self):
        if not self.orders:
            self.fetch_digicert_data()
            
        today = datetime.datetime.now().date()
        total = 0
        expiring = 0
        action_required = 0
        certs = []
        digicert_alerts = []

        # We will keep track of active or pending certs for each domain to avoid duplicates
        # But we prioritize 'pending' over 'issued' if there are multiple.
        domain_records = {}

        for order in self.orders:
            status = order.get('status')
            if status not in ['issued', 'pending', 'needs_approval']:
                continue
                
            cert = order.get('certificate', {})
            domain = cert.get('common_name')
            if not domain:
                continue

            # Check if valid_till exists (issued), otherwise use a dummy date for pending
            valid_till_str = cert.get('valid_till')
            if not valid_till_str:
                valid_till_str = "2099-12-31" # Pending orders don't expire yet
                
            try:
                valid_till = datetime.datetime.strptime(valid_till_str, '%Y-%m-%d').date()
            except:
                continue
                
            # Keep the most relevant order for the domain
            if domain not in domain_records:
                domain_records[domain] = {'order': order, 'date': valid_till, 'status': status}
            else:
                existing = domain_records[domain]
                # If current is pending and existing is not, replace it
                if status == 'pending' and existing['status'] != 'pending':
                    domain_records[domain] = {'order': order, 'date': valid_till, 'status': status}
                # If both are same status, keep the one with the highest date
                elif status == existing['status'] and valid_till > existing['date']:
                    domain_records[domain] = {'order': order, 'date': valid_till, 'status': status}

        for domain, rec in domain_records.items():
            order = rec['order']
            status = rec['status']
            cert = order.get('certificate', {})
            valid_till_str = cert.get('valid_till') or order.get('date_created', '')[:10]
            
            if cert.get('valid_till'):
                valid_till = datetime.datetime.strptime(cert.get('valid_till'), '%Y-%m-%d').date()
                days_left = (valid_till - today).days
            else:
                days_left = 9999 # Pending
                
            if days_left < 0:
                # Expired: not counted, but a certificate that just expired is exactly what must be flagged.
                if -days_left <= alerts_mod.RECENTLY_EXPIRED_DAYS:
                    digicert_alerts.append(alerts_mod.certificate_alert(domain, days_left, cert.get('valid_till') or ''))
                continue

            total += 1
                
            product_info = cert.get('product', {})
            product_name = product_info.get('name_id', product_info.get('name', 'Secure Site OV'))
            org_info = order.get('organization', {})
            org_id = org_info.get('id')
            assign = get_assignment(domain)
            note = get_note(domain)
            checklist = get_checklist(domain)
            issued_date = (order.get('date_created') or '')[:10]

            validity_days = None
            if status != 'pending' and issued_date and cert.get('valid_till'):
                try:
                    issued_d = datetime.datetime.strptime(issued_date, '%Y-%m-%d').date()
                    valid_d = datetime.datetime.strptime(cert.get('valid_till'), '%Y-%m-%d').date()
                    validity_days = (valid_d - issued_d).days
                except Exception:
                    validity_days = None

            certs.append({
                "domain": domain,
                "org_id": org_id,
                "status": status,
                "valid_till": valid_till_str,
                "days_left": days_left,
                "product": product_name,
                "issued_date": issued_date,
                "validity_days": validity_days,
                "approver": assign["approver"],
                "dns_verifier": assign["dns_verifier"],
                "installer": assign["installer"],
                "note": note,
                "checklist": checklist
            })
            
            if days_left <= 30:
                expiring += 1
                digicert_alerts.append(alerts_mod.certificate_alert(domain, days_left, valid_till_str))
            if days_left <= 7:
                action_required += 1

        certs = sorted(certs, key=lambda x: x['days_left'])
        
        # Process Domains
        domains_data = []
        for d in self.domains:
            domain_id = d.get('id', '')
            name = d.get('name', 'Unknown')
            method = d.get('dcv_approval_method', 'N/A')
            dcv_exp_str = d.get('dcv_expiration_datetime')
            date_added = d.get('date_created', '')
            if date_added:
                try:
                    date_added = datetime.datetime.strptime(date_added[:10], '%Y-%m-%d').strftime('%d %b %Y')
                except: pass
                
            org_info = d.get('organization', {})
            org_id = org_info.get('id', '')
            org_name = org_info.get('name', 'N/A')
            
            # Find the org's full details for address
            org_address = ""
            for o in self.organizations:
                if str(o.get('id')) == str(org_id):
                    addr_parts = [o.get('address', ''), o.get('city', ''), o.get('zip', ''), o.get('country', '')]
                    org_address = " ".join([p for p in addr_parts if p])
                    break
            
            days_left = 9999
            exp_date = "N/A"
            if dcv_exp_str:
                try:
                    vd = datetime.datetime.strptime(dcv_exp_str[:10], '%Y-%m-%d').date()
                    days_left = (vd - today).days
                    exp_date = vd.strftime('%d %b %Y')
                except: pass
                
            status_text = "Pending validation"
            if exp_date != "N/A":
                status_text = "Validated" if days_left >= 0 else "Expired"
                
            domains_data.append({
                "id": domain_id,
                "name": name,
                "org_name": org_name,
                "org_id": org_id,
                "org_address": org_address,
                "date_added": date_added,
                "method": method,
                "expires": exp_date,
                "status": status_text,
                "days_left": days_left
            })
            if days_left <= 30 and days_left >= 0:
                digicert_alerts.append(alerts_mod.domain_alert(name, days_left))
                if days_left <= 7: action_required += 1
                    
        domains_data = sorted(domains_data, key=lambda x: x['days_left'])

        # Process Organizations
        orgs_data = []
        for org in self.organizations:
            org_id = org.get('id', '')
            name = org.get('name', 'Unknown')
            status_val = org.get('status', 'inactive')
            addr_parts = [org.get('address', ''), org.get('city', ''), org.get('zip', ''), org.get('country', '')]
            address = " ".join([p for p in addr_parts if p])
            
            # Get validations from the detailed fetch OR the default if available
            validations = org.get('detailed_validations') or org.get('validations', [])
            
            validated_for = []
            pending_for = []
            
            best_days_left = 9999
            
            for v in validations:
                v_type = v.get('name', '')
                v_status = v.get('status', '')
                v_exp = v.get('validated_until')
                
                if v_status == 'active' or v_status == 'valid':
                    exp_str = ""
                    d_left = 9999
                    if v_exp:
                        try:
                            vd = datetime.datetime.strptime(v_exp[:10], '%Y-%m-%d').date()
                            d_left = (vd - today).days
                            exp_str = f" ({vd.strftime('%d %b %Y')})"
                            if d_left < best_days_left:
                                best_days_left = d_left
                        except: pass
                    validated_for.append(f"{v_type}{exp_str}")
                else:
                    pending_for.append(v_type)
            
            if best_days_left == 9999:
                best_days_left = -1
                
            validated_str = ", ".join(validated_for) if validated_for else "-"
            pending_str = ", ".join(pending_for) if pending_for else "-"

            orgs_data.append({
                "id": org_id,
                "name": name,
                "address": address,
                "status": "Active" if status_val == "active" else "Deactivated",
                "validated_for": validated_str,
                "pending_for": pending_str,
                "days_left": best_days_left
            })
            if best_days_left <= 30 and best_days_left >= 0:
                digicert_alerts.append(alerts_mod.organization_alert(name, best_days_left))
                if best_days_left <= 7: action_required += 1
                    
        orgs_data = sorted(orgs_data, key=lambda x: x['days_left'])
        
        # Calculate Prerequisites for Certs
        for cert_dict in certs:
            prereqs = []
            c_domain = cert_dict['domain']
            c_org_id = cert_dict.get('org_id')
            c_days_left = cert_dict['days_left']
            c_status = cert_dict.get('status', 'issued')
            
            if c_status == 'pending':
                # Check DCV (Domain)
                for d in domains_data:
                    if d['name'] == c_domain:
                        if d['days_left'] <= 0 or d['status'] == 'Pending validation':
                            prereqs.append("DCV")
                        break
                # Check Org Validation
                if c_org_id:
                    for o in orgs_data:
                        if str(o['id']) == str(c_org_id):
                            if o['days_left'] <= 0:
                                prereqs.append("ORG")
                            break
            else:
                # Check DCV (Domain)
                for d in domains_data:
                    if d['name'] == c_domain:
                        # If domain days_left is less than cert days_left + 30, we need DCV
                        if d['days_left'] < c_days_left + 30:
                            prereqs.append("DCV")
                        break
                        
                # Check Org Validation
                if c_org_id:
                    for o in orgs_data:
                        if str(o['id']) == str(c_org_id):
                            if o['days_left'] < c_days_left + 30:
                                prereqs.append("ORG")
                            break
                        
            cert_dict['prerequisites'] = prereqs

        self._digicert_alerts = digicert_alerts
        self.last_certs = certs
        alerts = self._compose_alerts()
        self._notify_desktop(alerts)

        self.maybe_send_expiry_email_alert(certs)
        self.detect_renewals(certs)

        return {
            "api_status": self.api_status,
            "total": total,
            "expiring": expiring,
            "action_required": action_required,
            "certs": certs,
            "domains": domains_data,
            "organizations": orgs_data,
            "users": self.users,
            "balance": self.balance,
            "audit_logs": self.audit_logs,
            "notifications": alerts,
            "alerts_generated_at": datetime.datetime.now().isoformat(timespec='seconds'),
            "config": {
                "api_key_set": bool(self.api_key),
                "api_key_masked": ('*' * (len(self.api_key) - 4) + self.api_key[-4:]) if len(self.api_key) > 4 else '****',
                "notifications_enabled": self.config.get('notifications_enabled', True),
                "alert_threshold_days": self.config.get('alert_threshold_days', 10),
                "smtp_host": self.config.get('smtp_host', ''),
                "smtp_port": self.config.get('smtp_port', ''),
                "smtp_user": self.config.get('smtp_user', ''),
                "smtp_from": self.config.get('smtp_from', ''),
                "smtp_use_tls": self.config.get('smtp_use_tls', True),
                "smtp_recipients": self.config.get('smtp_recipients', []),
                "smtp_password_set": bool(get_smtp_password())
            }
        }

    # ===== Alerts (the bell on the SSL dashboard; rules live in alerts.py) =====

    @staticmethod
    def _days_until(iso_date):
        try:
            return (datetime.date.fromisoformat(str(iso_date)[:10]) - datetime.date.today()).days
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _age_days(iso_time):
        try:
            return (datetime.datetime.now() - datetime.datetime.fromisoformat(iso_time)).total_seconds() / 86400
        except (TypeError, ValueError):
            return None

    def _compose_alerts(self):
        """DigiCert-derived alerts (cached from the last dashboard load) plus everything that
        can change between two loads: agents, what they found installed, renewals, connections.
        Cheap enough to recompute every minute."""
        alerts = copy.deepcopy(self._digicert_alerts)
        agents = self.get_agents()
        disabled = {a['hostname'] for a in agents if not a.get('enabled', True)}
        alerts += alerts_mod.connection_alerts(
            bool(self.api_key), self.api_status, _agent_server is not None,
            self.config.get('agent_listener_port', DEFAULT_AGENT_PORT))
        alerts += alerts_mod.agent_alerts(agents)
        alerts += alerts_mod.server_certificate_alerts(get_all_discovered_certs(), self._days_until, alerts, disabled)
        alerts += alerts_mod.renewal_alerts(self._renewal.list_jobs(limit=50), self._age_days)
        if self.last_certs:
            alerts += alerts_mod.discovery_alert(len(self.get_discovery_summary()['unknown_to_digicert']))
        return alerts_mod.sort_alerts(alerts)

    def get_alerts(self):
        """Light refresh for the bell (called every minute by the UI)."""
        alerts = self._compose_alerts()
        return {"alerts": alerts, "generated_at": datetime.datetime.now().isoformat(timespec='seconds')}

    def _notify_desktop(self, alerts):
        """One native notification each time the number of critical alerts changes."""
        critical = [a for a in alerts if a['type'] == alerts_mod.CRITICAL]
        if len(critical) == self.last_notified_count:
            return
        self.last_notified_count = len(critical)
        if not critical or not self.config.get('notifications_enabled', True):
            return
        try:
            shown = '\n'.join(f"{a['title']} - {a['message']}" for a in critical[:3])
            more = f"\n... et {len(critical) - 3} autre(s)" if len(critical) > 3 else ''
            notification.notify(title=f'CertHelm : {len(critical)} alerte(s) critique(s)',
                                message=(shown + more)[:250], app_name='CertHelm', timeout=10)
        except Exception as e:
            print("Notification error:", e)

    def save_settings(self, new_config):
        # Store API key securely in Windows Credential Manager
        api_key = new_config.get('api_key', '')
        if api_key and api_key != self.get_masked_key():
            set_api_key(api_key)
            self.api_key = api_key

        # Same treatment for the SMTP password: only overwrite if the user actually
        # typed a new one (the frontend never re-sends the stored password back).
        smtp_password = new_config.get('smtp_password', '')
        if smtp_password:
            set_smtp_password(smtp_password)

        # Save non-sensitive settings to config.json (secrets never land here)
        self.config = {k: v for k, v in new_config.items() if k not in ('api_key', 'smtp_password')}
        save_config(self.config)

        self.fetch_digicert_data()
        return {"status": "success"}

    def test_smtp_config(self, smtp_conf):
        """Sends an immediate test e-mail using the form's current values (not
        necessarily saved yet), so the user gets feedback before committing to it."""
        try:
            self.send_smtp_email(
                smtp_conf,
                "Test - CertHelm",
                "Ceci est un e-mail de test envoyé depuis CertHelm pour vérifier la configuration SMTP d'alerting."
            )
            return {"status": "success", "message": "E-mail de test envoyé avec succès."}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def send_smtp_email(self, smtp_conf, subject, body):
        """Low-level SMTP send. Falls back to the stored password when the caller
        doesn't supply one (e.g. the automatic alert path, which reads from self.config)."""
        host = (smtp_conf.get('smtp_host') or '').strip()
        port = int(smtp_conf.get('smtp_port') or 587)
        user = (smtp_conf.get('smtp_user') or '').strip()
        password = smtp_conf.get('smtp_password') or get_smtp_password()
        from_addr = (smtp_conf.get('smtp_from') or user).strip()
        use_tls = smtp_conf.get('smtp_use_tls', True)
        recipients = smtp_conf.get('smtp_recipients') or []
        if isinstance(recipients, str):
            recipients = [r.strip() for r in recipients.split(',') if r.strip()]

        if not host:
            raise ValueError("Serveur SMTP manquant.")
        if not recipients:
            raise ValueError("Aucun destinataire configuré.")

        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = from_addr or user
        msg['To'] = ', '.join(recipients)

        with smtplib.SMTP(host, port, timeout=10) as server:
            if use_tls:
                server.starttls()
            if user and password:
                server.login(user, password)
            server.sendmail(from_addr or user, recipients, msg.as_string())

    def maybe_send_expiry_email_alert(self, certs):
        """Sends at most one summary e-mail per calendar day when SMTP alerting is
        configured and there are certificates within the alert threshold. Mirrors
        the native desktop notification but reaches people who don't have the app
        open at all."""
        smtp_host = self.config.get('smtp_host')
        recipients = self.config.get('smtp_recipients')
        if not smtp_host or not recipients:
            return

        today_str = datetime.datetime.now().date().isoformat()
        if self.config.get('_last_email_alert_date') == today_str:
            return

        threshold = self.config.get('alert_threshold_days', 10)
        urgent = [c for c in certs if c.get('status') != 'pending' and c.get('days_left', 9999) <= threshold]
        if not urgent:
            return

        lines = [f"- {c['domain']} : expire dans {c['days_left']} jour(s) ({c.get('product', '')})" for c in urgent]
        body = "Certificats SSL à renouveler prochainement :\n\n" + "\n".join(lines)
        subject = f"CertHelm - {len(urgent)} certificat(s) à renouveler (<= {threshold}j)"

        try:
            self.send_smtp_email(self.config, subject, body)
            self.config['_last_email_alert_date'] = today_str
            save_config(self.config)
        except Exception as e:
            print(f"Erreur envoi alerte SMTP: {e}")

    def detect_renewals(self, certs):
        """Compares each certificate's current valid_till against the last value we
        saw for that domain. A later date means it was renewed since our last check
        -> logged to renewal_history so the app builds a real history over time
        instead of only ever showing a snapshot of "now"."""
        for c in certs:
            if c.get('status') == 'pending':
                continue
            domain = c.get('domain')
            new_valid_till = c.get('valid_till')
            if not domain or not new_valid_till:
                continue

            old_valid_till = get_cert_snapshot(domain)
            if old_valid_till is None:
                set_cert_snapshot(domain, new_valid_till, c.get('product', ''))
                continue
            if old_valid_till == new_valid_till:
                continue

            try:
                old_d = datetime.datetime.strptime(old_valid_till, '%Y-%m-%d').date()
                new_d = datetime.datetime.strptime(new_valid_till, '%Y-%m-%d').date()
                if new_d > old_d:
                    record_renewal(domain, old_valid_till, new_valid_till, c.get('product', ''))
            except Exception:
                pass
            set_cert_snapshot(domain, new_valid_till, c.get('product', ''))

    def save_cert_note(self, domain, note):
        save_note(domain, note)
        return {"status": "success"}

    def save_cert_checklist(self, domain, checklist):
        save_checklist(domain, checklist)
        return {"status": "success"}

    def get_renewal_history(self, domain=None):
        return get_renewal_history(domain)

    def get_compliance_data(self):
        """Aggregates the certificates from the last dashboard load by product/
        validity period, plus the renewal history logged so far -- used by the
        Conformite & Tendances view to show how certificate lifetimes are
        trending, which is the whole reason this app exists (DigiCert keeps
        shortening its max validity periods)."""
        certs = getattr(self, 'last_certs', [])
        by_product = {}
        for c in certs:
            if not c.get('validity_days'):
                continue
            p = c.get('product', 'Inconnu')
            entry = by_product.setdefault(p, {"product": p, "count": 0, "validities": []})
            entry["count"] += 1
            entry["validities"].append(c['validity_days'])

        products = []
        for p, entry in by_product.items():
            vals = entry["validities"]
            products.append({
                "product": p,
                "count": entry["count"],
                "avg_validity_days": round(sum(vals) / len(vals)),
                "min_validity_days": min(vals),
                "max_validity_days": max(vals)
            })
        products.sort(key=lambda x: -x["count"])

        history = get_renewal_history(limit=500)
        return {"products": products, "history": history}

    def force_refresh(self):
        """Force re-fetch all data from DigiCert API."""
        self.orders = []
        self.domains = []
        self.organizations = []
        self.users = []
        self.balance = None
        self.audit_logs = []
        self.fetch_digicert_data()
        return {"status": "refreshed"}
    
    def get_masked_key(self):
        """Return a masked version of the API key for display."""
        key = get_api_key()
        if key and len(key) > 4:
            return '*' * (len(key) - 4) + key[-4:]
        return '****'

    def get_all_assignments(self):
        return get_all_assignments()
        
    def save_assignment(self, domain, approver, dns, installer):
        save_assignment(domain, approver, dns, installer)
        return "Success"
        
    def trigger_notification(self, domain):
        assign = get_assignment(domain)
        approver = assign["approver"] or "Non assigné"
        try:
            notification.notify(
                title='CertHelm - renouvellement',
                message=f'Action requise pour {domain}\nApprobateur: {approver}',
                app_name='CertHelm',
                timeout=5
            )
            return f"Notification Desktop envoyée pour {domain} (Cible: {approver})."
        except Exception as e:
            return f"Erreur de notification: {e}"

    def send_outlook_email(self, to, subject, html_body):
        try:
            import win32com.client as win32
            outlook = win32.Dispatch('outlook.application')
            mail = outlook.CreateItem(0)
            mail.To = to
            mail.Subject = subject
            mail.HTMLBody = html_body
            mail.Display(False)
            return {"status": "success", "message": "Email généré dans Outlook."}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def check_live_cert(self, domain):
        try:
            # Disable verification so we can inspect expired/invalid certificates
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    
                    if not der_cert:
                        return {"status": "error", "message": "Aucun certificat retourné par le serveur."}
                        
                    # Parse the certificate using cryptography
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    
                    # Extract issuer organization
                    issuer_org = "Inconnu"
                    for attribute in cert.issuer:
                        if attribute.oid == x509.NameOID.ORGANIZATION_NAME:
                            issuer_org = attribute.value
                            break
                            
                    # Extract expiry
                    expiry_date = cert.not_valid_after_utc
                    
                    return {
                        "status": "success",
                        "issuer": issuer_org,
                        "expiry": expiry_date.strftime('%Y-%m-%d %H:%M:%S')
                    }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def get_agent_config(self):
        """Connection details an admin needs to configure agents: where to
        point them and the token to authenticate with. The token itself is
        never sent back in full once already set — only a masked preview,
        same pattern as the DigiCert API key."""
        token = get_agent_token()
        port = self.config.get('agent_listener_port', DEFAULT_AGENT_PORT)
        local_ip = guess_local_ip()
        return {
            "token_masked": ('*' * max(0, len(token) - 6)) + token[-6:],
            "listener_port": port,
            # Base URL only (no /agent/checkin) - that's what belongs in an agent's
            # controller_url; the agent script appends the path itself. Showing the
            # full check-in URL here previously caused it to get doubled up when
            # pasted verbatim into agent_config.json.
            "listener_url_hint": f"http://{local_ip}:{port}",
            "listener_running": _agent_server is not None
        }

    def regenerate_agent_token(self):
        """Rotates the shared secret. Returns the new token ONCE in full so it
        can be copied into agent configs — after this call it is only ever
        shown masked again."""
        new_token = secrets.token_urlsafe(32)
        set_agent_token(new_token)
        return {"status": "success", "token": new_token}

    def get_agents(self):
        agents = get_all_agents()
        now = datetime.datetime.now()
        for a in agents:
            # Agents v2+ poll every few seconds, so they can be judged "online"
            # tightly and can receive commands; older ones only check in once
            # per scan and keep the loose 24h rule.
            a['supports_commands'] = self._agent_supports_commands(a.get('agent_version'))
            a['supports_cert_management'] = renewal.supports_cert_management(a.get('agent_version'))
            try:
                last = datetime.datetime.fromisoformat(a['last_checkin'])
                delta_hours = (now - last).total_seconds() / 3600
                a['hours_since_checkin'] = round(delta_hours, 1)
                a['online'] = delta_hours < 24
            except Exception:
                a['online'] = False
                a['hours_since_checkin'] = None
            if a['supports_commands'] and a.get('last_seen'):
                try:
                    seen_seconds = (now - datetime.datetime.fromisoformat(a['last_seen'])).total_seconds()
                    a['online'] = seen_seconds < AGENT_LIVE_SECONDS
                    a['seconds_since_seen'] = int(seen_seconds)
                except Exception:
                    pass
        return agents

    @staticmethod
    def _agent_supports_commands(agent_version):
        try:
            return float(agent_version) >= 2.0
        except (TypeError, ValueError):
            return False

    def _find_agent(self, hostname):
        return next((a for a in get_all_agents() if a['hostname'] == hostname), None)

    def request_agent_scan(self, hostname):
        """Queues a 'scan now' for an agent. It runs the next time that agent
        polls (seconds, for a running agent) - the controller never connects
        out to the agent."""
        agent = self._find_agent(hostname)
        if not agent:
            return {"status": "error", "message": "Agent inconnu"}
        if not self._agent_supports_commands(agent.get('agent_version')):
            return {"status": "error", "message": "Cet agent est trop ancien (v1) pour recevoir des commandes. Réinstallez la dernière version."}
        return {"status": "success", "command_id": queue_command(hostname, 'scan_now')}

    def update_agent_settings(self, hostname, enabled, interval_hours):
        agent = self._find_agent(hostname)
        if not agent:
            return {"status": "error", "message": "Agent inconnu"}
        try:
            interval = float(interval_hours)
        except (TypeError, ValueError):
            return {"status": "error", "message": "Fréquence invalide"}
        if not (MIN_SCAN_INTERVAL_HOURS <= interval <= MAX_SCAN_INTERVAL_HOURS):
            return {"status": "error",
                    "message": f"La fréquence doit être entre {MIN_SCAN_INTERVAL_HOURS}h et {MAX_SCAN_INTERVAL_HOURS}h"}
        set_agent_settings(hostname, bool(enabled), interval)
        return {"status": "success"}

    def get_agent_commands(self, hostname):
        return get_recent_commands(hostname)

    def get_agent_certs(self, hostname):
        """Certificates this agent found on its server at its last scan."""
        return [c for c in get_all_discovered_certs() if c['hostname'] == hostname]

    def delete_agent(self, hostname):
        """Removes an agent from the console (server decommissioned, agent uninstalled...).
        A running agent would just register again, so this is refused while a renewal
        is in progress on that server."""
        if not self._find_agent(hostname):
            return {"status": "error", "message": "Agent inconnu"}
        if any(j['hostname'] == hostname and j['status'] not in RENEWAL_TERMINAL
               for j in self._renewal.list_jobs(limit=200)):
            return {"status": "error", "message": "Un renouvellement est en cours sur ce serveur : annulez-le d'abord."}
        db_delete_agent(hostname)
        return {"status": "success"}

    # ===== Certificate renewal (see renewal.py for the workflow and its safety rules) =====

    def _orders_loaded(self):
        if not self.orders:
            self.fetch_digicert_data()
        return self.orders

    def get_renewal_settings(self):
        return {"mode": renewal.get_mode(), "base_url": renewal.get_base_url(),
                "default_base_url": digicert_api.DEFAULT_BASE_URL}

    def set_renewal_settings(self, mode, base_url):
        if mode not in renewal.MODES:
            return {"status": "error", "message": "Mode invalide"}
        base_url = (base_url or '').strip().rstrip('/') or digicert_api.DEFAULT_BASE_URL
        host = urllib.parse.urlparse(base_url)
        # The API key is sent to this address, so it can only point at DigiCert itself
        # (production or the demo environment) - never an arbitrary server.
        if host.scheme != 'https' or not (host.hostname or '').endswith('digicert.com'):
            return {"status": "error", "message": "L'URL doit être en https et sur un domaine digicert.com"}
        renewal.set_mode(mode)
        db_set_setting(renewal.SETTING_BASE_URL, base_url)
        return {"status": "success"}

    def get_certificates_overview(self):
        return self._renewal.certificates_overview()

    def preview_renewal(self, hostname, thumbprint):
        return self._renewal.preview(hostname, thumbprint)

    def start_renewal(self, hostname, thumbprint):
        return self._renewal.start(hostname, thumbprint)

    def cancel_renewal(self, job_id):
        return self._renewal.cancel(job_id)

    def get_renewal_jobs(self):
        return self._renewal.list_jobs()

    def get_discovery_summary(self):
        """Cross-references what DigiCert says it issued against what agents
        have actually found installed on real servers. This is the actual
        payoff of the agent layer: certificates renewed in DigiCert but never
        deployed anywhere (real outage risk), and certificates running in
        production that DigiCert doesn't know about (shadow IT / other CA)."""
        known_certs = getattr(self, 'last_certs', [])
        discovered = get_all_discovered_certs()

        known_domains = {c['domain'].lower(): c for c in known_certs if c.get('domain')}
        discovered_by_domain = {}
        for d in discovered:
            key = (d.get('domain') or '').lower()
            if key:
                discovered_by_domain.setdefault(key, []).append(d)

        not_installed = [
            {"domain": cert['domain'], "days_left": cert.get('days_left'), "product": cert.get('product')}
            for domain, cert in known_domains.items() if domain not in discovered_by_domain
        ]

        unknown_to_digicert = [
            entry for domain, entries in discovered_by_domain.items() if domain not in known_domains
            for entry in entries
        ]

        return {
            "not_installed": not_installed,
            "unknown_to_digicert": unknown_to_digicert,
            "total_known": len(known_domains),
            "total_discovered_domains": len(discovered_by_domain)
        }

    # ===== Window controls (frameless window - see __main__) =====
    def minimize_window(self):
        self._window.minimize()

    def close_window(self):
        self._window.destroy()

    def toggle_maximize_window(self):
        if getattr(self, '_is_maximized', False):
            self._window.restore()
            self._is_maximized = False
        else:
            self._window.maximize()
            self._is_maximized = True


class AgentCheckinHandler(BaseHTTPRequestHandler):
    """Receives scan results from agents running on remote servers. Read-only
    from the agent's perspective: this endpoint only ever stores data, it never
    returns commands or instructs an agent to do anything, so a compromised
    controller can't be used to push actions onto the fleet."""

    def log_message(self, format, *args):
        pass  # BaseHTTPRequestHandler logs every request to stderr by default; stay quiet

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == '/agent/ping':
            self._send_json(200, {"status": "ok"})
        else:
            self._send_json(404, {"status": "error", "message": "Not found"})

    def _read_authenticated_json(self):
        """Checks the bearer token and parses the JSON body. Returns the payload
        dict, or None after having already sent the error response."""
        auth_header = self.headers.get('Authorization', '')
        presented_token = auth_header[7:] if auth_header.startswith('Bearer ') else ''
        expected_token = get_agent_token()
        if not presented_token or not hmac.compare_digest(presented_token, expected_token):
            self._send_json(401, {"status": "error", "message": "Unauthorized"})
            return None

        try:
            length = int(self.headers.get('Content-Length', 0))
        except ValueError:
            length = 0
        if length <= 0 or length > AGENT_MAX_BODY_BYTES:
            self._send_json(400, {"status": "error", "message": "Invalid content length"})
            return None

        try:
            body = self.rfile.read(length)
            payload = json.loads(body.decode('utf-8'))
        except Exception:
            self._send_json(400, {"status": "error", "message": "Invalid JSON"})
            return None
        if not isinstance(payload, dict):
            self._send_json(400, {"status": "error", "message": "Invalid JSON"})
            return None
        return payload

    def do_POST(self):
        if self.path == '/agent/checkin':
            self._handle_checkin()
        elif self.path == '/agent/poll':
            self._handle_poll()
        elif self.path == '/agent/command_result':
            self._handle_command_result()
        elif self.path == '/agent/verify':
            self._handle_verify()
        else:
            self._send_json(404, {"status": "error", "message": "Not found"})

    @staticmethod
    def _cert_management_flag(payload):
        """True/False as reported by the agent (its administrator's opt-in); None if it did not say."""
        value = payload.get('cert_management')
        return value if isinstance(value, bool) else None

    def _handle_verify(self):
        """Lets the agent installer check the token and see whether this server is already
        registered, without creating or changing anything."""
        payload = self._read_authenticated_json()
        if payload is None:
            return
        hostname = str(payload.get('hostname', ''))[:255].strip()
        self._send_json(200, {"status": "success", "registered": bool(hostname) and agent_is_registered(hostname)})

    def _handle_poll(self):
        """Lightweight heartbeat: the agent asks 'anything for me?' and gets its
        current settings plus any queued commands. This is the ONLY way a command
        reaches an agent - the agent always initiates, nothing is pushed."""
        payload = self._read_authenticated_json()
        if payload is None:
            return
        hostname = str(payload.get('hostname', ''))[:255].strip()
        if not hostname:
            self._send_json(400, {"status": "error", "message": "Missing hostname"})
            return
        try:
            touch_agent(hostname, str(payload.get('agent_version', ''))[:50].strip(),
                        self.client_address[0], self._cert_management_flag(payload))
            commands = claim_pending_commands(hostname, ALLOWED_AGENT_COMMANDS)
            self._send_json(200, {"status": "success", "settings": get_agent_settings(hostname), "commands": commands})
        except Exception as e:
            self._send_json(500, {"status": "error", "message": str(e)})

    def _handle_command_result(self):
        payload = self._read_authenticated_json()
        if payload is None:
            return
        hostname = str(payload.get('hostname', ''))[:255].strip()
        try:
            cmd_id = int(payload.get('command_id'))
        except (TypeError, ValueError):
            self._send_json(400, {"status": "error", "message": "Invalid command_id"})
            return
        status = str(payload.get('status', ''))
        message = str(payload.get('message', ''))
        data = payload.get('data') if isinstance(payload.get('data'), dict) else {}
        try:
            # Only the first report for a delivered command counts: replays and
            # reports for someone else's command change nothing and trigger nothing.
            if finish_command(hostname, cmd_id, status, message) and _renewal_manager is not None:
                _renewal_manager.on_command_result(hostname, cmd_id, 'done' if status == 'done' else 'failed',
                                                   message[:500], data)
            self._send_json(200, {"status": "success"})
        except Exception as e:
            self._send_json(500, {"status": "error", "message": str(e)})

    def _handle_checkin(self):
        payload = self._read_authenticated_json()
        if payload is None:
            return

        hostname = str(payload.get('hostname', ''))[:255].strip()
        os_name = str(payload.get('os', ''))[:100].strip()
        agent_version = str(payload.get('agent_version', ''))[:50].strip()
        raw_certs = payload.get('certs', [])

        if not hostname:
            self._send_json(400, {"status": "error", "message": "Missing hostname"})
            return
        if not isinstance(raw_certs, list) or len(raw_certs) > 5000:
            self._send_json(400, {"status": "error", "message": "Invalid certs payload"})
            return

        certs = []
        for c in raw_certs[:5000]:
            if not isinstance(c, dict):
                continue
            certs.append({
                "domain": str(c.get('domain', ''))[:255],
                "issuer": str(c.get('issuer', ''))[:255],
                "valid_till": str(c.get('valid_till', ''))[:20],
                "thumbprint": str(c.get('thumbprint', ''))[:100],
                "install_path": str(c.get('install_path', ''))[:500]
            })

        try:
            upsert_agent(hostname, os_name, agent_version, len(certs),
                         self.client_address[0], self._cert_management_flag(payload))
            replace_discovered_certs(hostname, certs)
        except Exception as e:
            self._send_json(500, {"status": "error", "message": str(e)})
            return

        self._send_json(200, {"status": "success", "certs_received": len(certs),
                              "settings": get_agent_settings(hostname)})


_agent_server = None
_renewal_manager = None  # set by Api.__init__; used by the check-in handler to hand agent results to the renewal workflow

def start_agent_listener(port):
    """Starts the check-in listener in a background thread. Binds to all
    interfaces (0.0.0.0) since agents call in from other hosts on the network
    -- this opens a real port, so it must be firewalled to the server subnet
    in production, not left open to the whole network."""
    global _agent_server
    try:
        _agent_server = ThreadingHTTPServer(('0.0.0.0', port), AgentCheckinHandler)
        thread = threading.Thread(target=_agent_server.serve_forever, daemon=True)
        thread.start()
        print(f"Agent listener started on 0.0.0.0:{port}")
    except Exception as e:
        print(f"Failed to start agent listener on port {port}: {e}")


def background_task(api_instance):
    # Fonction qui tourne en arrière plan pour vérifier périodiquement
    while True:
        # Check happens every 4 hours
        time.sleep(14400)
        try:
            api_instance.fetch_digicert_data()
            api_instance.get_dashboard_data() # This triggers the native notification if required
        except Exception:
            pass

if __name__ == '__main__':
    api = Api()

    # Thread pour tâches d'arrière plan (notifs auto)
    t = threading.Thread(target=background_task, args=(api,), daemon=True)
    t.start()

    # Advances renewal jobs (order status polling, hand-off to agents). Does nothing
    # unless a job exists, and jobs only exist after an explicit, confirmed "Renouveler".
    threading.Thread(target=api._renewal.run_forever, daemon=True).start()

    # Écouteur pour les check-ins des agents (Option A: agents -> app centrale).
    # Génère le token au premier lancement si besoin.
    get_agent_token()
    start_agent_listener(api.config.get('agent_listener_port', DEFAULT_AGENT_PORT))

    # NOTE: la fenetre reste standard (pas de frameless). Si un jour on la reessaie, ne
    # JAMAIS exposer l'objet fenetre dans un attribut public de l'Api (voir _window plus bas).

    # Création de la fenêtre
    window = webview.create_window(
        'CertHelm',
        'ui/index.html',
        js_api=api,
        width=1100,
        height=700,
        min_size=(900, 600),
        background_color='#0f172a'
    )
    # Private on purpose: pywebview walks every public attribute of js_api to expose it to
    # JavaScript, and recurses forever into the native window object (RecursionError, the UI
    # never becomes ready and the splash screen stays frozen).
    api._window = window
    webview.start()
