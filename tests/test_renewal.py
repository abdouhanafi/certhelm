"""Controller-side renewal workflow test. Talks ONLY to a fake DigiCert on 127.0.0.1.
Keys/certs are generated in memory; nothing touches a certificate store or the network."""
import os, sys, json, tempfile, threading, datetime, urllib.request, urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SRC = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "certhelm"))
os.chdir(tempfile.mkdtemp())
sys.path.insert(0, SRC)

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import sqlite3
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _stubs  # noqa: F401 - fakes for webview/keyring/plyer
import main as controller
import database as db
import renewal, digicert_api as dc

# Guard: if anything ever tried the default (real) DigiCert URL, it would hit a dead local port.
dc.DEFAULT_BASE_URL = "http://127.0.0.1:1/never"

fails = []
def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (" " + str(extra)[:200] if extra else ""))
    if not cond: fails.append(name)

# ---------- test PKI ----------
def make_key(): return rsa.generate_private_key(public_exponent=65537, key_size=2048)
CA_KEY = make_key()
CA_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA (not real)")])
def utcnow(): return datetime.datetime.now(datetime.timezone.utc)
CA_CERT = (x509.CertificateBuilder().subject_name(CA_NAME).issuer_name(CA_NAME).public_key(CA_KEY.public_key())
           .serial_number(x509.random_serial_number()).not_valid_before(utcnow() - datetime.timedelta(days=1))
           .not_valid_after(utcnow() + datetime.timedelta(days=3650))
           .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(CA_KEY, hashes.SHA256()))

def make_csr(key, cn, sans=None):
    b = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
    b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in (sans or [cn])]), False)
    return b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()

def issue(csr_pem, cn=None, days=365):
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    cn = cn or csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(CA_NAME).public_key(csr.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(utcnow() - datetime.timedelta(minutes=5)).not_valid_after(utcnow() + datetime.timedelta(days=days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), False).sign(CA_KEY, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode() + CA_CERT.public_bytes(serialization.Encoding.PEM).decode()

# ---------- fake DigiCert ----------
FAKE = {"posts": [], "gets": [], "order_mode": "ok", "pending_polls": 1, "polls": 0, "csr": None,
        "issue_for_wrong_key": False}
class FakeDigiCert(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def _send(self, code, body, ctype="application/json"):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(raw)))
        self.end_headers(); self.wfile.write(raw)
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        FAKE["posts"].append({"path": self.path, "body": body, "key": self.headers.get("X-DC-DEVKEY")})
        if FAKE["order_mode"] == "refuse":
            return self._send(400, {"errors": [{"code": "invalid_csr", "message": "CSR rejected"}]})
        if FAKE["order_mode"] == "5xx":
            return self._send(503, {"errors": [{"message": "try later"}]})
        FAKE["csr"] = body["certificate"]["csr"]
        self._send(201, {"id": 5551, "requests": [{"id": 1, "status": "pending"}]})
    def do_GET(self):
        FAKE["gets"].append(self.path)
        if self.path.endswith("/order/certificate/5551"):
            FAKE["polls"] += 1
            if FAKE["polls"] <= FAKE["pending_polls"]:
                return self._send(200, {"id": 5551, "status": "pending"})
            return self._send(200, {"id": 5551, "status": "issued", "certificate": {"id": 777}})
        if "/certificate/777/download/format/pem_noroot" in self.path:
            csr = FAKE["csr"]
            if FAKE["issue_for_wrong_key"]:
                csr = make_csr(make_key(), "app.example.com")
            return self._send(200, issue(csr).encode(), "application/x-pem-file")
        self._send(404, {"errors": [{"message": "nope"}]})

srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeDigiCert)
threading.Thread(target=srv.serve_forever, daemon=True).start()
FAKE_URL = f"http://127.0.0.1:{srv.server_port}/services/v2"

# ---------- controller under test ----------
TOKEN = "renewal-test-token"
controller.get_agent_token = lambda: TOKEN
LPORT = 18767
controller.start_agent_listener(LPORT)
LURL = f"http://127.0.0.1:{LPORT}"

api = controller.Api()
api.api_key = "TEST-KEY-NOT-REAL"
api.orders = [{
    "id": 4242, "status": "issued", "product": {"name_id": "ssl_plus"}, "organization": {"id": 99},
    "certificate": {"common_name": "app.example.com", "dns_names": ["app.example.com", "www.example.com"], "valid_till": "2026-10-01"},
}]
renewal.ORDER_POLL_SECONDS = 0
mgr = api._renewal

def post(path, body, token=TOKEN):
    req = urllib.request.Request(LURL + path, data=json.dumps(body).encode(), method="POST")
    req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req) as r: return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e: return e.code, None

def pick(reply, ctype, job_id):
    found = [c for c in reply["commands"] if c["type"] == ctype and c["params"].get("job_id") == job_id]
    assert found, f"no {ctype} for job {job_id} in {[ (c['type'], c['params'].get('job_id')) for c in reply['commands']]}"
    return found[0]

def poll(host): return post("/agent/poll", {"hostname": host, "agent_version": "2.1"})[1]
def report(host, cmd, status, message="", data=None):
    return post("/agent/command_result", {"hostname": host, "command_id": cmd["id"], "status": status, "message": message, "data": data or {}})

def seed(host="HOST1", version="2.1", thumb="A" * 40, domain="app.example.com", live=True):
    controller.upsert_agent(host, "Windows (11)", version, 1)
    if live: controller.touch_agent(host, version)
    db.replace_discovered_certs(host, [{"domain": domain, "issuer": "DigiCert", "valid_till": "2026-10-01",
                                        "thumbprint": thumb, "install_path": "Cert:\\LocalMachine\\My"}])

def job(job_id): return db.get_renewal_job(job_id)

seed()

# 1. default mode, legacy mode, preview (nothing is ever sent by a preview)
check("default mode is live (per-server opt-in + confirmation protect it)", renewal.get_mode() == "live")
db.set_setting(renewal.SETTING_MODE, "dry_run")
check("legacy 'dry_run' database value is treated as OFF, never as live", renewal.get_mode() == "off")
check("the Simulation mode no longer exists", renewal.MODES == ("off", "live"))
check("setting the removed mode is refused", api.set_renewal_settings("dry_run", "")["status"] == "error")
db.set_setting(renewal.SETTING_MODE, "live")
db.set_setting(renewal.SETTING_BASE_URL, FAKE_URL)
pv = api.preview_renewal("HOST1", "A" * 40)
check("preview: describes the order that would be placed",
      pv["status"] == "success" and pv["product"] == "ssl_plus" and pv["original_order_id"] == 4242
      and "www.example.com" in pv["dns_names"] and pv["validity_years"] == 1, pv)
check("preview: sent nothing and created nothing",
      FAKE["posts"] == [] and FAKE["gets"] == [] and db.list_renewal_jobs() == [] and db.get_recent_commands("HOST1") == [])
check("preview: unknown certificate refused", api.preview_renewal("HOST1", "F" * 40)["status"] == "error")
seed("NOTALLOWED", thumb="9" * 39 + "8")
controller.touch_agent("NOTALLOWED", "2.2", "10.0.0.9", False)
refused = api.start_renewal("NOTALLOWED", "9" * 39 + "8")
check("server whose admin did not allow renewal is refused before any command",
      refused["status"] == "error" and "autorisé" in refused["message"] and db.get_recent_commands("NOTALLOWED") == [], refused)
check("preview refuses it too", api.preview_renewal("NOTALLOWED", "9" * 39 + "8")["status"] == "error")
controller.touch_agent("NOTALLOWED", "2.2", "10.0.0.9", True)
check("once the admin allows it, the same renewal can be previewed",
      api.preview_renewal("NOTALLOWED", "9" * 39 + "8")["status"] == "success")

# 2. off
api_mode = api.set_renewal_settings("off", "https://demo.digicert.com/services/v2")
check("set mode off", api_mode["status"] == "success" and renewal.get_mode() == "off")
check("off: renewal refused", api.start_renewal("HOST1", "A" * 40)["status"] == "error")
db.set_setting(renewal.SETTING_BASE_URL, FAKE_URL)  # set_renewal_settings reset it to default; keep fake for later

# 3. base URL restrictions
for bad in ("http://demo.digicert.com/services/v2", "https://evil.example.com/v2", "https://digicert.com.evil.io/x", "http://127.0.0.1:1"):
    check(f"base url rejected: {bad}", api.set_renewal_settings("live", bad)["status"] == "error")
check("mode not changed by rejected url", renewal.get_mode() == "off")
check("demo.digicert.com accepted", api.set_renewal_settings("off", "https://demo.digicert.com/services/v2")["status"] == "success")
check("invalid mode rejected", api.set_renewal_settings("yolo", "")["status"] == "error")
db.set_setting(renewal.SETTING_BASE_URL, FAKE_URL)

# 4. live pre-conditions
renewal.set_mode("live")
seed("OLDAGENT", version="2.0", thumb="B" * 40)
check("live: agent < 2.1 refused", api.start_renewal("OLDAGENT", "B" * 40)["status"] == "error")
seed("HOST2", thumb="C" * 40, domain="unknown.example.org")
check("live: domain absent from DigiCert refused", "DigiCert" in api.start_renewal("HOST2", "C" * 40)["message"])
seed("HOST3", thumb="D" * 40, live=False)
_c = sqlite3.connect("workflow.db"); _c.execute("UPDATE agents SET last_seen=? WHERE hostname='HOST3'", ((datetime.datetime.now() - datetime.timedelta(hours=2)).isoformat(),)); _c.commit(); _c.close()
db_conn_msg = api.start_renewal("HOST3", "D" * 40)
check("live: offline agent refused", db_conn_msg["status"] == "error" and "en ligne" in db_conn_msg["message"], db_conn_msg)
check("live: unknown thumbprint refused", api.start_renewal("HOST1", "F" * 40)["status"] == "error")
check("nothing sent to DigiCert by refusals", FAKE["posts"] == [])

# 5. live happy path
seed()
r = api.start_renewal("HOST1", "A" * 40)
check("live: job awaiting_csr", r["status"] == "success" and job(r["job_id"])["status"] == "awaiting_csr", r)
jid = r["job_id"]
dup = api.start_renewal("HOST1", "A" * 40)
check("live: duplicate blocked while active", dup["status"] == "error" and "déjà en cours" in dup["message"])
reply = poll("HOST1")
cmds = [c for c in reply["commands"] if c["type"] == "generate_csr"]
check("agent receives generate_csr with job data", len(cmds) == 1 and cmds[0]["params"]["job_id"] == jid
      and cmds[0]["params"]["domain"] == "app.example.com" and "www.example.com" in cmds[0]["params"]["dns_names"], cmds)
check("controller sends NO file path to the agent", "install_path" not in json.dumps(cmds[0]["params"]))

AGENT_KEY = make_key()
csr = make_csr(AGENT_KEY, "app.example.com", ["app.example.com", "www.example.com"])
check("report csr accepted by HTTP", report("HOST1", cmds[0], "done", "ok", {"csr": csr})[0] == 200)
check("job csr_ready", job(jid)["status"] == "csr_ready")
check("replayed result is ignored (no state change)", report("HOST1", cmds[0], "done", "ok", {"csr": "garbage"})[0] == 200 and job(jid)["status"] == "csr_ready")

mgr.step()
j = job(jid)
check("order placed once -> ordered", j["status"] == "ordered" and j["digicert_order_id"] == "5551", j["message"])
check("exactly one order POST", len(FAKE["posts"]) == 1)
p = FAKE["posts"][0]
check("order POST goes to the product endpoint with the API key", p["path"].endswith("/order/certificate/ssl_plus") and p["key"] == "TEST-KEY-NOT-REAL")
check("order is a renewal of the original order, 1 year, agent's CSR",
      p["body"]["renewal_of_order_id"] == 4242 and p["body"]["validity_years"] == 1 and p["body"]["certificate"]["csr"].strip() == csr.strip()
      and p["body"]["organization"]["id"] == 99 and p["body"]["certificate"]["common_name"] == "app.example.com")
mgr.step()
check("still ordered while DigiCert says pending", job(jid)["status"] == "ordered" and "pending" in job(jid)["message"], job(jid)["message"])
check("no second order POST while waiting", len(FAKE["posts"]) == 1)
mgr.step()
j = job(jid)
check("issued cert verified -> installing", j["status"] == "installing" and j["new_valid_till"], j["message"])
reply = poll("HOST1")
inst = [c for c in reply["commands"] if c["type"] == "install_cert"]
check("agent receives install_cert with the chain", len(inst) == 1 and inst[0]["params"]["certificate_pem"].count("BEGIN CERTIFICATE") == 2)
check("controller sends no private key material", "PRIVATE KEY" not in json.dumps(inst[0]["params"]))
mgr.step(); mgr.step()
check("no extra POST/commands after installing", len(FAKE["posts"]) == 1 and job(jid)["status"] == "installing")
report("HOST1", inst[0], "done", "Installé dans le magasin (2 binding(s) mis à jour)", {"new_thumbprint": "E" * 40, "new_valid_till": "2027-09-19"})
j = job(jid)
check("job installed", j["status"] == "installed" and j["new_thumbprint"] == "E" * 40, j["message"])
check("chain stored for audit, csr stored", "BEGIN CERTIFICATE" in j["cert_pem"] and "CERTIFICATE REQUEST" in j["csr_pem"])
check("UI job view hides PEM fields", "cert_pem" not in mgr.list_jobs()[0] and "csr_pem" not in mgr.list_jobs()[0])

# 6. concurrent double-order protection
seed(thumb="1" * 40)
r = api.start_renewal("HOST1", "1" * 40); jid2 = r["job_id"]
c2 = pick(poll("HOST1"), "generate_csr", jid2)
report("HOST1", c2, "done", "ok", {"csr": make_csr(make_key(), "app.example.com")})
before = len(FAKE["posts"]); FAKE["polls"] = 99
threads = [threading.Thread(target=mgr.step) for _ in range(8)]
[t.start() for t in threads]; [t.join() for t in threads]
check("8 concurrent workers -> exactly ONE order", len(FAKE["posts"]) - before == 1, len(FAKE["posts"]) - before)
mgr.cancel(jid2)

# 7. DigiCert definitive refusal
FAKE["order_mode"] = "refuse"; FAKE["polls"] = 0
seed(thumb="2" * 40)
jid3 = api.start_renewal("HOST1", "2" * 40)["job_id"]
c3 = pick(poll("HOST1"), "generate_csr", jid3)
report("HOST1", c3, "done", "ok", {"csr": make_csr(make_key(), "app.example.com")})
mgr.step()
j = job(jid3)
check("4xx -> failed, 'no order created'", j["status"] == "failed" and "Aucune commande n'a été créée" in j["message"], j["message"])

# 8. ambiguous failure -> uncertain, blocks a new job
FAKE["order_mode"] = "5xx"
seed(thumb="3" * 40)
jid4 = api.start_renewal("HOST1", "3" * 40)["job_id"]
c4 = pick(poll("HOST1"), "generate_csr", jid4)
report("HOST1", c4, "done", "ok", {"csr": make_csr(make_key(), "app.example.com")})
mgr.step()
check("5xx -> uncertain", job(jid4)["status"] == "uncertain", job(jid4)["message"])
n = len(FAKE["posts"]); mgr.step(); mgr.step()
check("uncertain job is never retried automatically", len(FAKE["posts"]) == n)
blocked = api.start_renewal("HOST1", "3" * 40)
check("uncertain job blocks a new renewal (no double purchase)", blocked["status"] == "error" and "déjà en cours" in blocked["message"])
check("cancel warns to check the DigiCert portal", "portail DigiCert" in (api.cancel_renewal(jid4) and job(jid4)["message"]))
check("after cancel a new renewal is possible", api.start_renewal("HOST1", "3" * 40)["status"] == "success")
FAKE["order_mode"] = "ok"

# 9. wrong-key certificate refused, nothing installed
FAKE["polls"] = 0; FAKE["issue_for_wrong_key"] = True
seed(thumb="4" * 40)
# cancel leftovers for HOST1 so the new job can start
for j in db.list_renewal_jobs():
    if j["status"] not in db.RENEWAL_TERMINAL: mgr.cancel(j["id"])
jid5 = api.start_renewal("HOST1", "4" * 40)["job_id"]
c5 = pick(poll("HOST1"), "generate_csr", jid5)
report("HOST1", c5, "done", "ok", {"csr": make_csr(make_key(), "app.example.com")})
mgr.step(); mgr.step(); mgr.step()
j = job(jid5)
check("cert for another key rejected", j["status"] == "failed" and "ne correspond pas" in j["message"], j["message"])
check("no install_cert queued for rejected cert", not [c for c in poll("HOST1")["commands"] if c["type"] == "install_cert"])
FAKE["issue_for_wrong_key"] = False

# 10. bad CSRs from the agent
seed(thumb="5" * 40)
jid6 = api.start_renewal("HOST1", "5" * 40)["job_id"]
c6 = pick(poll("HOST1"), "generate_csr", jid6)
posts_before = len(FAKE["posts"])
report("HOST1", c6, "done", "ok", {"csr": make_csr(make_key(), "attacker.example.com")})
check("CSR for another domain rejected, no order", job(jid6)["status"] == "failed" and len(FAKE["posts"]) == posts_before, job(jid6)["message"])
seed(thumb="6" * 40)
jid7 = api.start_renewal("HOST1", "6" * 40)["job_id"]
c7 = pick(poll("HOST1"), "generate_csr", jid7)
report("HOST1", c7, "failed", "clé privée introuvable", {})
check("agent-side failure surfaces, no order", job(jid7)["status"] == "failed" and "clé privée introuvable" in job(jid7)["message"] and len(FAKE["posts"]) == posts_before)
seed(thumb="7" * 40)
jid8 = api.start_renewal("HOST1", "7" * 40)["job_id"]
c8 = pick(poll("HOST1"), "generate_csr", jid8)
weak = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "app.example.com")])).sign(
    rsa.generate_private_key(public_exponent=65537, key_size=1024), hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
report("HOST1", c8, "done", "ok", {"csr": weak})
check("1024-bit CSR rejected", job(jid8)["status"] == "failed" and "trop courte" in job(jid8)["message"], job(jid8)["message"])

# 11. install failure is reported loudly
FAKE["polls"] = 0
seed(thumb="8" * 40)
jid9 = api.start_renewal("HOST1", "8" * 40)["job_id"]
c9 = pick(poll("HOST1"), "generate_csr", jid9)
report("HOST1", c9, "done", "ok", {"csr": make_csr(make_key(), "app.example.com")})
mgr.step(); mgr.step(); mgr.step()
inst9 = pick(poll("HOST1"), "install_cert", jid9)
report("HOST1", inst9, "failed", "nginx -t a échoué", {})
j = job(jid9)
check("install failure -> failed with 'ÉMIS' warning + manual hint", j["status"] == "failed" and "ÉMIS" in j["message"] and "manuellement" in j["message"], j["message"])

# 11b. commands of a closed job are withdrawn, never delivered later
seed(thumb="c" * 40)
jidw = api.start_renewal("HOST1", "c" * 40)["job_id"]
mgr.cancel(jidw)
check("cancelled job's queued generate_csr is withdrawn (agent never receives it)",
      not [c for c in poll("HOST1")["commands"] if c["params"].get("job_id") == jidw])
withdrawn = [c for c in db.get_recent_commands("HOST1", 50) if c["status"] == "failed" and "Retirée" in (c["result"] or "")]
check("withdrawn command is recorded as failed/Retirée", len(withdrawn) >= 1)

# 12. spoofing: another host can't close HOST1's job
seed(thumb="9" * 40); seed("HOST9", thumb="9" * 40)
jid10 = api.start_renewal("HOST1", "9" * 40)["job_id"]
c10 = pick(poll("HOST1"), "generate_csr", jid10)
report("HOST9", c10, "done", "ok", {"csr": make_csr(make_key(), "app.example.com")})
check("another host's report is ignored", job(jid10)["status"] == "awaiting_csr")
mgr.cancel(jid10)

# 13. timeouts
seed(thumb="a" * 40)
jid11 = api.start_renewal("HOST1", "a" * 40)["job_id"]
old = (datetime.datetime.now() - datetime.timedelta(minutes=renewal.CSR_TIMEOUT_MIN + 1)).isoformat()
import sqlite3
c = sqlite3.connect("workflow.db"); c.execute("UPDATE renewal_jobs SET updated_at=? WHERE id=?", (old, jid11)); c.commit(); c.close()
mgr.step()
check("awaiting_csr times out -> failed, no order", job(jid11)["status"] == "failed" and "Aucune commande" in job(jid11)["message"])

# 14. mode flipped away from live before ordering -> nothing sent
FAKE["polls"] = 0
seed(thumb="b" * 40)
jid12 = api.start_renewal("HOST1", "b" * 40)["job_id"]
c12 = pick(poll("HOST1"), "generate_csr", jid12)
report("HOST1", c12, "done", "ok", {"csr": make_csr(make_key(), "app.example.com")})
posts_before = len(FAKE["posts"])
renewal.set_mode("off")
mgr.step()
check("switching renewal off stops a queued order", job(jid12)["status"] == "failed" and len(FAKE["posts"]) == posts_before, job(jid12)["message"])
renewal.set_mode("live")

# 15. overview
rows = api.get_certificates_overview()
check("overview lists certs with renew flag/reason", rows and all("can_renew" in r_ and "reason" in r_ for r_ in rows))
r_old = [r_ for r_ in rows if r_["hostname"] == "OLDAGENT"][0]
check("overview: old agent not renewable", not r_old["can_renew"] and "2.1" in r_old["reason"])
r_unk = [r_ for r_ in rows if r_["hostname"] == "HOST2"][0]
check("overview: cert absent from DigiCert not renewable", not r_unk["can_renew"] and "DigiCert" in r_unk["reason"])

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
