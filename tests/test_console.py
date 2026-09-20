"""Console side of the agents: token check used by the installer, what an agent reports about
itself, removing an agent, database upgrade from an older version, and the agent's own
resilience. Fake keyring, temporary database, loopback only."""
import os, sys, json, tempfile, sqlite3, datetime, urllib.request, urllib.error

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.chdir(tempfile.mkdtemp())
sys.path[:0] = [os.path.join(ROOT, "certhelm"), os.path.join(ROOT, "agent")]
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _stubs  # noqa: F401 - fakes for webview/keyring/plyer
import main as controller
import database as db
import certhelm_agent as agent

TOKEN = "console-test-token"
controller.get_agent_token = lambda: TOKEN
PORT = 18771
controller.start_agent_listener(PORT)
URL = f"http://127.0.0.1:{PORT}"

fails = []
def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (" " + str(extra)[:200] if extra else ""))
    if not cond: fails.append(name)

def post(path, body, token=TOKEN):
    req = urllib.request.Request(URL + path, data=json.dumps(body).encode(), method="POST")
    if token is not None: req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req) as r: return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e: return e.code, None

api = controller.Api()

# ---------- /agent/verify (used by the installer) ----------
check("verify: wrong token refused", post("/agent/verify", {"hostname": "SRV"}, "nope")[0] == 401)
check("verify: no token refused", post("/agent/verify", {"hostname": "SRV"}, None)[0] == 401)
code, body = post("/agent/verify", {"hostname": "SRV"})
check("verify: good token, server not registered yet", code == 200 and body["registered"] is False, body)
check("verify: changes nothing (no agent row created)", api.get_agents() == [])

# ---------- what an agent reports about itself ----------
check("agent.send_checkin reports renewal permission",
      agent.send_checkin(URL, TOKEN, "SRV", "Windows (Server 2022)", [], cert_management=True) is not None)
a = api.get_agents()[0]
check("console knows the agent's address (from the connection)", a["last_ip"] == "127.0.0.1", a)
check("console knows renewal is allowed", a["cert_management"] is True)
check("verify now says registered", post("/agent/verify", {"hostname": "SRV"})[1]["registered"] is True)

post("/agent/poll", {"hostname": "SRV", "agent_version": "2.2", "cert_management": False})
check("a poll updates the renewal permission (admin edited the config)", api.get_agents()[0]["cert_management"] is False)

post("/agent/checkin", {"hostname": "OLD", "os": "Windows", "agent_version": "2.0", "certs": []})
old = [x for x in api.get_agents() if x["hostname"] == "OLD"][0]
check("an agent that says nothing has unknown permission (None, not False)", old["cert_management"] is None, old)
post("/agent/checkin", {"hostname": "ODD", "os": "x", "agent_version": "2.2", "certs": [], "cert_management": "yes"})
check("a non-boolean permission is ignored", [x for x in api.get_agents() if x["hostname"] == "ODD"][0]["cert_management"] is None)

# ---------- per-agent certificates ----------
post("/agent/checkin", {"hostname": "SRV", "os": "Windows", "agent_version": "2.2", "cert_management": True,
                        "certs": [{"domain": "a.example.com", "issuer": "DigiCert", "valid_till": "2027-01-01",
                                   "thumbprint": "AA", "install_path": "IIS"},
                                  {"domain": "b.example.com", "issuer": "DigiCert", "valid_till": "2027-02-02",
                                   "thumbprint": "BB", "install_path": "IIS"}]})
post("/agent/checkin", {"hostname": "OLD", "os": "Windows", "agent_version": "2.0",
                        "certs": [{"domain": "z.example.com", "issuer": "X", "valid_till": "2027-03-03", "thumbprint": "ZZ", "install_path": "p"}]})
mine = api.get_agent_certs("SRV")
check("get_agent_certs returns only that server's certificates", sorted(c["domain"] for c in mine) == ["a.example.com", "b.example.com"], mine)

# ---------- removing an agent ----------
check("delete: unknown agent refused", api.delete_agent("NOPE")["status"] == "error")
api.request_agent_scan("SRV")
job_id, _ = db.create_renewal_job("SRV", "a.example.com", "AA", "IIS", "2027-01-01", "awaiting_csr", "wait", "live", ["a.example.com"])
blocked = api.delete_agent("SRV")
check("delete: refused while a renewal is in progress", blocked["status"] == "error" and "renouvellement" in blocked["message"].lower(), blocked)
db.update_renewal_job(job_id, status="cancelled")
ok = api.delete_agent("SRV")
check("delete: accepted once the renewal is over", ok["status"] == "success", ok)
check("delete: agent, certificates and queued commands are gone",
      not any(x["hostname"] == "SRV" for x in api.get_agents()) and api.get_agent_certs("SRV") == [] and db.get_recent_commands("SRV") == [])
check("delete: another agent is untouched", len(api.get_agent_certs("OLD")) == 1)
check("delete: renewal history is kept", db.get_renewal_job(job_id) is not None)
post("/agent/checkin", {"hostname": "SRV", "os": "Windows", "agent_version": "2.2", "certs": []})
check("a still-running agent simply registers again", any(x["hostname"] == "SRV" for x in api.get_agents()))

# ---------- the address suggested to administrators ----------
check("link-local and loopback addresses are never suggested",
      controller.pick_reachable_ip(["169.254.10.20", "127.0.0.1", "192.168.1.20"]) == "192.168.1.20")
check("falls back to loopback when nothing else exists", controller.pick_reachable_ip(["169.254.1.1"]) == "127.0.0.1")
hint = api.get_agent_config()["listener_url_hint"]
check("the hint shown in Settings is never a 169.254 address", "169.254." not in hint, hint)

# ---------- upgrading an old database ----------
current = db.DB_PATH
db.DB_PATH = os.path.join(tempfile.mkdtemp(), "old.db")
conn = sqlite3.connect(db.DB_PATH)
conn.execute("CREATE TABLE agents (hostname TEXT PRIMARY KEY, os TEXT, agent_version TEXT, last_checkin TEXT, cert_count INTEGER DEFAULT 0, first_seen TEXT)")
conn.execute("INSERT INTO agents VALUES ('LEGACY','Windows','1.0','2025-01-01T00:00:00',2,'2025-01-01T00:00:00')")
conn.execute("""CREATE TABLE renewal_jobs (id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT, domain TEXT, old_thumbprint TEXT,
    install_path TEXT, old_valid_till TEXT, status TEXT, message TEXT, mode TEXT, dns_names TEXT, digicert_order_id TEXT,
    digicert_cert_id TEXT, csr_pem TEXT, cert_pem TEXT, payload TEXT, new_thumbprint TEXT, new_valid_till TEXT, created_at TEXT, updated_at TEXT)""")
conn.execute("INSERT INTO renewal_jobs (hostname, domain, status, mode) VALUES ('LEGACY','old-sim.example.com','simulated','dry_run')")
conn.execute("INSERT INTO renewal_jobs (hostname, domain, status, mode) VALUES ('LEGACY','real.example.com','installed','live')")
conn.commit(); conn.close()
db.init_db()
agents = db.get_all_agents()
check("upgrade: old agent kept, new columns exist and are empty",
      len(agents) == 1 and agents[0]["hostname"] == "LEGACY" and agents[0]["last_ip"] is None and agents[0]["cert_management"] is None, agents)
left = [j["domain"] for j in db.list_renewal_jobs()]
check("upgrade: leftover simulation jobs are removed, real ones kept", left == ["real.example.com"], left)
db.init_db()
check("upgrade: running it twice is harmless", len(db.get_all_agents()) == 1 and len(db.list_renewal_jobs()) == 1)
db.DB_PATH = current

# ---------- what pywebview can see of the Api ----------
# pywebview exposes every public attribute of js_api and recurses into objects: a native window
# there made it recurse for ever (RecursionError, splash screen frozen). Only plain data may be public.
api._window = object()
plain = (list, dict, str, int, float, bool, type(None))
offenders = [n for n, v in vars(api).items() if not n.startswith("_") and not isinstance(v, plain)]
check("Api exposes only plain data as public attributes (native window stays private)", offenders == [], offenders)
check("window controls use the private attribute", hasattr(api, "_window") and not hasattr(api, "window"))

# ---------- the agent's loop survives surprises ----------
runner = agent.AgentRunner(URL, TOKEN, "LOOPTEST", 6)
calls = []
def flaky_poll():
    calls.append(1)
    if len(calls) == 1: raise RuntimeError("boom")
    raise KeyboardInterrupt  # only here to leave the endless loop in the test
runner.poll_once = flaky_poll
agent.time.sleep = lambda s: None
try:
    runner.loop()
except KeyboardInterrupt:
    pass
check("agent loop keeps going after an unexpected error", len(calls) == 2, calls)

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
