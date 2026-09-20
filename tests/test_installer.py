"""Agent installer core (agent/installer_windows.py) against a real CertHelm listener on loopback.
Windows commands (schtasks, icacls, PowerShell) are replaced by a recorder: nothing is installed,
no task is created, no folder outside a temporary one is touched. The GUI is not opened."""
import os, sys, json, tempfile, threading, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.chdir(tempfile.mkdtemp())
sys.path[:0] = [os.path.join(ROOT, "certhelm"), os.path.join(ROOT, "agent")]
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _stubs  # noqa: F401 - fakes for webview/keyring/plyer
import main as controller
import installer_windows as inst

TOKEN = "installer-test-token"
controller.get_agent_token = lambda: TOKEN
PORT = 18772
controller.start_agent_listener(PORT)
URL = f"http://127.0.0.1:{PORT}"

fails = []
def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (" " + str(extra)[:220] if extra else ""))
    if not cond: fails.append(name)

def raises(fn, *a, **k):
    try: fn(*a, **k)
    except inst.InstallError as e: return str(e)
    return None

# ---------- the module must load without a display ----------
check("installer imports without tkinter being loaded", "tkinter" not in sys.modules)

# ---------- address handling ----------
check("adds http:// when missing", inst.normalize_url("10.0.0.5:8765") == "http://10.0.0.5:8765")
check("strips a trailing slash", inst.normalize_url("http://10.0.0.5:8765/") == "http://10.0.0.5:8765")
check("accepts the full check-in URL pasted from a doc", inst.normalize_url("http://h:8765/agent/checkin") == "http://h:8765")
check("empty address refused", raises(inst.normalize_url, "  ") is not None)
check("non-http scheme refused", raises(inst.normalize_url, "ftp://h:1") is not None)

# ---------- talking to CertHelm ----------
r = inst.verify_controller(URL, TOKEN, "SRV-INSTALL")
check("good address + token accepted, not registered yet", r == {"registered": False, "token_checked": True}, r)
msg = raises(inst.verify_controller, URL, "wrong", "SRV-INSTALL")
check("wrong token gives an explicit message", msg and "refuse ce jeton" in msg, msg)
check("empty token refused before any request", raises(inst.verify_controller, URL, "", "SRV-INSTALL") is not None)
msg = raises(inst.verify_controller, "http://127.0.0.1:1", TOKEN, "SRV-INSTALL", 2)
check("unreachable address says how to fix it", msg and "Impossible de joindre" in msg and "pare-feu" in msg, msg)

class Old(BaseHTTPRequestHandler):  # an older CertHelm: /agent/ping only
    def log_message(self, *a): pass
    def do_GET(self):
        self.send_response(200 if self.path == "/agent/ping" else 404); self.send_header("Content-Length", "0"); self.end_headers()
    def do_POST(self):
        self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()
class Other(Old):  # something else on that port
    def do_GET(self):
        self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers()
for handler, expected in ((Old, "old"), (Other, "other")):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    u = f"http://127.0.0.1:{srv.server_port}"
    if expected == "old":
        r = inst.verify_controller(u, TOKEN, "H")
        check("older CertHelm: reachable but token cannot be verified (said so)", r["token_checked"] is False and r["registered"] is None, r)
    else:
        m = raises(inst.verify_controller, u, TOKEN, "H")
        check("a different service on that port is recognised", m and "pas CertHelm" in m, m)
    srv.shutdown()

# ---------- install (Windows commands recorded, not run) ----------
ran = []
class Done:  # what subprocess.run returns
    returncode = 0; stdout = ""; stderr = ""
inst._run = lambda cmd, check=True: (ran.append(cmd), Done())[1]
inst.time.sleep = lambda s: None

work = tempfile.mkdtemp()
fake_agent = os.path.join(work, "CertHelmAgent.exe")
open(fake_agent, "wb").write(b"MZ-fake-agent")
inst.find_agent_source = lambda: fake_agent

target = os.path.join(work, "Program Files", "CertHelmAgent")
lines = []
installer = inst.Installer(lines.append)

inst.is_admin = lambda: False
msg = raises(installer.install, URL, TOKEN, "SRV-INSTALL", "schedule", False, target, False)
check("background task needs administrator rights, refused up front", msg and "administrateur" in msg, msg)
check("...and nothing was created", not os.path.exists(target) and ran == [])

inst.is_admin = lambda: True
msg = raises(installer.install, URL, "wrong-token", "SRV-INSTALL", "schedule", False, target, False)
check("wrong token: refused BEFORE anything is installed", msg and not os.path.exists(target) and ran == [], msg)

res = installer.install(URL, TOKEN, "SRV-INSTALL", "schedule", False, target, wait=False)
check("install succeeds", res["ok"], res)
check("agent copied into the chosen folder", open(os.path.join(target, "CertHelmAgent.exe"), "rb").read() == b"MZ-fake-agent")
cfg = json.load(open(os.path.join(target, "agent_config.json")))
check("config holds address, token, hostname", cfg["controller_url"] == URL and cfg["token"] == TOKEN and cfg["hostname"] == "SRV-INSTALL", cfg)
check("renewal NOT allowed unless the box is ticked", "allow_cert_management" not in cfg, cfg)
flat = [" ".join(c) for c in ran]
check("folder locked to SYSTEM and Administrators (well-known SIDs)",
      any("icacls" in c and "S-1-5-18" in c and "S-1-5-32-544" in c and "/inheritance:r" in c for c in flat), flat)
script = [c for c in ran if c[0] == "powershell" and "Register-ScheduledTask" in c[-1]]
check("task registered: daemon mode, SYSTEM, at startup, no time limit, restarts",
      script and all(x in script[0][-1] for x in ("--daemon", "'SYSTEM'", "AtStartup", "ExecutionTimeLimit", "RestartCount")), script[:1])
check("task points at the copied agent, not at the installer's folder", target.replace("'", "''") in script[0][-1])
check("task is started immediately", any(c[:2] == ["schtasks", "/run"] for c in ran))
check("previous agent stopped before overwriting", any(c[:2] == ["schtasks", "/end"] for c in ran) and any(c[0] == "taskkill" for c in ran))

res = installer.install(URL, TOKEN, "SRV-INSTALL", "manual", True, target, wait=False)
cfg = json.load(open(os.path.join(target, "agent_config.json")))
check("ticking the box writes allow_cert_management = true", cfg.get("allow_cert_management") is True, cfg)
check("manual mode only writes the configuration", "Configuration enregistrée" in res["message"])
n = len(ran)
installer.install(URL, TOKEN, "SRV-INSTALL", "manual", False, target, wait=False)
cfg = json.load(open(os.path.join(target, "agent_config.json")))
check("re-installing without the box removes the permission again", "allow_cert_management" not in cfg)

# ---------- registration is confirmed by the console ----------
check("wait_until_registered gives up when the server never appears", installer.wait_until_registered(URL, TOKEN, "GHOST", timeout=0.2, interval=0.05) is False)
urllib.request.urlopen(urllib.request.Request(URL + "/agent/checkin", method="POST", headers={"Authorization": "Bearer " + TOKEN},
                       data=json.dumps({"hostname": "SRV-INSTALL", "os": "Windows", "agent_version": "2.2", "certs": []}).encode())).read()
check("...and returns True once the agent has checked in", installer.wait_until_registered(URL, TOKEN, "SRV-INSTALL", timeout=2, interval=0.05) is True)
res = installer.install(URL, TOKEN, "SRV-INSTALL", "schedule", True, target)
check("full install reports the server as registered and renewal as allowed",
      res["registered"] is True and "enregistré dans CertHelm et actif" in res["message"] and "AUTORISÉ" in res["message"], res)
inst.REGISTRATION_WAIT_SECONDS = 0
res = installer.install(URL, TOKEN, "NEVER-SEEN", "schedule", False, target)
check("if the server does not show up, the admin is told where to look", res["registered"] is False and "agent.log" in res["message"], res)

# ---------- failures are readable ----------
def deny(*a, **k): raise PermissionError(13, "denied", target)
original = installer.copy_agent
installer.copy_agent = deny
msg = raises(installer.install, URL, TOKEN, "SRV-INSTALL", "manual", False, target, False)
check("access denied becomes an instruction, not a traceback", msg and "administrateur" in msg, msg)
installer.copy_agent = original
inst.find_agent_source = lambda: None
msg = raises(installer.install, URL, TOKEN, "SRV-INSTALL", "manual", False, target, False)
check("missing bundled agent is reported", msg and "introuvable" in msg, msg)
inst.find_agent_source = lambda: fake_agent

# ---------- uninstall ----------
ran.clear()
text = installer.uninstall(target)
flat = [" ".join(c) for c in ran]
check("uninstall stops and deletes the task and kills the agent",
      any("/end" in c for c in flat) and any("/delete" in c for c in flat) and any(c.startswith("taskkill") for c in flat), flat)
check("uninstall keeps the folder (log, config) and says so", os.path.exists(target) and "conservé" in text)
inst.is_admin = lambda: False
check("uninstall needs administrator rights", raises(installer.uninstall, target) is not None)
inst.is_admin = lambda: True

# ---------- command line ----------
a = inst.parse_args(["--silent", "--controller-url", URL, "--token", TOKEN, "--mode", "manual", "--allow-renewal",
                     "--hostname", "CLI-HOST", "--install-dir", target])
check("arguments parsed", a.silent and a.mode == "manual" and a.allow_renewal and a.hostname == "CLI-HOST")
check("silent without a token fails cleanly (exit 2) and logs why",
      inst.run_silent(inst.parse_args(["--silent", "--install-dir", target])) == 2
      and "requis" in open(os.path.join(target, "install.log"), encoding="utf-8").read())
check("silent install succeeds (exit 0)", inst.run_silent(a) == 0)
check("silent install wrote the configuration", json.load(open(os.path.join(target, "agent_config.json")))["hostname"] == "CLI-HOST")
bad = inst.parse_args(["--silent", "--controller-url", URL, "--token", "wrong", "--mode", "manual", "--install-dir", target])
check("silent install with a wrong token fails (exit 1)", inst.run_silent(bad) == 1)
check("failure is written to install.log", "ÉCHEC" in open(os.path.join(target, "install.log"), encoding="utf-8").read())

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
