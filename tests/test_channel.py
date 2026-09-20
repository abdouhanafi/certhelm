import os, sys, time, tempfile, json, urllib.request, urllib.error

SRC = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "certhelm"))
AGENT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agent"))
os.chdir(tempfile.mkdtemp())            # workflow.db is relative to cwd -> throwaway DB
sys.path[:0] = [SRC, AGENT_DIR]

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _stubs  # noqa: F401 - fakes for webview/keyring/plyer
import main as controller
import certhelm_agent as agent

TOKEN = "test-token-123"
controller.get_agent_token = lambda: TOKEN
PORT = 18765
controller.start_agent_listener(PORT)
URL = f"http://127.0.0.1:{PORT}"

FAKE = [{"domain": "a.example.com", "issuer": "Test", "valid_till": "2027-01-01", "thumbprint": "AA", "install_path": "x"}]
agent.run_single_scan = lambda: ("Windows (test)", FAKE)
agent.POLL_SECONDS = 1

fails = []
def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (" " + str(extra) if extra else ""))
    if not cond: fails.append(name)

api = controller.Api()
runner = agent.AgentRunner(URL, TOKEN, "TESTHOST", 6)

# 1. poll before any check-in: no row created
runner.poll_once()
check("poll does not create agent row", api.get_agents() == [])

# 2. first scan creates the agent
check("scan/check-in ok", runner.do_scan())
ags = api.get_agents()
check("agent registered", len(ags) == 1 and ags[0]["hostname"] == "TESTHOST", ags)
check("agent v2 supports commands", ags[0]["supports_commands"] is True)
check("online right after check-in", ags[0]["online"] is True)

# 3. scan_now command round trip
before = runner.last_scan
res = api.request_agent_scan("TESTHOST")
check("scan request queued", res["status"] == "success", res)
res2 = api.request_agent_scan("TESTHOST")
check("duplicate scan request reuses same command", res2["command_id"] == res["command_id"])
runner.poll_once()
cmds = api.get_agent_commands("TESTHOST")
check("scan command completed", cmds and cmds[0]["status"] == "done", cmds)
check("scan actually ran", runner.last_scan != before)

# 4. unknown command type is refused by agent
cid = controller.queue_command("TESTHOST", "format_disk")
# controller-side allowlist must already filter it
runner.poll_once()
cmd = [c for c in api.get_agent_commands("TESTHOST") if c["id"] == cid][0]
check("non-allowlisted command is failed, never delivered", cmd["status"] == "failed" and "non autoris" in (cmd["result"] or ""), cmd)
# and agent-side refusal
runner.handle_command({"id": cid, "type": "format_disk"})
cmd = [c for c in api.get_agent_commands("TESTHOST") if c["id"] == cid]
# it was still 'pending' (not delivered) so result is ignored server side - that's correct

# 5. settings
bad = api.update_agent_settings("TESTHOST", True, 0)
check("interval 0h rejected", bad["status"] == "error")
bad = api.update_agent_settings("TESTHOST", True, 999)
check("interval 999h rejected", bad["status"] == "error")
check("settings saved", api.update_agent_settings("TESTHOST", True, 12)["status"] == "success")
runner.poll_once()
check("agent applied interval", runner.interval_hours == 12.0, runner.interval_hours)
states = []
runner.on_state = lambda s, m: states.append(s)
api.update_agent_settings("TESTHOST", False, 12)
runner.poll_once()
check("agent disabled", runner.enabled is False and "disabled" in states, states)
check("no scan due while disabled", runner.scan_due() is False)
cid = controller.queue_command("TESTHOST", "scan_now")
runner.poll_once()
cmd = [c for c in api.get_agent_commands("TESTHOST") if c["id"] == cid][0]
check("scan_now on disabled agent reported failed", cmd["status"] == "failed", cmd)
api.update_agent_settings("TESTHOST", True, 12)
runner.poll_once()
check("agent re-enabled", runner.enabled is True)

# 6. auth
def post(path, token, body):
    req = urllib.request.Request(URL + path, data=json.dumps(body).encode(), method="POST")
    if token: req.add_header("Authorization", "Bearer " + token)
    try:
        return urllib.request.urlopen(req).status
    except urllib.error.HTTPError as e:
        return e.code
check("poll wrong token -> 401", post("/agent/poll", "nope", {"hostname": "TESTHOST"}) == 401)
check("poll no token -> 401", post("/agent/poll", None, {"hostname": "TESTHOST"}) == 401)
check("command_result wrong token -> 401", post("/agent/command_result", "nope", {"hostname": "X", "command_id": 1}) == 401)

# 7. one agent cannot close another agent's command
controller.upsert_agent("OTHER", "Linux", "2.0", 0)
cid = controller.queue_command("OTHER", "scan_now")
controller.claim_pending_commands("OTHER", controller.ALLOWED_AGENT_COMMANDS)
post("/agent/command_result", TOKEN, {"hostname": "TESTHOST", "command_id": cid, "status": "done", "message": "spoof"})
cmd = [c for c in api.get_agent_commands("OTHER") if c["id"] == cid][0]
check("command result scoped to its own hostname", cmd["status"] == "delivered", cmd)

# 8. legacy v1 agent cannot get commands
controller.upsert_agent("OLDBOX", "Windows", "1.0", 0)
r = api.request_agent_scan("OLDBOX")
check("v1 agent rejected for commands", r["status"] == "error", r)
check("unknown agent rejected", api.request_agent_scan("NOPE")["status"] == "error")

# 9. stale delivered command times out
import sqlite3, datetime
c = sqlite3.connect("workflow.db")
old = (datetime.datetime.now() - datetime.timedelta(minutes=30)).isoformat()
c.execute("UPDATE agent_commands SET delivered_at=? WHERE id=?", (old, cid)); c.commit(); c.close()
controller.claim_pending_commands("OTHER", controller.ALLOWED_AGENT_COMMANDS)
cmd = [c for c in api.get_agent_commands("OTHER") if c["id"] == cid][0]
check("stale delivered command marked failed", cmd["status"] == "failed", cmd)

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
