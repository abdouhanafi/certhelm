"""Alert rules (alerts.py) and how the controller assembles them for the bell on the dashboard.
Nothing here touches the network, a certificate store or the real credential store."""
import os, sys, tempfile, datetime, types

SRC = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "certhelm"))
os.chdir(tempfile.mkdtemp())
sys.path.insert(0, SRC)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _stubs  # noqa: F401 - fakes for webview/keyring/plyer
import alerts as A
import main as controller
import database as db

fails = []
def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (" " + str(extra)[:200] if extra else ""))
    if not cond: fails.append(name)

def types_of(alerts): return [a["type"] for a in alerts]

# ---------- certificate / domain / organisation expiry ----------
check("cert 3 days left: critical", A.certificate_alert("a.example.com", 3)["type"] == "critical")
check("cert 7 days left: still critical", A.certificate_alert("a.example.com", 7)["type"] == "critical")
check("cert 8 days left: warning", A.certificate_alert("a.example.com", 8)["type"] == "warning")
expired = A.certificate_alert("a.example.com", -5)
check("expired cert: critical and says how long ago", expired["type"] == "critical" and "depuis 5 jour(s)" in expired["message"], expired["message"])
check("expiry today is worded as today", "aujourd'hui" in A.expiry_text(0))
check("window keeps 30 days past and 30 days ahead",
      A.in_expiry_window(-30) and A.in_expiry_window(30) and not A.in_expiry_window(-31) and not A.in_expiry_window(31))
check("cert alert points at the certificate", A.certificate_alert("a.example.com", 3)["target"] == {"kind": "cert", "value": "a.example.com"})
check("domain alert wording", "Validation expire dans 4" in A.domain_alert("d.example.com", 4)["message"])
check("org alert targets the org", A.organization_alert("Acme", 2)["target"]["kind"] == "org")

# ---------- connection ----------
no_key = A.connection_alerts(False, "Not Connected", True, 8765)
check("no API key: critical, leads to settings", len(no_key) == 1 and no_key[0]["type"] == "critical" and no_key[0]["target"]["kind"] == "settings")
bad = A.connection_alerts(True, "Error: HTTP Error 401: Unauthorized", True, 8765)
check("API error: critical with the reason", len(bad) == 1 and "401" in bad[0]["message"], bad)
check("healthy connection: nothing", A.connection_alerts(True, "Connected", True, 8765) == [])
lst = A.connection_alerts(True, "Connected", False, 8765)
check("listener down: critical, names the port", len(lst) == 1 and "8765" in lst[0]["message"])

# ---------- agents ----------
def agent(host, **kw):
    base = {"hostname": host, "enabled": True, "supports_commands": True, "seconds_since_seen": 20, "hours_since_checkin": 0.01}
    base.update(kw); return base
check("live agent: no alert", A.agent_alerts([agent("A")]) == [])
w = A.agent_alerts([agent("A", seconds_since_seen=700)])
check("agent silent 12 min: warning", len(w) == 1 and w[0]["type"] == "warning" and "12 min" in w[0]["message"], w)
c = A.agent_alerts([agent("A", seconds_since_seen=90000)])
check("agent silent > 24h: critical", c[0]["type"] == "critical" and "1 j" in c[0]["message"], c)
check("disabled agent is not reported offline", A.agent_alerts([agent("A", enabled=False, seconds_since_seen=90000)]) == [])
check("agent alert leads to that agent", w[0]["target"] == {"kind": "agent", "value": "A"})
never = A.agent_alerts([agent("A", seconds_since_seen=None, hours_since_checkin=None)])
check("registered but never heard: warning", len(never) == 1 and never[0]["type"] == "warning")
old = dict(supports_commands=False, seconds_since_seen=None)
check("legacy agent 10h ago: fine (it only checks in per scan)", A.agent_alerts([agent("L", hours_since_checkin=10, **old)]) == [])
check("legacy agent 60h ago: warning", A.agent_alerts([agent("L", hours_since_checkin=60, **old)])[0]["type"] == "warning")
check("legacy agent 200h ago: critical", A.agent_alerts([agent("L", hours_since_checkin=200, **old)])[0]["type"] == "critical")

# ---------- certificates found on servers ----------
today = datetime.date.today()
def iso(days): return (today + datetime.timedelta(days=days)).isoformat()
def days_of(text):
    try: return (datetime.date.fromisoformat(text[:10]) - today).days
    except Exception: return None
found = [
    {"hostname": "S1", "domain": "web.example.com", "valid_till": iso(3), "install_path": "Cert:\\LocalMachine\\My"},
    {"hostname": "S1", "domain": "ok.example.com", "valid_till": iso(200), "install_path": "x"},
    {"hostname": "S1", "domain": "gone.example.com", "valid_till": iso(-10), "install_path": "x"},
    {"hostname": "S1", "domain": "ancient.example.com", "valid_till": iso(-400), "install_path": "x"},
    {"hostname": "S2", "domain": "muted.example.com", "valid_till": iso(2), "install_path": "x"},
]
res = A.server_certificate_alerts(found, days_of, [], disabled_hosts={"S2"})
names = sorted(a["title"] for a in res)
check("server certs: expiring and just-expired reported, healthy/ancient/disabled-host not",
      names == ["Serveur S1: gone.example.com", "Serveur S1: web.example.com"], names)
check("server cert 3 days: critical, expired: critical", set(types_of(res)) == {"critical"})
twin = A.certificate_alert("web.example.com", 3, iso(3))
res2 = A.server_certificate_alerts(found[:1], days_of, [twin])
check("same cert as a DigiCert alert: no duplicate, the server is added to it",
      res2 == [] and twin["servers"] == ["S1"] and "installé sur S1" in twin["message"], twin["message"])
res3 = A.server_certificate_alerts(found[:1], days_of, [A.certificate_alert("web.example.com", 3, iso(90))])
check("same domain but another expiry date stays a separate alert", len(res3) == 1)

# ---------- renewals ----------
now = datetime.datetime.now()
def age(iso_time): return (now - datetime.datetime.fromisoformat(iso_time)).total_seconds() / 86400
def rjob(i, status, days_ago, message=""):
    return {"id": i, "hostname": "S1", "domain": "web.example.com", "status": status, "message": message,
            "updated_at": (now - datetime.timedelta(days=days_ago)).isoformat()}
r = A.renewal_alerts([rjob(1, "uncertain", 30, "Statut incertain"), rjob(2, "failed", 1, "boom"),
                      rjob(3, "failed", 1, "Le certificat a été ÉMIS mais l'installation a échoué"),
                      rjob(4, "failed", 20, "old failure"), rjob(5, "installed", 1), rjob(6, "installed", 10),
                      rjob(7, "ordered", 0), rjob(8, "cancelled", 0)], age)
by = {a["title"].split(":")[0]: a for a in r}
check("uncertain renewal: critical however old", by["Renouvellement n°1"]["type"] == "critical")
check("failed renewal: warning", by["Renouvellement n°2"]["type"] == "warning")
check("failed after the certificate was issued: critical", by["Renouvellement n°3"]["type"] == "critical")
check("old failure, old success, in-flight and cancelled: silent", sorted(by) == ["Renouvellement n°1", "Renouvellement n°2", "Renouvellement n°3", "Renouvellement n°5"], sorted(by))
check("recent success is only informational", by["Renouvellement n°5"]["type"] == "info")

# ---------- discovery + ordering ----------
check("no unknown certificates: no alert", A.discovery_alert(0) == [])
check("unknown certificates: info", A.discovery_alert(3)[0]["type"] == "info")
mixed = [A.certificate_alert("z.example.com", 20), A.discovery_alert(1)[0], A.certificate_alert("y.example.com", 2),
         A.connection_alerts(False, "", True, 1)[0], A.certificate_alert("x.example.com", 6)]
snapshot = [dict(m) for m in mixed]
ordered = A.sort_alerts(mixed)
check("sorted: critical first, system problems before expiries, nearest expiry first, info last",
      [a["title"] for a in ordered] == ["Connexion DigiCert", "Certificat: y.example.com", "Certificat: x.example.com",
                                        "Certificat: z.example.com", "Certificats inconnus de DigiCert"], [a["title"] for a in ordered])
check("sorting does not modify its input", mixed == snapshot)

# ---------- assembled by the controller ----------
api = controller.Api()
api.api_key = "TEST-KEY-NOT-REAL"; api.api_status = "Connected"
db.upsert_agent("SRV1", "Windows (11)", "2.2", 1, "10.0.0.5", True)
db.replace_discovered_certs("SRV1", [
    {"domain": "shop.example.com", "issuer": "DigiCert", "valid_till": iso(3), "thumbprint": "T1", "install_path": "IIS"},
    {"domain": "fine.example.com", "issuer": "DigiCert", "valid_till": iso(300), "thumbprint": "T2", "install_path": "IIS"}])
api._digicert_alerts = [A.certificate_alert("app.example.com", 5, iso(5))]

got = api.get_alerts()
titles = [a["title"] for a in got["alerts"]]
check("get_alerts returns a timestamp", "T" in got["generated_at"])
check("listener not started yet -> reported", "Récepteur des agents" in titles, titles)
controller.start_agent_listener(18770)
titles = [a["title"] for a in api.get_alerts()["alerts"]]
check("listener running -> that alert is gone", "Récepteur des agents" not in titles, titles)
check("DigiCert cert alert present", "Certificat: app.example.com" in titles)
check("certificate found on the server is alerted", "Serveur SRV1: shop.example.com" in titles, titles)
check("healthy certificate is not alerted", not any("fine.example.com" in t for t in titles))
check("a fresh agent is not reported offline", not any(t == "Agent: SRV1" for t in titles))

import sqlite3
c = sqlite3.connect("workflow.db")
c.execute("UPDATE agents SET last_seen=? WHERE hostname='SRV1'", ((datetime.datetime.now() - datetime.timedelta(hours=3)).isoformat(),))
c.commit(); c.close()
offline = [a for a in api.get_alerts()["alerts"] if a["title"] == "Agent: SRV1"]
check("agent silent for 3h shows up as an alert", len(offline) == 1 and offline[0]["type"] == "warning", offline)

api.api_key = ""
check("without API key the bell is NOT empty (0 would be misleading)",
      any(a["title"] == "Connexion DigiCert" and a["type"] == "critical" for a in api.get_alerts()["alerts"]))

cached_before = list(api._digicert_alerts)
api.get_alerts(); api.get_alerts()
check("recomputing alerts never mutates the cached DigiCert alerts", api._digicert_alerts == cached_before)

# ---------- desktop notification ----------
sent = []
controller.notification = types.SimpleNamespace(notify=lambda **kw: sent.append(kw))
crit = [A.certificate_alert("a.example.com", 1), A.certificate_alert("b.example.com", 2)]
api.last_notified_count = -1
api.config["notifications_enabled"] = True
api._notify_desktop(crit)
check("one native notification for new critical alerts", len(sent) == 1 and "2 alerte(s)" in sent[0]["title"], sent)
api._notify_desktop(crit)
check("no repeat while the count is unchanged", len(sent) == 1)
api._notify_desktop(crit + [A.certificate_alert("c.example.com", 3)])
check("notifies again when the count changes", len(sent) == 2)
api._notify_desktop([])
api._notify_desktop(crit)
check("notifies again after everything cleared", len(sent) == 3)
api.config["notifications_enabled"] = False
api._notify_desktop(crit + crit)
check("respects the 'notifications natives' setting", len(sent) == 3)
api.config["notifications_enabled"] = True
api._notify_desktop([A.certificate_alert("w.example.com", 20)])
check("warnings alone do not trigger a native popup", len(sent) == 3)

print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
