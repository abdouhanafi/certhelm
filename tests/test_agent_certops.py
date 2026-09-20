"""Agent-side certificate management test.
 - Windows part: `_run` is replaced by a recorder - certreq / the certificate store are NEVER touched.
 - Linux part: real openssl, but only inside a throwaway temp dir with a fake 'service' (a python one-liner).
Nothing leaves this machine and no real certificate store or system file is modified."""
import os, sys, json, types, tempfile, hashlib, datetime, subprocess, shutil, base64

AGENT_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "agent"))
sys.path.insert(0, AGENT_DIR)
import certhelm_agent as agent

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

fails = []
def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (" " + str(extra)[:220] if extra else ""))
    if not cond: fails.append(name)

def raises(fn, *a, **kw):
    try: fn(*a, **kw)
    except agent.CertOpError as e: return str(e)
    except Exception as e: return "OTHER:" + repr(e)
    return None

WORK = tempfile.mkdtemp(prefix="certhelm-agent-test-")
agent.PENDING_FILE = os.path.join(WORK, "pending_renewals.json")
agent.PENDING_DIR = os.path.join(WORK, "pending")

# ---- in-memory test CA / helpers ----
def utcnow(): return datetime.datetime.now(datetime.timezone.utc)
CA_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
CA_NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA (not real)")])
CA_PEM = (x509.CertificateBuilder().subject_name(CA_NAME).issuer_name(CA_NAME).public_key(CA_KEY.public_key())
          .serial_number(1).not_valid_before(utcnow() - datetime.timedelta(days=1)).not_valid_after(utcnow() + datetime.timedelta(days=999))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), True).sign(CA_KEY, hashes.SHA256())
          .public_bytes(serialization.Encoding.PEM).decode())

def issue_from_csr(csr_pem, cn, days=365, start_offset_days=0, sans=None):
    csr = x509.load_pem_x509_csr(csr_pem.encode())
    now = utcnow() + datetime.timedelta(days=start_offset_days)
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
         .issuer_name(CA_NAME).public_key(csr.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(minutes=5)).not_valid_after(now + datetime.timedelta(days=days))
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in (sans or [cn])]), False))
    return b.sign(CA_KEY, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()

def self_signed_pair(cn):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(utcnow() - datetime.timedelta(days=1))
            .not_valid_after(utcnow() + datetime.timedelta(days=20)).add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), False)
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM).decode(),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(), cert)

def sha1_of(pem):
    return hashlib.sha1(x509.load_pem_x509_certificate(pem.encode()).public_bytes(serialization.Encoding.DER)).hexdigest().upper()

# =====================================================================
# WINDOWS (fake _run)
# =====================================================================
print("--- Windows (fake command runner) ---")
OLD_T = "A1" * 20
agent.platform = types.SimpleNamespace(system=lambda: "Windows", win32_ver=lambda: ("11",), release=lambda: "11")
REAL_SCAN = agent.run_single_scan
agent.run_single_scan = lambda: ("Windows (11)", [{"domain": "app.example.com", "issuer": "X", "valid_till": "2026-10-01",
                                                   "thumbprint": OLD_T, "install_path": "Cert:\\LocalMachine\\My"}])
agent._is_admin = lambda: True

calls = []
state = {"certreq_accept_rc": 0, "rebind_rc": 0, "bindings": 2, "haskey": True, "inf_text": None, "notafter": "2027-09-19"}
def fake_run(cmd, timeout=60):
    calls.append(cmd)
    ok = lambda out="": subprocess.CompletedProcess(cmd, 0, out, "")
    if cmd[0] == "certreq" and "-new" in cmd:
        state["inf_text"] = open(cmd[-2], encoding="ascii").read()
        open(cmd[-1], "w").write("-----BEGIN NEW CERTIFICATE REQUEST-----\nMIIFAKE\n-----END NEW CERTIFICATE REQUEST-----\n")
        return ok()
    if cmd[0] == "certreq" and "-accept" in cmd:
        return subprocess.CompletedProcess(cmd, state["certreq_accept_rc"], "", "no matching request" if state["certreq_accept_rc"] else "")
    if cmd[0] == "powershell":
        script = cmd[-1]
        if "AddSslCertificate" in script:
            return subprocess.CompletedProcess(cmd, state["rebind_rc"], f"{state['bindings']}\n", "boom" if state["rebind_rc"] else "")
        if "Get-WebBinding" in script:
            return ok(f"{state['bindings']}\n")
        if "HasPrivateKey" in script:
            return ok(json.dumps({"hasKey": state["haskey"], "notAfter": state["notafter"]}))
        return ok()
    return subprocess.CompletedProcess(cmd, 127, "", "unexpected")
agent._run = fake_run

# input validation happens before ANY command
for bad in ('a.com"\r\n[Evil]', "a b.com", "a.com&dns=evil.com", "", "-x.com", "a..com", "x" * 300, "$(calc).com"):
    calls.clear()
    err = raises(agent.generate_csr, {"job_id": 1, "domain": bad, "dns_names": [bad], "old_thumbprint": OLD_T})
    check(f"win: hostile domain rejected without running anything: {bad[:20]!r}", err and not calls, err)
calls.clear()
check("win: job_id must be a positive int", raises(agent.generate_csr, {"job_id": "1; calc", "domain": "app.example.com", "old_thumbprint": OLD_T}) and not calls)
check("win: bad thumbprint rejected", raises(agent.generate_csr, {"job_id": 1, "domain": "app.example.com", "old_thumbprint": "zz'; calc; '"}) and not calls)
check("win: unknown thumbprint (cert not on this machine)", "introuvable" in (raises(agent.generate_csr, {"job_id": 1, "domain": "app.example.com", "old_thumbprint": "B2" * 20}) or ""))
agent._is_admin = lambda: False
calls.clear()
check("win: needs admin, runs nothing", "administrateur" in (raises(agent.generate_csr, {"job_id": 1, "domain": "app.example.com", "old_thumbprint": OLD_T}) or "") and not calls)
agent._is_admin = lambda: True

calls.clear()
msg, data = agent.generate_csr({"job_id": 11, "domain": "app.example.com", "dns_names": ["app.example.com", "www.example.com"], "old_thumbprint": OLD_T})
inf = state["inf_text"]
check("win: certreq -new -machine -q with inf+csr paths", [c for c in calls if c[0] == "certreq"][0][:4] == ["certreq", "-new", "-machine", "-q"])
check("win: INF has CN, both SANs, non-exportable machine key, RSA 2048",
      'Subject = "CN=app.example.com"' in inf and "dns=app.example.com&" in inf and "dns=www.example.com" in inf
      and "Exportable = FALSE" in inf and "MachineKeySet = TRUE" in inf and "KeyLength = 2048" in inf, inf)
check("win: returns CSR text, private key not in payload", "CERTIFICATE REQUEST" in data["csr"] and "PRIVATE" not in json.dumps(data))
check("win: reports binding count", "2 binding" in msg)
pend = json.load(open(agent.PENDING_FILE))
check("win: pending state saved for job", pend["11"]["os"] == "windows" and pend["11"]["old_thumbprint"] == OLD_T)

# install
new_leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
csr_x = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "app.example.com")])).sign(new_leaf_key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
leaf = issue_from_csr(csr_x, "app.example.com")
chain = leaf + CA_PEM
NEW_T = sha1_of(leaf)

calls.clear()
check("win: install w/o pending request refused", "Aucune demande" in (raises(agent.install_cert, {"job_id": 99, "certificate_pem": chain}) or "") and not calls)
check("win: garbage after PEM refused", "autre chose" in (raises(agent.install_cert, {"job_id": 11, "certificate_pem": chain + "\nrm -rf /"}) or "") and not calls)
check("win: private key inside 'certificate' refused", raises(agent.install_cert, {"job_id": 11, "certificate_pem": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"}) and not calls)

state["certreq_accept_rc"] = 1
calls.clear()
err = raises(agent.install_cert, {"job_id": 11, "certificate_pem": chain})
check("win: certreq -accept refusal (cert not matching pending key) stops everything",
      err and "aucune demande en attente" in err and not [c for c in calls if c[0] == "powershell"], err)
check("win: pending kept after a failed accept (can retry)", "11" in json.load(open(agent.PENDING_FILE)))
state["certreq_accept_rc"] = 0

state["haskey"] = False
calls.clear()
err = raises(agent.install_cert, {"job_id": 11, "certificate_pem": chain})
check("win: cert without private key -> abort before touching bindings", err and "sans cle privee" in err and not [c for c in calls if c[0] == "powershell" and "AddSslCertificate" in c[-1]], err)
state["haskey"] = True

calls.clear()
msg, data = agent.install_cert({"job_id": 11, "certificate_pem": chain})
accept = [c for c in calls if c[0] == "certreq"][0]
check("win: certreq -accept -machine -q on the leaf only", accept[:4] == ["certreq", "-accept", "-machine", "-q"] and accept[-1].endswith("leaf.cer"))
check("win: new thumbprint = SHA-1 of leaf DER", data["new_thumbprint"] == NEW_T and data["new_valid_till"] == "2027-09-19", data)
ps = [c[-1] for c in calls if c[0] == "powershell"]
check("win: intermediate imported to CA store (once)", sum("CertStoreLocation Cert:\\LocalMachine\\CA" in s for s in ps) == 1)
rebind = [s for s in ps if "AddSslCertificate" in s][0]
check("win: IIS rebind uses old->new thumbprints, My store", f"'{OLD_T}'" in rebind and f"'{NEW_T}'" in rebind and "'My'" in rebind, rebind)
check("win: old certificate not deleted", not any("Remove-Item" in s or "Remove-" in s for s in ps))
check("win: pending cleared after success", "11" not in json.load(open(agent.PENDING_FILE)))
check("win: message says old cert kept", "n'a pas ete supprime" in msg and "2 binding" in msg)

# rebind failure -> rollback
agent.generate_csr({"job_id": 12, "domain": "app.example.com", "dns_names": ["app.example.com"], "old_thumbprint": OLD_T})
state["rebind_rc"] = 1
calls.clear()
err = raises(agent.install_cert, {"job_id": 12, "certificate_pem": chain})
rebinds = [c[-1] for c in calls if c[0] == "powershell" and "AddSslCertificate" in c[-1]]
check("win: rebind failure -> rollback attempted (new->old)", err and len(rebinds) == 2 and f"certificateHash -ieq '{NEW_T}'" in rebinds[1] and f"AddSslCertificate('{OLD_T}'" in rebinds[1], err)
state["rebind_rc"] = 0

# no IIS at all
state["bindings"] = 0
agent.generate_csr({"job_id": 13, "domain": "app.example.com", "dns_names": ["app.example.com"], "old_thumbprint": OLD_T})
msg, _ = agent.install_cert({"job_id": 13, "certificate_pem": chain})
check("win: works with zero IIS bindings", "0 binding" in msg)

# =====================================================================
# LINUX (real openssl, temp dir only, fake service)
# =====================================================================
print("--- Linux (real openssl, temp dir, fake service) ---")
agent._run = lambda cmd, timeout=60: (subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
                                      if cmd[0] != "systemctl" else subprocess.CompletedProcess(cmd, 127, "", "no systemd here"))
agent.platform = types.SimpleNamespace(system=lambda: "Linux", win32_ver=lambda: ("",), release=lambda: "test")
agent.DEFAULT_PROBE_PORTS = []          # don't probe local ports
agent.run_single_scan = REAL_SCAN      # real Linux discovery, pointed at the temp dir only

def setup_site(name, cn="app.example.com"):
    root = os.path.join(WORK, name); ssl_dir = os.path.join(root, "ssl"); os.makedirs(ssl_dir)
    cert_pem, key_pem, cert_obj = self_signed_pair(cn)
    open(os.path.join(ssl_dir, "site.crt"), "w").write(cert_pem)
    open(os.path.join(ssl_dir, "site.key"), "w").write(key_pem)
    marker = os.path.join(root, "service.log")
    cfg = {"test_command": [sys.executable, "-c", f"open(r'{marker}','a').write('test\\n')"],
           "reload_command": [sys.executable, "-c", f"open(r'{marker}','a').write('reload\\n')"]}
    cfg_path = os.path.join(root, "agent_config.json"); json.dump(cfg, open(cfg_path, "w"))
    agent.CONFIG_FILE = cfg_path
    agent.LINUX_SCAN_DIRS = [ssl_dir]
    thumb = hashlib.sha256(cert_obj.public_bytes(serialization.Encoding.DER)).hexdigest().upper()
    return root, ssl_dir, thumb, marker, cfg_path

root, ssl_dir, T, marker, cfg_path = setup_site("site1")
cert_path, key_path = os.path.join(ssl_dir, "site.crt"), os.path.join(ssl_dir, "site.key")
old_cert_bytes, old_key_bytes = open(cert_path, "rb").read(), open(key_path, "rb").read()

params = {"job_id": 21, "domain": "app.example.com", "dns_names": ["app.example.com", "www.example.com"], "old_thumbprint": T}
msg, data = agent.generate_csr(params)
csr = x509.load_pem_x509_csr(data["csr"].encode())
sans = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
check("linux: CSR is valid, RSA 2048, CN + SANs", csr.is_signature_valid and csr.public_key().key_size == 2048 and sorted(sans) == ["app.example.com", "www.example.com"]
      and csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "app.example.com")
pending_key = os.path.join(agent.PENDING_DIR, "21.key")
check("linux: new private key created locally, CSR data carries no key", os.path.isfile(pending_key) and "PRIVATE" not in json.dumps(data))
check("linux: target files auto-detected by the agent (not from controller)", cert_path in msg and key_path in msg, msg)
check("linux: live cert/key untouched by generate_csr", open(cert_path, "rb").read() == old_cert_bytes and open(key_path, "rb").read() == old_key_bytes)

good = issue_from_csr(data["csr"], "app.example.com", sans=["app.example.com", "www.example.com"]) + CA_PEM

# wrong-key cert
other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
other_csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "app.example.com")])).sign(other, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode()
err = raises(agent.install_cert, {"job_id": 21, "certificate_pem": issue_from_csr(other_csr, "app.example.com")})
check("linux: cert for a different key refused, nothing modified", err and "ne correspond pas" in err and open(cert_path, "rb").read() == old_cert_bytes, err)
err = raises(agent.install_cert, {"job_id": 21, "certificate_pem": issue_from_csr(data["csr"], "evil.example.org")})
check("linux: cert for another domain refused", err and "ne mentionne pas" in err and open(key_path, "rb").read() == old_key_bytes, err)
err = raises(agent.install_cert, {"job_id": 21, "certificate_pem": issue_from_csr(data["csr"], "app.example.com", days=1, start_offset_days=-30)})
check("linux: expired cert refused", err and "expire" in err and open(cert_path, "rb").read() == old_cert_bytes, err)

# service test fails -> full rollback
json.dump({"test_command": [sys.executable, "-c", "import sys; sys.exit(3)"], "reload_command": [sys.executable, "-c", f"open(r'{marker}','a').write('reload\\n')"]}, open(cfg_path, "w"))
err = raises(agent.install_cert, {"job_id": 21, "certificate_pem": good})
check("linux: failed config test -> old files restored byte-for-byte",
      err and "test de configuration" in err and open(cert_path, "rb").read() == old_cert_bytes and open(key_path, "rb").read() == old_key_bytes, err)
check("linux: reload NOT called after failed test", not os.path.exists(marker))
check("linux: pending key kept so the job can be retried", os.path.isfile(pending_key))
# reload fails -> rollback
json.dump({"test_command": [sys.executable, "-c", "pass"], "reload_command": [sys.executable, "-c", "import sys; sys.exit(1)"]}, open(cfg_path, "w"))
err = raises(agent.install_cert, {"job_id": 21, "certificate_pem": good})
check("linux: failed reload -> old files restored", err and "rechargement" in err and open(cert_path, "rb").read() == old_cert_bytes and open(key_path, "rb").read() == old_key_bytes, err)

check("linux: failed attempts leave no backup files behind", not [f for f in os.listdir(ssl_dir) if ".bak-" in f], os.listdir(ssl_dir))

# success
json.dump({"test_command": [sys.executable, "-c", f"open(r'{marker}','a').write('test\\n')"],
           "reload_command": [sys.executable, "-c", f"open(r'{marker}','a').write('reload\\n')"]}, open(cfg_path, "w"))
msg, data2 = agent.install_cert({"job_id": 21, "certificate_pem": good})
new_cert = open(cert_path).read()
check("linux: cert file now = new leaf + intermediate (fullchain)", new_cert == "".join(agent._pem_blocks(good)) and new_cert.count("BEGIN CERTIFICATE") == 2)
new_key = open(key_path).read()
check("linux: key file = the key generated for this job", "PRIVATE KEY" in new_key and new_key != old_key_bytes.decode())
baks = [f for f in os.listdir(ssl_dir) if ".bak-" in f]
check("linux: timestamped backups of old cert and key exist", len(baks) == 2 and any(open(os.path.join(ssl_dir, b), "rb").read() == old_cert_bytes for b in baks))
check("linux: config tested then service reloaded, in that order", open(marker).read().split() == ["test", "reload"])
leaf_only = agent._pem_blocks(good)[0]
check("linux: reported thumbprint = SHA-256 of new leaf", data2["new_thumbprint"] == hashlib.sha256(x509.load_pem_x509_certificate(leaf_only.encode()).public_bytes(serialization.Encoding.DER)).hexdigest().upper(), data2)
check("linux: reported expiry present", len(data2["new_valid_till"]) == 10, data2)
check("linux: pending key deleted after success", not os.path.exists(pending_key) and "21" not in json.load(open(agent.PENDING_FILE)))
new_pub = subprocess.run(["openssl", "x509", "-in", cert_path, "-noout", "-pubkey"], capture_output=True, text=True).stdout
new_key_pub = subprocess.run(["openssl", "pkey", "-in", key_path, "-pubout"], capture_output=True, text=True).stdout
check("linux: installed cert and key pair up (openssl)", new_pub.split() == new_key_pub.split())

# preflight failures (must fail BEFORE any order would be placed)
root2, ssl2, T2, marker2, cfg2 = setup_site("site2")
os.remove(os.path.join(ssl2, "site.key"))
check("linux preflight: private key not found -> refused early", "introuvable" in (raises(agent.generate_csr, {"job_id": 31, "domain": "app.example.com", "old_thumbprint": T2}) or ""))
root3, ssl3, T3, marker3, cfg3 = setup_site("site3")
os.remove(cfg3); agent.CONFIG_FILE = cfg3
err = raises(agent.generate_csr, {"job_id": 32, "domain": "app.example.com", "old_thumbprint": T3})
check("linux preflight: no web service detected -> refused early", err and "Aucun service web" in err, err)
check("linux preflight: no key left behind", not os.path.exists(os.path.join(agent.PENDING_DIR, "32.key")))
root4, ssl4, T4, marker4, cfg4 = setup_site("site4")
json.dump({"reload_command": "systemctl reload nginx"}, open(cfg4, "w"))
check("linux preflight: reload_command must be a list (no shell strings)", "liste" in (raises(agent.generate_csr, {"job_id": 33, "domain": "app.example.com", "old_thumbprint": T4}) or ""))
root5, ssl5, T5, marker5, cfg5 = setup_site("site5")
combo = os.path.join(ssl5, "site.crt"); open(combo, "a").write(open(os.path.join(ssl5, "site.key")).read())
check("linux preflight: combined cert+key file refused", "meme fichier" in (raises(agent.generate_csr, {"job_id": 34, "domain": "app.example.com", "old_thumbprint": T5}) or ""))
check("linux: controller can't point the agent at a file - unknown thumbprint refused", "introuvable" in (raises(agent.generate_csr, {"job_id": 35, "domain": "app.example.com", "old_thumbprint": "C3" * 32}) or ""))
check("linux: a path smuggled in params is ignored", "install_path" not in open(agent.__file__).read().split("def generate_csr")[1].split("def install_cert")[0])

# =====================================================================
# Runner gating
# =====================================================================
print("--- runner opt-in ---")
reports = []
r = agent.AgentRunner("http://x", "t", "H", 6, allow_cert_management=False)
r._report = lambda cid, status, message, data=None: reports.append((cid, status, message))
agent.generate_csr = lambda p: (_ for _ in ()).throw(AssertionError("must not run when not allowed"))
r.handle_command({"id": 1, "type": "generate_csr", "params": {"job_id": 1}})
check("runner: cert commands refused unless allow_cert_management", reports and reports[0][1] == "failed" and "allow_cert_management" in reports[0][2], reports)
r.handle_command({"id": 2, "type": "rm_rf", "params": {}})
check("runner: unknown command type refused", reports[-1][1] == "failed" and "non autorisee" in reports[-1][2])
agent.CONFIG_FILE = os.path.join(WORK, "cfg_optin.json")
check("opt-in defaults to False when config absent", agent.cert_management_enabled() is False)
json.dump({"allow_cert_management": "yes"}, open(agent.CONFIG_FILE, "w"))
check("opt-in requires literal true (string 'yes' does not count)", agent.cert_management_enabled() is False)
json.dump({"allow_cert_management": True}, open(agent.CONFIG_FILE, "w"))
check("opt-in true when set", agent.cert_management_enabled() is True)

shutil.rmtree(WORK, ignore_errors=True)
print("\nFAILED:" if fails else "\nALL PASSED", fails if fails else "")
sys.exit(1 if fails else 0)
