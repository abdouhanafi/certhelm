# Security model

CertHelm can read certificate inventories and, if you enable it, replace certificates on servers. Treat the controller and the
agent token like administrative credentials.

## Trust boundaries

| Asset | Where it lives |
|---|---|
| DigiCert API key | OS credential store (`keyring`; Windows Credential Manager). Never in `config.json` or the database. |
| SMTP password | Same. |
| Agent token | Same on the controller; plain text in each agent's `agent_config.json`. The Windows installer restricts that folder to Administrators and SYSTEM; on Linux use `chmod 600`. |
| Private keys of renewed certificates | Generated and kept on the server. Never sent to, or created by, the controller. |

## Agent ↔ controller channel

* The agent opens no port. Every connection is agent → controller.
* Authentication is a single **shared bearer token** compared in constant time.
* Transport is **plain HTTP**. The token and the data are readable and modifiable by anyone who can intercept the traffic.
  Use a trusted network segment, restrict the listener port to your server subnets, or terminate TLS in front of the listener
  (reverse proxy) and use an `https://` controller URL.
* Because the token is shared, anyone holding it can impersonate any hostname. Regenerate it (Settings) if a server is
  compromised or decommissioned; agents must then be reconfigured.

## What a controller can make an agent do

Commands are an allow-list on both sides:

* `scan_now` — always allowed.
* `generate_csr`, `install_cert` — only if that server's own `agent_config.json` contains `"allow_cert_management": true` (the
  installer's *Autoriser CertHelm à renouveler* box). The agent reports this setting so the console can refuse up front.

Anything else is refused. Parameters are treated as untrusted: domain names and job ids are re-validated (no shell
metacharacters, no line breaks), the target certificate is found by the agent from its own scan, file paths and reload/test
commands come only from the agent's local config, and no command is ever run through a shell.

Even a fully compromised controller therefore cannot: run arbitrary commands, write to arbitrary files, read private keys, or
install a certificate that does not match a key the agent generated for that job.

## Renewal-specific protections

See [renewal.md](renewal.md#safety-guarantees): atomic single-order claim, preflight before ordering, key/certificate matching,
opt-in per server, rollback, restricted DigiCert URL.

## Hardening checklist

- [ ] Install the Windows agent with `CertHelmAgent_Setup.exe`: it uses `C:\Program Files\CertHelmAgent` and restricts it to Administrators and SYSTEM, because the agent runs as SYSTEM.
- [ ] Firewall the listener port to the server subnets only.
- [ ] Put a TLS reverse proxy in front of the listener, or keep the channel on an isolated network.
- [ ] `chmod 600` the Linux `agent_config.json` and keep `/etc/ssl/private`-style permissions on key files.
- [ ] Enable `allow_cert_management` only on servers where you have tested the flow.
- [ ] Run a first renewal against the DigiCert demo environment (Settings → Renouvellement automatique) before pointing at production; switch renewal off in Settings when it is not needed.
- [ ] Never commit `agent_config.json`, `config.json`, `workflow.db`, keys or certificates (already git-ignored).

## Known limitations

* No TLS on the agent channel; single shared token (no per-agent identity).
* Renewal worker lives inside the desktop app: if the app is closed, in-flight renewals pause.
* The DigiCert integration has not been validated against the live service.

## Reporting a vulnerability

See [../SECURITY.md](../SECURITY.md).
