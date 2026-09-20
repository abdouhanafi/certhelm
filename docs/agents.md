# Agents

An agent scans the certificates installed on one server and reports them to CertHelm. It never listens on a port: it calls the
controller.

## Before deploying

1. In CertHelm open **Paramètres → Agents & Découverte** and note the **controller URL** and the **token**
   (the token is shown in clear only when generated or regenerated — copy it right away).
2. The machine running CertHelm must be reachable from your servers on the listener port (default `8765`). That usually needs a
   firewall rule — restrict it to your server subnets.
3. Read [security.md](security.md).

## Windows

### With the installer (recommended)

Run `CertHelmAgent_Setup.exe` (it must sit in the same folder as `CertHelmAgent.exe`; it asks for administrator rights):

1. Paste the controller URL and token, click **Tester la connexion**.
2. Choose how to run the agent:
   * **Background task** *(servers)* — runs continuously (`--daemon`), starts with Windows under the SYSTEM account and restarts
     itself if it crashes. Required for remote control and renewal. Log: `agent.log` next to the agent.
   * **Tray icon** *(workstations)* — runs in the user session with a status dot (green = last check-in OK, red = failed).
   * **Nothing** — only writes `agent_config.json`.
3. Optionally tick **Allow CertHelm to renew this server's certificates** (off by default — see [renewal.md](renewal.md)).

> The agent runs as SYSTEM: install it in a folder only administrators can write to (for example
> `C:\Program Files\CertHelmAgent`), never on a desktop or user folder, otherwise any user could replace the executable and
> gain SYSTEM rights.

### Manually

Copy `agent_config.example.json` to `agent_config.json` next to the executable and fill it in, then:

```powershell
CertHelmAgent.exe --dry-run    # scan and print, send nothing
CertHelmAgent.exe              # one scan + check-in, then exit
CertHelmAgent.exe --daemon     # continuous, headless (log in agent.log)
CertHelmAgent.exe --tray       # continuous, tray icon
```

## Linux / RedHat

`agent/certhelm_agent.py` needs Python 3 and the `openssl` command — no `pip install`.

```bash
sudo mkdir -p /opt/certhelm-agent
sudo cp certhelm_agent.py agent_config.json /opt/certhelm-agent/
sudo chmod 600 /opt/certhelm-agent/agent_config.json
python3 /opt/certhelm-agent/certhelm_agent.py --dry-run
```

Run it continuously with systemd (`/etc/systemd/system/certhelm-agent.service`):

```ini
[Unit]
Description=CertHelm agent
After=network-online.target

[Service]
ExecStart=/usr/bin/python3 /opt/certhelm-agent/certhelm_agent.py --daemon
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now certhelm-agent
```

A plain cron job (`0 6 * * * python3 certhelm_agent.py`) also works for scanning, but that agent cannot be controlled remotely.

## `agent_config.json`

| Key | Required | Meaning |
|---|---|---|
| `controller_url` | yes | e.g. `http://controller-host:8765` (no path). |
| `token` | yes | Shared token from CertHelm settings. |
| `hostname` | no | Name shown in CertHelm (default: the machine name). |
| `interval_hours` | no | Initial scan frequency; afterwards CertHelm controls it. |
| `allow_cert_management` | no | Must be literally `true` to let this server take part in automatic renewal. Default `false`. |
| `test_command` / `reload_command` | no | Linux: argv **lists** to test the web-server config and reload it, e.g. `["nginx","-t"]`. Auto-detected for nginx/httpd/apache2 under systemd when omitted. |

## Controlling an agent from CertHelm

In **Agents & Découverte**, each agent (v2.0+) has:

* **Scanner maintenant** — queued; the agent picks it up within ~30 s and the result is shown as a notification.
* **Réglages** — scan frequency (1 h – 7 days) and an *Agent actif* switch. A disabled agent stops scanning and reporting until
  re-enabled. The panel also lists the last commands and their results.

Only agents that run continuously (background task, tray, `--daemon`) can be controlled. An agent is *online* if it was heard from in the last 3 minutes.

## Troubleshooting

| Symptom | Check |
|---|---|
| Agent not listed in CertHelm | It never ran: launch it once or use the *background task* mode. Look at `agent.log`. |
| "Impossible de joindre le contrôleur" | URL/port, firewall, CertHelm running. Use the installer's *Tester la connexion*. |
| HTTP 401 in `agent.log` | Wrong or regenerated token. |
| Buttons greyed out | Agent older than v2.0. |
| *Scan now* ends with "no answer from the agent" | The agent is not running continuously (one-shot mode, stopped service). Use the background task, tray or `--daemon`. |
| Suggested controller URL looks like `169.254.x.x` | The app picked a link-local adapter address; use the machine's real IP. |
