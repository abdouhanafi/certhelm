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

`CertHelmAgent_Setup.exe` is the **only file to give to the server's administrator**: it embeds the agent. Run it (it asks for
administrator rights):

1. Enter the CertHelm address and the token, then click **Tester la connexion et le jeton**: it says whether CertHelm answers, whether
   the token is accepted, and whether this server is already registered.
2. Choose how to run the agent:
   * **Background task** *(servers)* — runs continuously (`--daemon`), starts with Windows under the SYSTEM account and restarts
     itself if it crashes. Required for remote control and renewal. Log: `agent.log` next to the agent.
   * **Tray icon** *(workstations)* — runs in the user session with a status dot (green = last check-in OK, red = failed).
   * **Nothing** — only writes `agent_config.json`.
3. Optionally tick **Allow CertHelm to renew this server's certificates** (off by default — see [renewal.md](renewal.md)).
4. Click **Installer**. The installer copies the agent into `C:\Program Files\CertHelmAgent` and restricts that folder to
   Administrators and SYSTEM (the agent runs as SYSTEM and its configuration holds the token), registers the task, starts it, then
   **waits until the server appears in the CertHelm console** and says so. Nothing is installed if the address or token is wrong.

Run the installer again at any time to change the address, the token or the renewal permission; it shows the current state
and has a **Désinstaller** button (stops and removes the task; the folder with the configuration and log is kept).

### Scripted deployment (GPO, remote shell)

```powershell
CertHelmAgent_Setup.exe --silent --controller-url http://10.0.0.5:8765 --token <token> [--hostname NAME] [--mode schedule|tray|manual] [--allow-renewal]
CertHelmAgent_Setup.exe --uninstall
```

The outcome is written to `install.log` in the install folder (exit code `0` = registered, `1` = failed, `2` = missing arguments,
`3` = installed but the server did not appear in the console).

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
* **Détails** — name, system, address, agent version, first contact, last scan, last sign of life, whether the server's
  administrator allowed automatic renewal, the **certificates the agent reported** (with days left), and the last commands with their
  results. From there: scan frequency (1 h – 7 days) and the *Agent actif* switch (a disabled agent stops scanning and reporting until
  re-enabled), and **Retirer de la console** (forgets the server and its certificates; refused while a renewal is in progress; a
  running agent registers again at its next contact, so uninstall it first).

The bell in the top bar raises an alert when an agent that should be running has been silent for 10 minutes (critical after 24 hours),
and when a certificate installed on a server is about to expire or has just expired.

Only agents that run continuously (background task, tray, `--daemon`) can be controlled. An agent is *online* if it was heard from in the last 3 minutes.

## Troubleshooting

| Symptom | Check |
|---|---|
| Agent not listed in CertHelm | It never ran: launch it once or use the *background task* mode. Look at `agent.log`. |
| "Impossible de joindre le contrôleur" | URL/port, firewall, CertHelm running. Use the installer's *Tester la connexion*. |
| HTTP 401 in `agent.log` | Wrong or regenerated token. |
| Buttons greyed out | Agent older than v2.0. |
| *Scan now* ends with "no answer from the agent" | The agent is not running continuously (one-shot mode, stopped service). Use the background task, tray or `--daemon`. |
| Suggested controller URL looks wrong | CertHelm suggests the address of the network card used to reach the network; on a machine with several cards, use the address your servers can reach. |
