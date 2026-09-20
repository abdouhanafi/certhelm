# Architecture

CertHelm has two kinds of processes.

| Component | Where it runs | Role |
|---|---|---|
| **Controller** (`certhelm/main.py`) | One Windows workstation/server | Desktop UI (pywebview), DigiCert API client, SQLite database, HTTP listener for agents, renewal worker. |
| **Agent** (`agent/certhelm_agent.py`) | Every server you want to inspect | Scans local certificates, reports them, executes a few allow-listed commands. |

## Controller modules

| File | Responsibility |
|---|---|
| `certhelm/main.py` | `Api` class exposed to the UI, DigiCert data fetching, notifications/SMTP, the agent HTTP listener (`AgentCheckinHandler`). |
| `certhelm/database.py` | SQLite schema (created/migrated at import), all queries. |
| `certhelm/digicert_api.py` | The only code that builds DigiCert order requests. HTTP transport is injectable, so tests use a fake. |
| `certhelm/renewal.py` | The renewal state machine and its safety rules ([renewal.md](renewal.md)). |
| `certhelm/ui/` | Static HTML/CSS/JS front-end (no build step, no framework). |

The UI talks to Python through pywebview's `js_api`: every public method of `Api` is callable from JavaScript. Internals are
prefixed with `_` so they are not exposed.

## Agent ↔ controller protocol

All requests are `POST` JSON with `Authorization: Bearer <token>` (except `GET /agent/ping`). The agent always initiates.

| Endpoint | Purpose |
|---|---|
| `GET /agent/ping` | Reachability test used by the installer. |
| `POST /agent/checkin` | Full scan result: hostname, OS, agent version, list of certificates. Replies with the agent's settings. |
| `POST /agent/poll` | Lightweight heartbeat every 30 s. Replies with settings and any queued commands. |
| `POST /agent/verify` | Used by the installer: checks the token and says whether a hostname is already registered. Creates and changes nothing. |
| `POST /agent/command_result` | Outcome of a command (`done` / `failed`, message, optional small `data` object such as a CSR). |

### Commands

Commands are stored in `agent_commands` and handed out only as the reply to a poll. The controller filters them through
`ALLOWED_AGENT_COMMANDS`, and the agent independently checks `KNOWN_COMMANDS`.

| Command | Meaning |
|---|---|
| `scan_now` | Scan immediately and check in. |
| `generate_csr` | Create a key pair and CSR on the server for a renewal job. Requires the server to opt in. |
| `install_cert` | Install the issued certificate for a renewal job. Requires the server to opt in. |

Lifecycle: `pending` → `delivered` (on poll) → `done` / `failed`. A delivered command with no answer after 10 minutes becomes
`failed`. Commands of a job that has ended are withdrawn before delivery.

## Database (SQLite, `workflow.db`)

| Table | Content |
|---|---|
| `assignments`, `cert_notes`, `cert_checklist` | Team assignments, notes, pipeline checklist per domain. |
| `cert_snapshot`, `renewal_history` | Last seen expiry per domain and the renewals detected from it. |
| `agents` | Registered agents: last check-in / last seen, version, enabled flag, scan interval. |
| `discovered_certs` | Certificates reported by agents (replaced on each check-in of that host). |
| `agent_commands` | Command queue and results. |
| `renewal_jobs` | Renewal workflow state, DigiCert order id, CSR, issued chain, messages. |
| `app_settings` | Key/value settings that must survive the Settings form (e.g. renewal mode). |

Secrets (DigiCert API key, SMTP password, agent token) are stored in the OS credential store via `keyring`, not in the database.

## Agent internals

`certhelm_agent.py` is deliberately one file using only the standard library:

* **Discovery** — Windows: `Cert:\LocalMachine\My` via PowerShell; Linux: PEM files in common directories parsed with `openssl`,
  plus optional probing of local TLS ports.
* **Runner** (`AgentRunner`) — poll every 30 s, scan every *interval* hours, execute commands. Shared by `--daemon` and `--tray`.
* **Certificate management** — `generate_csr` / `install_cert` with Windows (`certreq`, IIS) and Linux (`openssl`, service reload)
  implementations. Every external command goes through one function (`_run`) with a fixed argv and no shell.

## Configuration files

| File | Where | Notes |
|---|---|---|
| `config.json` | controller working directory | Non-sensitive settings (alert threshold, SMTP host, listener port…). |
| `workflow.db` | controller working directory | SQLite database. |
| `agent_config.json` | next to the agent | Controller URL, token, hostname, options. **Contains the token — never commit it.** |
