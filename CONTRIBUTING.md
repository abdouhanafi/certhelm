# Contributing

Thanks for your interest in CertHelm.

## Ground rules

* **Never test against real infrastructure by default.** Tests must use the fake DigiCert server, temporary folders and stubbed
  system commands (see `tests/`). A change that can order a certificate or modify a certificate store needs a test that proves it
  cannot do so while renewal is switched off or without the server's opt-in.
* **Never commit secrets or runtime data**: API keys, tokens, `agent_config.json`, `config.json`, `workflow.db`, keys,
  certificates. Use `example.com` names and placeholder addresses in tests, docs and screenshots.
* Keep the agent a **single file with no third-party dependency**.
* Keep the safety properties described in [docs/renewal.md](docs/renewal.md) and [docs/security.md](docs/security.md); if a change
  weakens one, say so explicitly in the pull request.

## Development setup

```bash
python -m venv .venv && . .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt cryptography
python tests/run_all.py
```

The desktop app itself only runs on Windows; the tests run anywhere (they stub `webview`, `keyring` and `plyer`).

## Pull requests

* One topic per request, with tests for new behaviour.
* `python tests/run_all.py` must pass.
* JavaScript has no build step; check syntax with `node --check certhelm/ui/app.js`.
* Describe what you verified and what you could **not** verify (for example, anything that needs a real Windows Server / IIS).

## Ideas that would help

* Interface translation (i18n layer; the UI is currently mostly French).
* TLS and per-agent credentials on the agent channel.
* Support for more targets (Apache on Windows, non-IIS HTTP.sys, Kubernetes secrets).
* A headless controller mode so renewals progress without the desktop app open.
