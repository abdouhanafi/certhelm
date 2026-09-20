# Security policy

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Use GitHub's **private vulnerability reporting**: open the **Security** tab of this repository and click
**Report a vulnerability** (the maintainer must have enabled it under *Settings → Code security*). Include:

* what you found and its impact,
* steps to reproduce,
* the CertHelm version / commit and your environment.

You will get an acknowledgement, and the fix will be coordinated before details are published.

## Scope

In scope: the controller, the agent, the installer and the documentation's security claims
(see [docs/security.md](docs/security.md)).

Known and documented limitations (plain-HTTP agent channel, shared token) are design trade-offs described in that document;
proposals to improve them are welcome as regular issues or pull requests.

## Supported versions

Only the latest release is supported while the project is in beta.
