# Security policy

## Supported versions

Security fixes are made for the latest release. Please upgrade before reporting.

| Version | Supported |
|---|---|
| 1.x (latest) | ✅ |
| older | ❌ |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub: **Security → Report a vulnerability** on this repository (GitHub private
vulnerability reporting). Include:

- the version (Settings → About) and how you run it (Docker, systemd…);
- what an attacker can do, and the steps or a proof of concept;
- any logs or requests that help reproduce it (remove secrets and personal data).

You will get an acknowledgement within 7 days. Confirmed issues are fixed in a release and credited in the changelog
unless you prefer otherwise. Please give us a reasonable time to ship a fix before disclosing.

## Scope

In scope: the application in this repository and its default container image / compose file.

Out of scope: instances you do not own, denial of service by volume, findings that need a compromised host or a
malicious administrator, and the third-party sites the app reads from.

## How the app is secured

See [docs/admins/04_Security_design.md](docs/admins/04_Security_design.md) for the threat model and controls, and
[docs/admins/01_Deployment.md](docs/admins/01_Deployment.md#reaching-it-securely-from-outside) for exposing it safely.
