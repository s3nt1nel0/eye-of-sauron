# Development

## Local setup

Python 3.12, no Node toolchain: the front end is plain ES2020 served as static files.

```bash
python -m venv .venv
. .venv/bin/activate                       # Windows: .venv\Scripts\activate
pip install --require-hashes --no-deps -r requirements.lock
pip install -r requirements-dev.txt        # pytest, bandit, pip-audit, detect-secrets

export EOS_DATA_DIR=./data-dev        # the first start writes data-dev/initial_admin_password.txt
uvicorn app.main:create_app --factory --reload --port 8080
```

Set `EOS_DISABLE_SCHEDULER=true` to work on the UI without fetching anything.

## Project layout

```
app/            FastAPI application (one module per feature; app/api/ holds the routes)
app/data/       bundled data (threat-actor catalogue)
static/         front end: index.html, one JS / CSS file per screen, no build step
tests/          pytest suite (unit, API and security regression tests)
tools/          release gate, pentest harness, route audit, secret scan, catalogue builder
docs/           users / admins / developers documentation
deploy/         systemd unit
examples/       starter OPML, RSSHub compose file
```

See the [Architecture & extension guide](01_Architecture.md) for the code map and how to add a source type, an AI
provider, a delivery channel, a dashboard dataset or a setting.

## Tests and the release gate

```bash
pytest -q                                   # ~380 tests, about two minutes
python -I tools/security_check.py           # the release gate: everything below, in order
```

`tools/security_check.py` runs:

| Gate | What it checks |
|---|---|
| Secret scan | `detect-secrets` plus provider patterns against the reviewed baseline `.secrets.baseline.json` |
| Route audit | every API route declares its authentication / authorisation dependency |
| SAST | `bandit` |
| SCA | `pip-audit` on the hash-locked dependency set |
| Tests | the full pytest suite, including the security regression tests |

The **pentest harness** starts a throwaway instance and attacks it over HTTP (authentication, authorisation, CSRF, SSRF,
injection, XSS payloads, mass assignment, rate limits, token tampering, headers…):

```bash
python -I tools/pentest_harness.py . ./pentest-data 0   # cookie_secure=auto
python -I tools/pentest_harness.py . ./pentest-data 1   # behind TLS (Secure cookies)
```

Never point it at an instance holding real data.

## Conventions

- **Security invariants** in the architecture guide are not negotiable: all outbound requests through `app/netguard.py`,
  all HTML through `app/sanitize.py`, every route with an auth dependency, no secrets in responses or logs.
- SQL uses bound parameters only. Fixed SQL fragments that are interpolated are marked `# nosec B608` with a reason.
- Front end: build DOM with `h()`, never `innerHTML` with data; no inline scripts or styles (the CSP forbids them).
- New feature = tests + docs (user guide, and admin / developer docs where it applies) + a CHANGELOG entry.
- Dependencies: add to `requirements.txt`, regenerate `requirements.lock` with hashes (inside the Docker base image so
  the hashes match the target platform), and run the gate.

## Release checklist

1. `python -I tools/security_check.py` passes; the pentest harness reports 0 FAIL in both modes.
2. Version bumped in `app/__init__.py` and `docker-compose.yml`; CHANGELOG updated.
3. `docker build .` succeeds; the container starts, `/healthz` answers, sign-in works.
4. Tag the release (`vX.Y.Z`) and publish the image.
