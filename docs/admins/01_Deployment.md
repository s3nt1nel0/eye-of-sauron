# Installation & deployment

Eye of Sauron is **one small web service plus one SQLite database file**. It needs no external database, cache or queue, so it runs almost anywhere that can keep a process running and store a few hundred megabytes.

**Contents**
- [What it needs](#what-it-needs)
- [Choosing where to run it](#choosing-where-to-run-it)
- [1. Docker Compose (recommended, any Linux host)](#1-docker-compose-recommended-any-linux-host)
- [2. Home server / NAS (Synology, Unraid, TrueNAS, Raspberry Pi)](#2-home-server--nas-synology-unraid-truenas-raspberry-pi)
- [3. Proxmox](#3-proxmox)
- [4. Linux without Docker (systemd)](#4-linux-without-docker-systemd)
- [5. Cloud VPS](#5-cloud-vps-hetzner-digitalocean-linode-aws-lightsail-oracle-cloud)
- [6. Kubernetes](#6-kubernetes-single-replica)
- [7. Windows or macOS](#7-windows-or-macos-personal-use--testing)
- [Reaching it securely from outside](#reaching-it-securely-from-outside)
- [Where it does not fit](#where-it-does-not-fit)
- [After deploying: checklist](#after-deploying-checklist)

---

## What it needs

| | Minimum | Comfortable |
|---|---|---|
| CPU | 1 vCPU | 2 vCPU |
| RAM | 512 MB | 1 GB (more if you run a local AI model alongside it) |
| Disk | 1 GB | 5–10 GB for years of articles and full CVE history |
| Architecture | x86-64 (tested); 64-bit ARM such as Raspberry Pi 4/5 (should work, not yet tested) | |
| Network | Outbound HTTPS to the sites you follow; one inbound port (8080) for the web UI | |

**Real-world numbers:**
- A database holding about 3,000 articles and about 20,000 CVEs is about 75 MB.
- The container image is about 350 MB.

**What you must back up:**
- the **data directory** (`/data` in Docker): it holds the database and `secret.key`;
- the encryption key, wherever you keep it if you moved it to a Docker secret.

## Choosing where to run it

| Your situation | Recommended |
|---|---|
| Home lab, NAS or an always-on PC | **Docker Compose** (§1–2), reached remotely through **Tailscale** |
| Proxmox | **Docker in a Debian LXC** (§3) |
| You want it on the internet, reachable from anywhere | **Cloud VPS** (§5) with Caddy (automatic HTTPS) and SSO in front |
| An existing Kubernetes cluster | **Single-replica Deployment** with a persistent volume (§6) |
| Just trying it out on a laptop | **Docker Desktop** (§7) |

---

## 1. Docker Compose (recommended, any Linux host)

```bash
git clone <repository-url> eye-of-sauron && cd eye-of-sauron
cp .env.example .env           # optional: set EOS_ADMIN_PASSWORD (12+ characters)
docker compose up -d --build
```

* **Open:** `http://<host>:8080`.
* **First login:** if you didn't set a password, read the generated one, log in, change it, then delete the file.
  ```bash
  docker compose exec eye-of-sauron cat /data/initial_admin_password.txt
  docker compose exec eye-of-sauron rm /data/initial_admin_password.txt
  ```
* **Hardening already in the compose file:**
  * read-only root filesystem;
  * all Linux capabilities dropped;
  * `no-new-privileges`;
  * memory and PID limits;
  * log rotation.
* **Data:** lives in the named volume `eye-of-sauron-data`.
* **Upgrades:**
  ```bash
  git pull && docker compose up -d --build
  ```
  Database migrations run automatically on start. Back up first (see [GUIDE §5.2](GUIDE.md#52-backups--restore)).
* **Stronger key protection:** move the credential-encryption key and admin password into Docker secrets (commented example at the bottom of `docker-compose.yml`, and [GUIDE §5.4](GUIDE.md#54-encryption-key-management)). A leaked backup of the data volume then doesn't expose your stored social, AI and channel credentials.

## 2. Home server / NAS (Synology, Unraid, TrueNAS, Raspberry Pi)

All of these run Docker containers:

* **Synology (DSM 7+):**
  1. Install **Container Manager**.
  2. Create a **Project** and paste `docker-compose.yml` (or point it at the cloned folder).
  3. Map the volume to a shared folder you back up.
* **Unraid:** use the **Compose Manager** plugin with the same file, or add a container from the built image. Map `/data` to `/mnt/user/appdata/eye-of-sauron`.
* **TrueNAS SCALE:** use a **Custom App** (or Dockge / Portainer) with the image, port 8080 and a dataset mounted at `/data`.
* **Raspberry Pi 4/5:**
  * Use a 64-bit OS, then follow §1. The Python dependencies publish ARM64 wheels.
  * Use an SSD rather than an SD card for the data directory, because SQLite writes often.

The default compose file sets **resource limits** (`mem_limit: 512m`). Raise them if you add many feeds or run AI summaries through a local model on the same box.

## 3. Proxmox

* **Option A, recommended: Docker inside an LXC or VM.**
  1. Create a Debian 12 LXC: unprivileged, with `nesting=1` for Docker, 1–2 cores, 1 GB RAM, 8 GB disk.
  2. Install Docker and follow §1.
  3. Back up the container with vzdump, or just the `eye-of-sauron-data` volume.
* **Option B: LXC without Docker.** Follow §4 inside the LXC.

## 4. Linux without Docker (systemd)

For Debian/Ubuntu servers, Proxmox LXCs or any VM where you'd rather not run Docker:

```bash
sudo apt install -y python3 python3-venv git
sudo useradd --system --home /opt/eye-of-sauron --shell /usr/sbin/nologin eos
sudo git clone <repository-url> /opt/eye-of-sauron
sudo python3 -m venv /opt/eye-of-sauron/.venv
# install the exact, hash-verified dependency set (refuses tampered packages)
sudo /opt/eye-of-sauron/.venv/bin/pip install --require-hashes --no-deps -r /opt/eye-of-sauron/requirements.lock
sudo mkdir -p /etc/eye-of-sauron
sudo cp /opt/eye-of-sauron/.env.example /etc/eye-of-sauron/eye-of-sauron.env
sudo chmod 600 /etc/eye-of-sauron/eye-of-sauron.env
sudo cp /opt/eye-of-sauron/deploy/eye-of-sauron.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now eye-of-sauron
```

* **Data:** lives in `/var/lib/eye-of-sauron`. Back up that directory.
* **Hardening:** the unit file runs the service as an unprivileged user with a strict sandbox (`ProtectSystem=strict`, no capabilities, private `/tmp`, and so on).
* **Python version:** the project is built and tested on **Python 3.12**. Use that version, for example from the deadsnakes PPA or the distribution's own package where available.
* **Logs:** `journalctl -u eye-of-sauron -f`.

## 5. Cloud VPS (Hetzner, DigitalOcean, Linode, AWS Lightsail, Oracle Cloud…)

A €4–6/month VPS (1 vCPU, 1–2 GB RAM) is plenty.

1. Create an Ubuntu or Debian server and install Docker.
2. Follow §1, but **publish the app port on localhost only**: in `docker-compose.yml`, use `"127.0.0.1:8080:8080"`.
3. Put **Caddy** in front for automatic HTTPS. Caddyfile:
   ```
   feeds.example.com {
       reverse_proxy 127.0.0.1:8080
   }
   ```
4. Set these in `.env`:
   * `EOS_ALLOWED_HOSTS=feeds.example.com`;
   * `FORWARDED_ALLOW_IPS=127.0.0.1`. Only the proxy's IP may set the client-IP and HTTPS headers that login throttling and secure cookies rely on.
5. **Strongly recommended for internet-facing installs:** put single sign-on with MFA in front, such as Authelia, Authentik, Cloudflare Access or Tailscale Funnel with ACLs. Eye of Sauron has strong passwords, throttling and session controls, but no built-in second factor yet.
6. **Firewall:** allow only 22 (SSH, ideally restricted to your IP) and 80/443.

## 6. Kubernetes (single replica)

Eye of Sauron is designed as **one instance**: SQLite, an in-process scheduler and in-memory login throttling. Run exactly one pod.

* **Pod count:** `replicas: 1`, with `strategy: Recreate` so two pods never share the database.
* **Storage:** a **ReadWriteOnce** PersistentVolumeClaim mounted at `/data`.
* **Secrets:** a Secret for `EOS_SECRET_KEY` and the admin password.
* **Exposure:** an Ingress with TLS, plus `EOS_ALLOWED_HOSTS` and `FORWARDED_ALLOW_IPS` set to your ingress controller's address range.
* **Health checks:** liveness and readiness probes on `GET /healthz`.
* **Container security:** `runAsNonRoot`, `readOnlyRootFilesystem: true` with an `emptyDir` for `/tmp`, and `allowPrivilegeEscalation: false`.

Minimal sketch (adapt names, storage class and ingress; not yet tested on a cluster):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: eye-of-sauron }
spec:
  replicas: 1
  strategy: { type: Recreate }
  selector: { matchLabels: { app: eye-of-sauron } }
  template:
    metadata: { labels: { app: eye-of-sauron } }
    spec:
      securityContext: { runAsNonRoot: true, fsGroup: 10001 }
      containers:
        - name: app
          image: eye-of-sauron:0.8.0          # push to your registry first
          ports: [{ containerPort: 8080 }]
          env:
            - { name: EOS_ALLOWED_HOSTS, value: "feeds.example.com" }
            - name: EOS_SECRET_KEY
              valueFrom: { secretKeyRef: { name: eye-of-sauron, key: secret-key } }
          securityContext: { readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities: { drop: [ALL] } }
          readinessProbe: { httpGet: { path: /healthz, port: 8080 } }
          livenessProbe: { httpGet: { path: /healthz, port: 8080 }, periodSeconds: 30 }
          resources: { requests: { cpu: 100m, memory: 256Mi }, limits: { memory: 768Mi } }
          volumeMounts: [{ name: data, mountPath: /data }, { name: tmp, mountPath: /tmp }]
      volumes:
        - name: data
          persistentVolumeClaim: { claimName: eye-of-sauron-data }
        - name: tmp
          emptyDir: { sizeLimit: 16Mi }
```

## 7. Windows or macOS (personal use / testing)

1. Install **Docker Desktop**, clone the repository and run `docker compose up -d --build`.
2. Open `http://localhost:8080`.

This is fine for personal use or trying it out. For always-on monitoring (alerts and digests), run it on something that stays on: a home server, NAS or VPS. A laptop that sleeps misses scheduled digests and delays alerts until it wakes.

For developing without Docker, see [CONTRIBUTING.md](../CONTRIBUTING.md).

---

## Feed bridge (RSSHub) for X and sites without feeds

[RSSHub](https://docs.rsshub.app) turns many sites into feeds. Eye of Sauron uses it for **X** and, in the 👥 Accounts tab, for **LinkedIn, Instagram, Threads, TikTok** and others that publish no feeds. A ready-made setup is in `examples/rsshub/`.

1. **Copy `examples/rsshub/` outside the repository.** Its `.env` will hold a credential.
2. **Fill in `.env`:** `cp .env.example .env`. For X, set `TWITTER_AUTH_TOKEN` to the `auth_token` cookie of a logged-in X account.
   * Use a **spare account**. X may lock accounts used this way, and the token gives full access to the account.
   * Without a token, RSSHub only returns old posts.
3. **Start it:** `docker compose up -d`. It listens on `127.0.0.1:1200` only, read-only, with all capabilities dropped. Pin the image digest as the file explains.
4. **Let Eye of Sauron reach it:** set `EOS_PRIVATE_ALLOWLIST=127.0.0.1:1200` and restart. In one Compose project, use the service name instead: `rsshub:1200`.
5. **Connect X:** Settings → Integrations → X → Bridge: **RSSHub**, address `http://127.0.0.1:1200` (or `http://rsshub:1200`).
6. **Add accounts:**
   * For X, paste x.com profile links into 👥 Accounts.
   * For other sites, paste the RSSHub route URL (see RSSHub's docs for each site's route and any cookies it needs) and choose the platform.

Never publish RSSHub to the internet: anyone who can reach it can read X through your account.

## Reaching it securely from outside

| Method | Effort | Security | Notes |
|---|---|---|---|
| **Tailscale / WireGuard VPN** | Low | Excellent: nothing is exposed to the internet | Best choice for personal use. Phone apps work over it. |
| **Cloudflare Tunnel + Cloudflare Access** | Low–medium | Very good: SSO/MFA before traffic reaches you | No open ports. |
| **Reverse proxy (Caddy/Traefik/Nginx) + TLS + SSO** | Medium | Good, if kept updated | Needed for a public URL. Set `EOS_ALLOWED_HOSTS` and `FORWARDED_ALLOW_IPS`. |
| Port-forwarding plain HTTP | — | **Don't** | Passwords and app passwords would travel unencrypted. |

Cookies automatically become `Secure` and `__Host-`-prefixed when served over HTTPS.

## Where it does not fit

* **Serverless / scale-to-zero** platforms (AWS Lambda, Cloud Functions, Cloud Run with scale-to-zero, Vercel): the scheduler must keep running to refresh feeds and send alerts and digests.
* **Several replicas or load-balanced instances:** SQLite and the in-process scheduler mean only one instance may run against a database.
* **Platforms with a temporary filesystem** (classic Heroku dynos, some PaaS free tiers): the database would be lost on restart unless a persistent volume is attached.
* **Network shares (NFS/SMB) for the database:** SQLite locking is unreliable on network filesystems. Use local disk or block storage.

## After deploying: checklist

- [ ] **Password:** logged in, changed the password, deleted `initial_admin_password.txt`.
- [ ] **HTTPS or VPN:** used for any access beyond your own machine.
- [ ] **Backups:** of the data directory scheduled, and **restore tested** once ([GUIDE §5.2](GUIDE.md#52-backups--restore)).
- [ ] **Encryption key:** moved out of the data volume (Docker secret / `EOS_SECRET_KEY_FILE`), optional but recommended.
- [ ] **Source link:** if you run a **modified** version for other people, `EOS_SOURCE_URL` is set (AGPL; shown in Settings → About).
- [ ] **Optional extras:**
  - an NVD API key for faster CVE sync;
  - a YouTube API key;
  - an AI provider;
  - delivery channels for alerts.
- [ ] **Monitoring:** healthcheck at `GET /healthz`. Watch the logs for `eos.audit` events ([GUIDE §5.6](GUIDE.md#56-monitoring)).


## Temporary space for big sorts (1.2.0)

The image sets `SQLITE_TMPDIR=/data/tmp`, so large sorts (Videos → By topic, retention) use the data volume instead of the
16 MB `/tmp` of the read-only container. The app creates the folder (mode 0700) at start-up. If you run the app
outside the image on a small `/tmp`, set `SQLITE_TMPDIR` to a folder on a bigger disk.
