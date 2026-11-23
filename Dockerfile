# syntax=docker/dockerfile:1
# Base image pinned by digest (supply-chain integrity, reproducible builds).
# Refresh monthly for OS security patches:  docker pull python:3.12-slim && docker image inspect
#   python:3.12-slim --format '{{index .RepoDigests 0}}'   -> paste the new digest in BOTH stages.
FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
# requirements.lock = every (transitive) dependency pinned with sha256 hashes; pip refuses anything else.
# Regenerate after editing requirements.txt - see docs/GUIDE.md section 9 ("Updating dependencies").
COPY requirements.lock .
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --require-hashes --no-deps -r requirements.lock

FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928
LABEL org.opencontainers.image.title="Eye of Sauron" \
      org.opencontainers.image.description="Lightweight, security-focused RSS aggregator" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    EOS_DATA_DIR=/data \
    SQLITE_TMPDIR=/data/tmp
# SQLITE_TMPDIR: big sorts (video shelves, retention) spill to the data volume, not the 16 MB /tmp tmpfs.
# The app creates /data/tmp (0700) at start; SQLite falls back to /tmp if it is missing.

# Unprivileged runtime user; application code is owned by root and read-only to it.
RUN groupadd --system --gid 10001 eos \
 && useradd --system --uid 10001 --gid eos --home-dir /nonexistent --shell /usr/sbin/nologin eos \
 && mkdir -p /data && chown eos:eos /data && chmod 0700 /data

COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY app ./app
COPY static ./static

USER 10001:10001
EXPOSE 8080
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"]

# Single worker by design (in-process scheduler + login throttle).
# Behind a reverse proxy set FORWARDED_ALLOW_IPS to the proxy's IP so client IPs are correct.
CMD ["uvicorn", "app.main:create_app", "--factory", "--host", "0.0.0.0", "--port", "8080", \
     "--no-server-header", "--timeout-graceful-shutdown", "10"]
