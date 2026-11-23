#!/usr/bin/env bash
# Update a Docker Compose install of Eye of Sauron to the newest version on GitHub - safely.
#
#   cd ~/eye-of-sauron && ./deploy/update.sh          # shows what's new, asks, then updates
#   ./deploy/update.sh -y                             # no question (e.g. from a timer)
#   ./deploy/update.sh --check                        # only show whether an update is waiting
#
# What it does:
#   1. Fetches the newest code and lists the new commits (stops here if you are already up to date).
#   2. Builds the new image while the current app keeps running.
#   3. Stops the app for a moment and backs up the data volume to ./backups/ (keeps the newest 5).
#   4. Starts the new version and waits until its health check passes.
#   5. If it doesn't come up healthy, it rolls back to the version you had, and tells you how to restore the backup.
# Your .env, secrets and data volume are never changed by the update itself.
set -euo pipefail

BRANCH="main"
ASSUME_YES=0
CHECK_ONLY=0
BACKUP=1
KEEP_BACKUPS=5
WAIT_SECONDS=180

usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; }
while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes) ASSUME_YES=1 ;;
    --check) CHECK_ONLY=1 ;;
    --no-backup) BACKUP=0 ;;
    --branch) BRANCH="${2:?--branch needs a name}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31mxx\033[0m %s\n' "$*" >&2; exit 1; }

# --- where we are -------------------------------------------------------------------------------------------------
cd "$(dirname "$0")/.."
[ -f docker-compose.yml ] && [ -d .git ] || die "Run this from your Eye of Sauron folder (the one you cloned with git)."
command -v git >/dev/null || die "git is not installed."
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 is not available (try: apt install docker-compose-plugin)."
case "$BRANCH" in *[!A-Za-z0-9._/-]*|"") die "Invalid branch name: $BRANCH" ;; esac

SERVICE="eye-of-sauron"
VOLUME_KEY="eye-of-sauron-data"
if ! git diff --quiet || ! git diff --cached --quiet; then
  warn "You have changed tracked files here (git status shows them). The update keeps them only if they don't clash:"
  git status --short --untracked-files=no >&2
fi

# --- 1. anything new? -----------------------------------------------------------------------------------------------
say "Checking GitHub for a newer version ($BRANCH)…"
git fetch --quiet origin "$BRANCH"
OLD_COMMIT="$(git rev-parse HEAD)"
NEW_COMMIT="$(git rev-parse "origin/$BRANCH")"
if [ "$OLD_COMMIT" = "$NEW_COMMIT" ] || git merge-base --is-ancestor "origin/$BRANCH" HEAD; then
  say "Already up to date ($(git log -1 --format='%h %s' HEAD))."
  exit 0
fi
echo "New since your version:"
git log --oneline --no-decorate "HEAD..origin/$BRANCH" | sed 's/^/   /'
[ "$CHECK_ONLY" = 1 ] && exit 0
if [ "$ASSUME_YES" != 1 ]; then
  read -r -p "Update now? The app is offline for about a minute. [y/N] " answer
  case "$answer" in [yY]*) ;; *) echo "Nothing changed."; exit 0 ;; esac
fi

OLD_IMAGE="$(docker compose images -q "$SERVICE" 2>/dev/null | head -n1 || true)"
git merge --ff-only --quiet "origin/$BRANCH" || die "Your copy has its own commits or edits that clash; nothing was changed. See git status."

rollback() {
  warn "Rolling back to $(git log -1 --format='%h' "$OLD_COMMIT")…"
  git reset --quiet --hard "$OLD_COMMIT"
  if [ -n "$OLD_IMAGE" ]; then
    docker tag "$OLD_IMAGE" "$(docker compose config --images | head -n1)" >/dev/null 2>&1 || true
  fi
  docker compose up -d --no-build "$SERVICE" || docker compose up -d "$SERVICE"
  warn "The previous version is running again."
  if [ -n "${BACKUP_FILE:-}" ]; then
    warn "If its data looks wrong (the new version may have changed the database), restore the backup taken just before:"
    warn "  docker compose stop && docker run --rm --user 0 --entrypoint sh -v ${VOLUME:-<volume>}:/data -v \"$PWD/backups\":/in \\"
    warn "    $(docker compose config --images | head -n1) -c 'rm -rf /data/* && tar -xzf /in/$(basename "$BACKUP_FILE") -C /data' && docker compose start"
  fi
  exit 1
}

# --- 2. build while the current version keeps running ---------------------------------------------------------------
say "Building the new version (the current one keeps running)…"
docker compose build "$SERVICE" || rollback
IMAGE="$(docker compose config --images | head -n1)"   # the app image also does the backup (no extra download)

# --- 3. back up the data ---------------------------------------------------------------------------------------------
VOLUME="$(docker volume ls -q --filter "label=com.docker.compose.volume=$VOLUME_KEY" | head -n1)"
say "Stopping the app for the switch…"
docker compose stop "$SERVICE"
if [ "$BACKUP" = 1 ]; then
  [ -n "$VOLUME" ] || die "Couldn't find the data volume ($VOLUME_KEY). Nothing was changed; start the app with: docker compose up -d"
  mkdir -p backups
  BACKUP_FILE="backups/eos-data-$(date +%Y%m%d-%H%M%S)-$(git rev-parse --short "$OLD_COMMIT").tgz"
  say "Backing up your data to $BACKUP_FILE…"
  docker run --rm --user 0 --entrypoint tar -v "$VOLUME":/data:ro -v "$PWD/backups":/out "$IMAGE" \
    -czf "/out/$(basename "$BACKUP_FILE")" -C /data . || { docker compose start "$SERVICE"; die "Backup failed; the old version was started again."; }
  chmod 600 "$BACKUP_FILE" 2>/dev/null || true
  # keep only the newest backups
  ls -1t backups/eos-data-*.tgz 2>/dev/null | tail -n +$((KEEP_BACKUPS + 1)) | xargs -r rm -f --
fi

# --- 4. start the new version and wait for its health check ----------------------------------------------------------
say "Starting the new version…"
docker compose up -d "$SERVICE" || rollback
CONTAINER="$(docker compose ps -q "$SERVICE")"
say "Waiting for it to report healthy (up to ${WAIT_SECONDS}s)…"
for _ in $(seq 1 $((WAIT_SECONDS / 5))); do
  status="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$CONTAINER" 2>/dev/null || echo missing)"
  case "$status" in
    healthy) break ;;
    unhealthy|exited|dead|missing) warn "The new version is $status. Last log lines:"; docker compose logs --tail=30 "$SERVICE" >&2 || true; rollback ;;
  esac
  sleep 5
done
[ "${status:-}" = healthy ] || { warn "It didn't become healthy in time."; docker compose logs --tail=30 "$SERVICE" >&2 || true; rollback; }

say "Updated: $(git log -1 --format='%h %s' HEAD)"
[ -n "${BACKUP_FILE:-}" ] && echo "    Backup of your previous data: $BACKUP_FILE"
docker image prune -f >/dev/null 2>&1 || true
