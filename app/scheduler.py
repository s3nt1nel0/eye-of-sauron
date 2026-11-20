"""Background scheduler: refreshes due feeds and runs retention."""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from app.config import get_settings
from app.db import get_db, now
from app import digests
from app.attack_sync import attack_sync
from app.cve_sync import cve_sync
from app.fetcher import fetch_feed, run_retention

log = logging.getLogger("eos.scheduler")

TICK_SECONDS = 30
RETENTION_INTERVAL = 3600


class Scheduler:
    def __init__(self) -> None:
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None
        self._pool: ThreadPoolExecutor | None = None
        self._inflight: set[int] = set()
        self._lock = threading.Lock()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._pool = ThreadPoolExecutor(
            max_workers=get_settings().fetch_concurrency, thread_name_prefix="fetch"
        )
        self._thread = threading.Thread(target=self._run, name="scheduler", daemon=True)
        self._thread.start()
        log.info("Scheduler started")

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
        if self._pool:
            self._pool.shutdown(wait=False, cancel_futures=True)

    def wake(self) -> None:
        self._wake.set()

    def _run(self) -> None:
        last_retention = 0.0
        while not self._stop.is_set():
            try:
                self._tick()
                cve_sync.maybe_start()
                from app.observatory import refresher as observatory_refresher

                observatory_refresher.maybe_start()   # 🔭 public threat data for the dashboards (paced, cached)
                attack_sync.maybe_start()
                from app.atlas_sync import atlas_sync

                atlas_sync.maybe_start()              # MITRE ATLAS (AI techniques), same schedule as ATT&CK
                digests.run_due()
                from app.media import icons

                icons.maybe_start()                    # site icons for the article list (background, cached)
                from app.github import repo_sync

                repo_sync.maybe_start()                # 📦 GitHub repos you follow (twice a day, within GitHub's limits)
                if time.monotonic() - last_retention > RETENTION_INTERVAL:
                    run_retention()
                    last_retention = time.monotonic()
            except Exception:
                log.exception("Scheduler tick failed")
            self._wake.wait(TICK_SECONDS)
            self._wake.clear()

    def _tick(self) -> None:
        with get_db() as db:
            due = [
                r["id"]
                for r in db.execute(
                    "SELECT id FROM feeds WHERE enabled = 1 AND (next_fetch IS NULL OR next_fetch <= ?) "
                    "ORDER BY next_fetch LIMIT 200",
                    (now(),),
                )
            ]
        for feed_id in due:
            with self._lock:
                if feed_id in self._inflight:
                    continue
                self._inflight.add(feed_id)
            assert self._pool is not None
            self._pool.submit(self._fetch_one, feed_id)

    def _fetch_one(self, feed_id: int) -> None:
        try:
            fetch_feed(feed_id)
        except Exception:
            log.exception("Unexpected error fetching feed %d", feed_id)
        finally:
            with self._lock:
                self._inflight.discard(feed_id)


scheduler = Scheduler()
