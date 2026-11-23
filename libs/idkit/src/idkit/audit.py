"""Structured audit events: who (user), what (agent), which resource, which decision."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path


class AuditLog:
    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path) if path else None
        self.events: list[dict] = []
        self._lock = threading.Lock()

    def record(self, event: str, **fields) -> dict:
        entry = {"ts": round(time.time(), 3), "event": event, **fields}
        with self._lock:
            self.events.append(entry)
            if self.path:
                with self.path.open("a") as fh:
                    fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    def find(self, event: str) -> list[dict]:
        return [e for e in self.events if e["event"] == event]
