"""Tiny JSON-file store for idempotency and proof-reuse tracking.

Two jobs:
  * Idempotency — the platform may redeliver a task/turn; a retry must
    get the EXACT same response (and proof) as the first delivery.
    Responses are persisted by task_id (Gatekeeper) and by
    "matchId:turn" (Steal the VFY).
  * Proof reuse — a Gatekeeper proof_tx that was already ACCEPTED
    (answered APPROVE) must be rejected if it appears again
    (PROOF_REUSED). Seen proof_tx values are persisted across restarts.

Single-process, write-through, atomic replace. Good enough for one
agent instance; not a concurrent-writer store.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any


class Store:
    def __init__(self, path: Path):
        self._path = path
        self._lock = threading.Lock()
        self._data: dict[str, Any] = {"responses": {}, "seen_proofs": []}
        if path.exists():
            try:
                loaded = json.loads(path.read_text())
                if isinstance(loaded, dict):
                    self._data.update(loaded)
            except (json.JSONDecodeError, OSError):
                pass  # corrupt store -> start clean rather than crash

    def _flush(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data))
        tmp.replace(self._path)

    # -- idempotent responses -------------------------------------------------
    def get_response(self, key: str) -> dict | None:
        with self._lock:
            resp = self._data["responses"].get(key)
            return dict(resp) if resp is not None else None

    def save_response(self, key: str, response: dict) -> None:
        with self._lock:
            self._data["responses"][key] = response
            self._flush()

    # -- seen proof_tx (Gatekeeper) -------------------------------------------
    def is_proof_seen(self, proof_tx: str) -> bool:
        with self._lock:
            return proof_tx.lower() in self._data["seen_proofs"]

    def mark_proof_seen(self, proof_tx: str) -> None:
        with self._lock:
            value = proof_tx.lower()
            if value not in self._data["seen_proofs"]:
                self._data["seen_proofs"].append(value)
                self._flush()
