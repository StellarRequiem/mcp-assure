"""Hash-chained decision receipts — offline verifiable integrity.

Multi-writer safe: process-local lock + optional fcntl flock on a sidecar
.lock file so MCP host + CLI proof suites do not race-break the chain.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

try:
    import fcntl
except ImportError:  # pragma: no cover — non-POSIX
    fcntl = None  # type: ignore

GENESIS = "MCP_ASSURE_RECEIPT_GENESIS_v1"


@dataclass
class Receipt:
    id: str
    ts: float
    decision: str
    tool: str
    actor: str
    source: str
    code: str
    detail: str
    prev_hash: str
    hash: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        meta = dict(d.get("metadata") or {})
        for bad in ("password", "token", "secret", "api_key", "authorization"):
            meta.pop(bad, None)
        d["metadata"] = meta
        return d


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_hash(prev_hash: str, body: dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(b"|")
    h.update(_canonical(body))
    return h.hexdigest()


class ReceiptChain:
    def __init__(self, path: str | None = None) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._prev = GENESIS
        self._count = 0
        if path:
            parent = os.path.dirname(os.path.abspath(path))
            if parent:
                os.makedirs(parent, exist_ok=True)
            self._load_tip(path)

    def _lock_path(self) -> str | None:
        if not self.path:
            return None
        return f"{self.path}.lock"

    def _load_tip(self, path: str) -> None:
        if not os.path.isfile(path):
            self._prev = GENESIS
            self._count = 0
            return
        last = None
        n = 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    last = json.loads(line)
                    n += 1
            self._count = n
            if last and "hash" in last:
                self._prev = last["hash"]
            else:
                self._prev = GENESIS
        except (OSError, json.JSONDecodeError):
            self._prev = GENESIS
            self._count = 0

    def append(
        self,
        *,
        decision: str,
        tool: str,
        actor: str,
        source: str,
        code: str,
        detail: str,
        metadata: dict[str, Any] | None = None,
    ) -> Receipt:
        with self._lock:
            lock_f = None
            try:
                lp = self._lock_path()
                if lp and fcntl is not None:
                    lock_f = open(lp, "a+", encoding="utf-8")
                    fcntl.flock(lock_f.fileno(), fcntl.LOCK_EX)
                # Re-sync tip from disk so multi-process writers (MCP + cli proof)
                # do not race-break the chain; also recovers after manual truncate.
                if self.path:
                    self._load_tip(self.path)
                rid = str(uuid.uuid4())
                ts = time.time()
                body = {
                    "id": rid,
                    "ts": ts,
                    "decision": decision,
                    "tool": tool,
                    "actor": actor,
                    "source": source,
                    "code": code,
                    "detail": detail,
                    "metadata": metadata or {},
                }
                digest = compute_hash(self._prev, body)
                rec = Receipt(
                    id=rid,
                    ts=ts,
                    decision=decision,
                    tool=tool,
                    actor=actor,
                    source=source,
                    code=code,
                    detail=detail,
                    prev_hash=self._prev,
                    hash=digest,
                    metadata=metadata or {},
                )
                if self.path:
                    with open(self.path, "a", encoding="utf-8") as f:
                        f.write(json.dumps(rec.to_dict(), sort_keys=True) + "\n")
                        f.flush()
                        try:
                            os.fsync(f.fileno())
                        except OSError:
                            pass
                self._prev = digest
                self._count += 1
                return rec
            finally:
                if lock_f is not None:
                    try:
                        if fcntl is not None:
                            fcntl.flock(lock_f.fileno(), fcntl.LOCK_UN)
                    finally:
                        lock_f.close()

    @property
    def tip(self) -> str:
        return self._prev

    @property
    def count(self) -> int:
        return self._count

    @staticmethod
    def verify_file(path: str) -> tuple[bool, str]:
        if not os.path.isfile(path):
            return False, "missing file"
        prev = GENESIS
        n = 0
        try:
            with open(path, "r", encoding="utf-8") as f:
                for lineno, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    body = {
                        "id": obj["id"],
                        "ts": obj["ts"],
                        "decision": obj["decision"],
                        "tool": obj["tool"],
                        "actor": obj["actor"],
                        "source": obj["source"],
                        "code": obj["code"],
                        "detail": obj["detail"],
                        "metadata": obj.get("metadata") or {},
                    }
                    expect = compute_hash(prev, body)
                    if obj.get("prev_hash") != prev:
                        return False, f"line {lineno}: prev_hash mismatch"
                    if obj.get("hash") != expect:
                        return False, f"line {lineno}: hash mismatch"
                    prev = obj["hash"]
                    n += 1
        except (OSError, json.JSONDecodeError, KeyError) as e:
            return False, f"parse error: {e}"
        return True, f"ok ({n} receipts)"

    @staticmethod
    def rotate_if_broken(
        path: str,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        """Archive a broken (or force-rotated) chain and start empty.

        Used by plane.receipts_rotate recovery when the live chain cannot verify.
        Does not invent a forged genesis from stale tips — starts clean.
        """
        if not path:
            return {"ok": False, "code": "NO_PATH"}
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        if not os.path.isfile(path):
            # touch empty for a clean tip
            open(path, "a", encoding="utf-8").close()
            return {"ok": True, "code": "EMPTY", "detail": "no prior file; ready"}
        ok, msg = ReceiptChain.verify_file(path)
        if ok and not force:
            return {"ok": True, "code": "INTACT", "detail": msg, "path": path}
        ts = int(time.time())
        archive = f"{path}.broken-{ts}"
        try:
            os.replace(path, archive)
        except OSError as e:
            return {"ok": False, "code": "ROTATE_FAILED", "detail": str(e)}
        open(path, "a", encoding="utf-8").close()
        return {
            "ok": True,
            "code": "ROTATED",
            "path": path,
            "archive": archive,
            "was": msg if not ok else "force",
            "detail": "archived prior chain; new empty chain at path",
        }
