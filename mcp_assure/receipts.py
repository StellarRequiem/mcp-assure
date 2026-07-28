"""Hash-chained decision receipts — offline verifiable integrity."""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

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

    def _load_tip(self, path: str) -> None:
        if not os.path.isfile(path):
            return
        last = None
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    last = json.loads(line)
                    self._count += 1
            if last and "hash" in last:
                self._prev = last["hash"]
        except (OSError, json.JSONDecodeError):
            self._prev = GENESIS

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
            self._prev = digest
            self._count += 1
            return rec

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
