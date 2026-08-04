"""Receipt chain integrity: re-sync, rotate, multi-writer flock."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from mcp_assure.engine import AssureEngine
from mcp_assure.policy import Decision, ToolCall, ToolPolicy, ToolPolicyRegistry
from mcp_assure.receipts import GENESIS, ReceiptChain, compute_hash


def _engine(policies, **kw) -> AssureEngine:
    reg = ToolPolicyRegistry()
    for p in policies:
        reg.register(p)
    return AssureEngine(reg, **kw)


def _worker_append(path: str, n: int, tag: str) -> int:
    chain = ReceiptChain(path)
    for i in range(n):
        chain.append(
            decision="ALLOW",
            tool="echo",
            actor=tag,
            source="test",
            code="OK",
            detail=f"{tag}-{i}",
        )
    return n


class TestReceiptChain(unittest.TestCase):
    def test_empty_file_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "r.jsonl")
            open(path, "w").close()
            ok, msg = ReceiptChain.verify_file(path)
            self.assertTrue(ok)
            self.assertIn("0 receipts", msg)

    def test_resync_after_truncate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "r.jsonl")
            c = ReceiptChain(path)
            c.append(
                decision="ALLOW",
                tool="a",
                actor="x",
                source="s",
                code="OK",
                detail="1",
            )
            open(path, "w").close()
            c.append(
                decision="ALLOW",
                tool="b",
                actor="x",
                source="s",
                code="OK",
                detail="2",
            )
            ok, msg = ReceiptChain.verify_file(path)
            self.assertTrue(ok, msg)
            with open(path, encoding="utf-8") as f:
                line = f.readline()
            obj = json.loads(line)
            self.assertEqual(obj["prev_hash"], GENESIS)

    def test_rotate_if_broken(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "r.jsonl")
            c = ReceiptChain(path)
            c.append(
                decision="ALLOW",
                tool="a",
                actor="x",
                source="s",
                code="OK",
                detail="1",
            )
            with open(path, "w", encoding="utf-8") as f:
                f.write(
                    json.dumps(
                        {
                            "id": "bad",
                            "ts": 1.0,
                            "decision": "ALLOW",
                            "tool": "a",
                            "actor": "x",
                            "source": "s",
                            "code": "OK",
                            "detail": "1",
                            "metadata": {},
                            "prev_hash": "not-genesis",
                            "hash": "deadbeef",
                        }
                    )
                    + "\n"
                )
            out = ReceiptChain.rotate_if_broken(path)
            self.assertTrue(out["ok"])
            self.assertEqual(out["code"], "ROTATED")
            self.assertTrue(Path(out["archive"]).is_file())
            ok, msg = ReceiptChain.verify_file(path)
            self.assertTrue(ok, msg)

    def test_chain_broken_skips_receipt_append(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "r.jsonl")
            eng = _engine([ToolPolicy(name="echo")], receipts_path=path)
            eng.evaluate(ToolCall(tool="echo"))
            with open(path, "r", encoding="utf-8") as f:
                lines_before = f.readlines()
            obj = json.loads(lines_before[0])
            obj["detail"] = "TAMPER"
            with open(path, "w", encoding="utf-8") as f:
                f.write(json.dumps(obj) + "\n")
            eng2 = _engine(
                [ToolPolicy(name="echo")],
                receipts_path=path,
                require_intact_chain=True,
            )
            v = eng2.evaluate(ToolCall(tool="echo", source="after"))
            self.assertEqual(v.code, "CHAIN_BROKEN")
            self.assertIsNone(v.receipt)
            with open(path, "r", encoding="utf-8") as f:
                lines_after = f.readlines()
            self.assertEqual(len(lines_after), 1, "must not grow a broken chain")

    def test_chain_repair_allow_rotate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "r.jsonl")
            with open(path, "w", encoding="utf-8") as f:
                f.write(
                    json.dumps(
                        {
                            "id": "bad",
                            "ts": 1.0,
                            "decision": "ALLOW",
                            "tool": "a",
                            "actor": "x",
                            "source": "s",
                            "code": "OK",
                            "detail": "1",
                            "metadata": {},
                            "prev_hash": "not-genesis",
                            "hash": "deadbeef",
                        }
                    )
                    + "\n"
                )

            def rotate_handler(_args=None):
                return ReceiptChain.rotate_if_broken(path)

            eng = _engine(
                [ToolPolicy(name="plane.receipts_rotate")],
                receipts_path=path,
                chain_repair_allow=frozenset({"plane.receipts_rotate"}),
            )
            # evaluate alone only authorizes; call rotate via finish path
            v = eng.evaluate(ToolCall(tool="plane.receipts_rotate"))
            # catalog allow without handler — ALLOW means authz only in engine
            self.assertTrue(v.allowed)
            out = rotate_handler()
            self.assertEqual(out["code"], "ROTATED")
            ok, msg = ReceiptChain.verify_file(path)
            self.assertTrue(ok, msg)

    def test_multiprocess_append_intact(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = os.path.join(td, "r.jsonl")
            # seed empty
            open(path, "w").close()
            n_workers = 4
            per = 8
            with ProcessPoolExecutor(max_workers=n_workers) as ex:
                futs = [
                    ex.submit(_worker_append, path, per, f"w{i}")
                    for i in range(n_workers)
                ]
                total = sum(f.result() for f in as_completed(futs))
            self.assertEqual(total, n_workers * per)
            ok, msg = ReceiptChain.verify_file(path)
            self.assertTrue(ok, msg)
            with open(path, encoding="utf-8") as f:
                n = sum(1 for line in f if line.strip())
            self.assertEqual(n, n_workers * per)


if __name__ == "__main__":
    unittest.main()
