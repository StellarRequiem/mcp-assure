"""Security CLI surface."""

from __future__ import annotations

import json
import unittest
from io import StringIO
from unittest import mock

from mcp_assure.cli import main


class CliTests(unittest.TestCase):
    def test_status(self) -> None:
        with mock.patch("sys.stdout", new_callable=StringIO) as out:
            rc = main(["status", "--json"])
        self.assertEqual(rc, 0)
        data = json.loads(out.getvalue())
        self.assertEqual(data["name"], "mcp-assure")
        self.assertIn("version", data)
        self.assertIn("hosted_vulnerability_scanner", data["not"])

    def test_check(self) -> None:
        with mock.patch("sys.stdout", new_callable=StringIO):
            rc = main(["check"])
        self.assertEqual(rc, 0)

    def test_evaluate_allow(self) -> None:
        with mock.patch("sys.stdout", new_callable=StringIO) as out:
            rc = main(
                [
                    "evaluate",
                    "--tool",
                    "echo",
                    "--args-json",
                    '{"text":"hi"}',
                    "--pack",
                    "baseline",
                    "--json",
                ]
            )
        self.assertEqual(rc, 0)
        data = json.loads(out.getvalue())
        self.assertTrue(data["verdict"]["allowed"])

    def test_evaluate_deny_unknown(self) -> None:
        with mock.patch("sys.stdout", new_callable=StringIO):
            rc = main(["evaluate", "--tool", "shell_exec", "--pack", "baseline"])
        self.assertEqual(rc, 1)

    def test_packs(self) -> None:
        with mock.patch("sys.stdout", new_callable=StringIO) as out:
            rc = main(["packs"])
        self.assertEqual(rc, 0)
        self.assertIn("baseline", out.getvalue())
        self.assertIn("agent_eval_strict", out.getvalue())


if __name__ == "__main__":
    unittest.main()
