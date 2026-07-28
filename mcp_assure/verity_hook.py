"""Optional verity integration — soft dependency.

If ``verity`` / ``verity-core`` is installed, numeric-looking tool results can be
passed through a claim gate. If not installed, hooks no-op with a clear status.

This does **not** change tool ALLOW/DENY; it only post-checks *claims about results*.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class VerityHookResult:
    available: bool
    status: str
    detail: str
    raw: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "status": self.status,
            "detail": self.detail,
            "raw": self.raw,
        }


def verity_available() -> bool:
    try:
        import verity  # noqa: F401

        return True
    except ImportError:
        try:
            import verity_core  # noqa: F401

            return True
        except ImportError:
            return False


def check_claim(
    claim: dict[str, Any],
    truth: dict[str, Any] | None = None,
) -> VerityHookResult:
    """Best-effort claim check.

    Tries ``verity.check`` then no-ops if missing. Never raises into the tool path
    unless ``claim`` is not a dict.
    """
    if not isinstance(claim, dict):
        return VerityHookResult(False, "invalid", "claim must be a dict")

    try:
        from verity import check as verity_check  # type: ignore
    except ImportError:
        try:
            from verity_core import check as verity_check  # type: ignore
        except ImportError:
            return VerityHookResult(
                False,
                "unavailable",
                "verity not installed; pip install verity-core to enable",
            )

    try:
        # Support both check(claim) and check(claim, truth) styles
        if truth is not None:
            raw = verity_check(claim, truth)
        else:
            try:
                raw = verity_check(claim)
            except TypeError:
                raw = verity_check(claim, {})
        if isinstance(raw, dict):
            status = str(raw.get("verdict") or raw.get("status") or "checked")
        else:
            status = "checked"
            raw = {"result": raw}
        return VerityHookResult(True, status, "verity invoked", raw=raw)
    except Exception as exc:  # noqa: BLE001
        return VerityHookResult(
            True,
            "error",
            f"{type(exc).__name__}: {exc}",
            raw=None,
        )


def maybe_verify_tool_result(
    result: Any,
    *,
    claim_keys: tuple[str, ...] = ("accuracy", "win_rate", "score", "f1"),
) -> VerityHookResult | None:
    """If result is a dict containing claim-like keys, run verity; else None."""
    if not isinstance(result, dict):
        return None
    if not any(k in result for k in claim_keys):
        return None
    claim = {
        "name": str(result.get("name") or "tool_result"),
        "text": str(result.get("text") or result)[:500],
    }
    for k in claim_keys:
        if k in result:
            claim[k] = result[k]
    if "sample_size" in result:
        claim["sample_size"] = result["sample_size"]
    if "out_of_sample" in result:
        claim["out_of_sample"] = result["out_of_sample"]
    return check_claim(claim)
