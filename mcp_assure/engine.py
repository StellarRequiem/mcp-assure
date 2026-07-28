"""AssureEngine — single choke point for tool authorization.

Order:
  0. Freeze allowlist
  1. Receipt chain integrity
  2. Catalog membership (deny-by-default)
  3. Lab flag
  4. dry_run_only policy
  5. Argument constraints
  6. Resource / audience binding
  7. Blast radius
  8. Velocity
  9. Receipt
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from .args import validate_arguments
from .policy import Decision, ToolCall, ToolPolicyRegistry
from .receipts import Receipt, ReceiptChain
from .velocity import VelocityTracker


@dataclass
class Verdict:
    decision: Decision
    tool: str
    code: str
    detail: str
    receipt: Receipt | None = None

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    def as_dict(self) -> dict[str, Any]:
        return {
            "decision": self.decision.value,
            "tool": self.tool,
            "code": self.code,
            "detail": self.detail,
            "allowed": self.allowed,
            "receipt_hash": self.receipt.hash if self.receipt else None,
            "receipt_id": self.receipt.id if self.receipt else None,
        }


class AssureEngine:
    def __init__(
        self,
        registry: ToolPolicyRegistry | None = None,
        *,
        receipts_path: str | None = None,
        velocity: VelocityTracker | None = None,
        require_intact_chain: bool = True,
        freeze_path: str | None = None,
        freeze_allow: frozenset[str] | None = None,
    ) -> None:
        self.registry = registry or ToolPolicyRegistry()
        self.velocity = velocity or VelocityTracker()
        self.chain = ReceiptChain(receipts_path)
        self.require_intact_chain = require_intact_chain
        self._chain_path = receipts_path
        self.freeze_path = freeze_path
        self.freeze_allow = freeze_allow or frozenset()

    def _chain_ok(self) -> tuple[bool, str]:
        if not self._chain_path or not os.path.isfile(self._chain_path):
            return True, "empty_or_new"
        return ReceiptChain.verify_file(self._chain_path)

    def _frozen(self) -> bool:
        return bool(self.freeze_path and os.path.isfile(self.freeze_path))

    def evaluate(self, call: ToolCall) -> Verdict:
        tool = (call.tool or "").strip()

        # 0 freeze
        if self._frozen() and tool not in self.freeze_allow:
            return self._finish(
                call,
                Decision.DENY,
                "FREEZE",
                f"assurance freeze engaged; tool {tool!r} not on freeze allowlist",
            )

        # 1 chain
        ok, msg = self._chain_ok()
        if self.require_intact_chain and not ok:
            return self._finish(
                call,
                Decision.DENY,
                "CHAIN_BROKEN",
                f"receipt chain integrity failure: {msg}",
            )

        # 2 catalog
        if not tool:
            return self._finish(call, Decision.DENY, "EMPTY_TOOL", "tool name empty")
        if len(self.registry) == 0:
            return self._finish(
                call,
                Decision.DENY,
                "EMPTY_CATALOG",
                "no tools registered — deny by default",
            )
        policy = self.registry.get(tool)
        if policy is None:
            return self._finish(
                call,
                Decision.DENY,
                "UNKNOWN_TOOL",
                f"tool {tool!r} not in policy catalog",
            )

        # 3 lab
        if policy.lab_only and not call.lab_mode:
            return self._finish(
                call,
                Decision.DENY,
                "LAB_REQUIRED",
                f"tool {tool!r} requires lab_mode=True",
            )

        # 4 dry_run policy
        if policy.dry_run_only:
            # still validate args/bindings so dry-run is meaningful
            pass

        # 5 args
        a_ok, a_msg = validate_arguments(
            call.arguments if isinstance(call.arguments, dict) else {},
            required=policy.required_args,
            allowed=policy.allowed_args,
            forbidden=policy.forbidden_args,
            max_bytes=policy.max_arg_bytes,
            max_depth=policy.max_arg_depth,
        )
        if not a_ok:
            return self._finish(call, Decision.DENY, "ARG_POLICY", a_msg)

        # 6 resource / audience
        if policy.require_resource:
            if not call.resource:
                return self._finish(
                    call, Decision.DENY, "RESOURCE_REQUIRED", "resource binding required"
                )
            if policy.allowed_resources and call.resource not in policy.allowed_resources:
                return self._finish(
                    call,
                    Decision.DENY,
                    "RESOURCE_MISMATCH",
                    f"resource {call.resource!r} not in allowlist",
                )
        elif policy.allowed_resources and call.resource:
            if call.resource not in policy.allowed_resources:
                return self._finish(
                    call,
                    Decision.DENY,
                    "RESOURCE_MISMATCH",
                    f"resource {call.resource!r} not in allowlist",
                )

        if policy.require_audience:
            if not call.audience:
                return self._finish(
                    call, Decision.DENY, "AUDIENCE_REQUIRED", "audience binding required"
                )
            if policy.allowed_audiences and call.audience not in policy.allowed_audiences:
                return self._finish(
                    call,
                    Decision.DENY,
                    "AUDIENCE_MISMATCH",
                    f"audience {call.audience!r} not in allowlist",
                )
        elif policy.allowed_audiences and call.audience:
            if call.audience not in policy.allowed_audiences:
                return self._finish(
                    call,
                    Decision.DENY,
                    "AUDIENCE_MISMATCH",
                    f"audience {call.audience!r} not in allowlist",
                )

        # 7 blast
        blast = max(int(call.blast_units), 1)
        if blast > policy.max_blast:
            return self._finish(
                call,
                Decision.DENY,
                "BLAST_EXCEEDED",
                f"blast_units {blast} exceeds max_blast {policy.max_blast}",
            )

        # 8 velocity
        v_ok, v_msg = self.velocity.check_and_record(
            identity_key=call.identity_key(),
            actor=call.actor,
        )
        if not v_ok:
            return self._finish(call, Decision.DENY, "VELOCITY", v_msg)

        # 9 decision
        if policy.dry_run_only:
            decision = Decision.DRY_RUN
            code = "DRY_RUN_ONLY"
            detail = f"tool {tool!r} is dry_run_only — not executed"
        else:
            decision = Decision.ALLOW
            code = "OK"
            detail = f"allowed: {policy.description or tool}"

        # model_note never changes decision — only recorded
        return self._finish(
            call,
            decision,
            code,
            detail,
            meta_extra={
                "model_note_ignored_for_authz": bool(call.model_note),
                "model_note_len": len(call.model_note or ""),
            },
        )

    def _finish(
        self,
        call: ToolCall,
        decision: Decision,
        code: str,
        detail: str,
        meta_extra: dict[str, Any] | None = None,
    ) -> Verdict:
        meta: dict[str, Any] = {
            "code": code,
            "resource": call.resource,
            "audience": call.audience,
            "lab_mode": call.lab_mode,
            "blast_units": call.blast_units,
            "arg_keys": sorted((call.arguments or {}).keys())[:40],
        }
        if meta_extra:
            meta.update(meta_extra)
        rec = self.chain.append(
            decision=decision.value,
            tool=call.tool or "",
            actor=call.actor,
            source=call.source,
            code=code,
            detail=detail[:1000],
            metadata=meta,
        )
        return Verdict(
            decision=decision,
            tool=call.tool or "",
            code=code,
            detail=detail,
            receipt=rec,
        )
