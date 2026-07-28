"""Tool policies and call shapes — deny by default."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    DRY_RUN = "DRY_RUN"
    ESCALATE = "ESCALATE"


@dataclass(frozen=True)
class ToolPolicy:
    """Allowlisted tool definition.

    Unknown tools are never allowed. Empty registry ⇒ everything DENY.
    """

    name: str
    max_blast: int = 1
    lab_only: bool = False
    dry_run_only: bool = False
    # Argument constraints (stdlib — no JSON Schema engine required)
    required_args: tuple[str, ...] = ()
    allowed_args: tuple[str, ...] | None = None  # None = any keys ok
    forbidden_args: tuple[str, ...] = ()
    max_arg_bytes: int = 65_536
    max_arg_depth: int = 8
    # Optional resource/audience binding (MCP auth-shaped fields on the call)
    require_resource: bool = False
    allowed_resources: tuple[str, ...] = ()
    require_audience: bool = False
    allowed_audiences: tuple[str, ...] = ()
    description: str = ""


@dataclass
class ToolCall:
    """Normalized tool invocation entering the gate."""

    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    actor: str = "agent"
    source: str = "mcp"
    # Optional MCP-ish binding context (caller supplies; we do not invent)
    resource: str | None = None
    audience: str | None = None
    # Abstract cost; default 1 tool call unit
    blast_units: int = 1
    lab_mode: bool = False
    # Non-binding model chatter — never authorizes
    model_note: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def identity_key(self) -> str:
        return f"{self.actor}|{self.tool}|{self.source}"


class ToolPolicyRegistry:
    """Deny-by-default catalog."""

    def __init__(self, policies: list[ToolPolicy] | None = None) -> None:
        self._by_name: dict[str, ToolPolicy] = {}
        for p in policies or []:
            self.register(p)

    def register(self, policy: ToolPolicy) -> None:
        if not policy.name or not str(policy.name).strip():
            raise ValueError("tool policy name must be non-empty")
        self._by_name[policy.name] = policy

    def get(self, name: str) -> ToolPolicy | None:
        return self._by_name.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._by_name

    def names(self) -> list[str]:
        return sorted(self._by_name)

    def __len__(self) -> int:
        return len(self._by_name)

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> "ToolPolicyRegistry":
        """Build from a plain dict (JSON/YAML-loaded)."""
        reg = cls()
        tools = raw.get("tools") if isinstance(raw, dict) else None
        if not isinstance(tools, dict):
            return reg
        for name, body in tools.items():
            body = body if isinstance(body, dict) else {}
            reg.register(
                ToolPolicy(
                    name=str(name),
                    max_blast=int(body.get("max_blast", 1)),
                    lab_only=bool(body.get("lab_only", False)),
                    dry_run_only=bool(body.get("dry_run_only", False)),
                    required_args=tuple(body.get("required_args") or ()),
                    allowed_args=(
                        tuple(body["allowed_args"])
                        if body.get("allowed_args") is not None
                        else None
                    ),
                    forbidden_args=tuple(body.get("forbidden_args") or ()),
                    max_arg_bytes=int(body.get("max_arg_bytes", 65_536)),
                    max_arg_depth=int(body.get("max_arg_depth", 8)),
                    require_resource=bool(body.get("require_resource", False)),
                    allowed_resources=tuple(body.get("allowed_resources") or ()),
                    require_audience=bool(body.get("require_audience", False)),
                    allowed_audiences=tuple(body.get("allowed_audiences") or ()),
                    description=str(body.get("description") or ""),
                )
            )
        return reg
