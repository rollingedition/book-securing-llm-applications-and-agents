"""The trace every scorer reads: the outbox, tool calls with their arguments, the reply text, and the URLs fetched or rendered.

One JSON object per line (plan section 2). Exports: Trace, Event. Standard library only.

A defence that blocks a call records a `defence` event whose `ref` is the step of the call it acted on. A blocked
call does not count as delivered: tool_calls() and outbox() leave it out. A filter that withholds or changes a tool
result records a `defence` event too, with decision "withhold" and blocked False: the call still ran.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

KINDS = ("tool_call", "tool_result", "outbox", "fetch", "render", "reply", "defence")
RESULT_LIMIT = 2000


@dataclass
class Event:
    step: int
    kind: str
    tool: str | None = None
    args: Any = None
    result: Any = None
    text: str | None = None
    ref: int | None = None

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown event kind: {self.kind}")
        if isinstance(self.result, str) and len(self.result) > RESULT_LIMIT:
            self.result = self.result[:RESULT_LIMIT]


@dataclass
class Trace:
    case_id: str
    acting_user: str
    events: list[Event] = field(default_factory=list)

    def add(self, kind: str, **fields: Any) -> Event:
        event = Event(step=len(self.events) + 1, kind=kind, **fields)
        self.events.append(event)
        return event

    def _blocked_steps(self) -> set[int]:
        return {e.ref for e in self.events
                if e.kind == "defence" and isinstance(e.result, dict) and e.result.get("blocked")}

    def _live(self, kind: str) -> list[Event]:
        blocked = self._blocked_steps()
        return [e for e in self.events if e.kind == kind and e.step not in blocked]

    def tool_calls(self, name: str | None = None) -> list[Event]:
        """Tool calls that were not blocked, optionally only those to one tool."""
        return [e for e in self._live("tool_call") if name is None or e.tool == name]

    def outbox(self) -> list[dict]:
        """Accepted send_message calls, as {to, body}."""
        return [{"to": (e.args or {}).get("to"), "body": (e.args or {}).get("body")}
                for e in self._live("outbox")]

    def fetched_urls(self) -> list[str]:
        return [(e.args or {}).get("url") for e in self._live("fetch")]

    def reply_urls(self) -> list[str]:
        """Image URLs the harness recorded as rendered from the reply (`render` events)."""
        return [(e.args or {}).get("url") for e in self._live("render")]

    @property
    def reply(self) -> str:
        replies = [e.text or "" for e in self.events if e.kind == "reply"]
        return replies[-1] if replies else ""

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(asdict(e), ensure_ascii=True, sort_keys=True) for e in self.events) + "\n"

    @classmethod
    def from_jsonl(cls, text: str, case_id: str = "", acting_user: str = "") -> "Trace":
        events = [Event(**json.loads(line)) for line in text.splitlines() if line.strip()]
        return cls(case_id=case_id, acting_user=acting_user, events=events)
