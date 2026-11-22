"""design-dual-llm (chapter 8): the privileged model never reads untrusted text. Every untrusted string in a tool result
is replaced by an opaque reference ($Q1, $Q2, ... numbered per episode), and the only way to learn about one is
ask_quarantined(ref, question). The quarantined model is the same model with no tools and design-quarantined.md as its
system prompt. Its answers come back as a new reference (summary) or as a typed value (the other questions).

A reference's text goes into send_message.body only. A reference anywhere else is refused, with a defence event.

Replay keys: the quarantined calls are keyed (task id, n, "quarantined"), where n counts the ask_quarantined calls of the
episode (not the planner's turns); their rows carry role "quarantined" (lib/replay.py, recordings/assistant.py).
"""
from __future__ import annotations

import datetime
import re
from pathlib import Path

from lib import cases, harness, tools  # lib first: threads and seeds are fixed here

BOOK = Path(__file__).resolve().parents[2]
QUARANTINED = BOOK / "examples" / "prompts" / "design-quarantined.md"
QUESTIONS = ("summary", "unit", "date", "slot_id", "asks_for_visit")
REF = re.compile(r"\$Q\d+")
UNIT = re.compile(r"[1-4][A-H]")  # the case's own units: f"{floor}{letter}" for floor in "1234", letter in "ABCDEFGH" (recordings/make_case.py)
ISO = re.compile(r"\d{4}-\d{2}-\d{2}")
ASK_MAX = 64


def _err(message: str) -> tools.ToolResult:
    return tools.ToolResult({"error": message}, frozenset())


class _Dual:
    def __init__(self, task: cases.Task) -> None:
        self.task = task
        self.refs: dict[str, str] = {}
        self.state: tools.ToolState | None = None
        self.model = None
        self.asks = 0

    def _ref(self, text: str) -> str:
        key = f"$Q{len(self.refs) + 1}"
        self.refs[key] = text
        return key

    def transform(self, segments: list) -> list:
        return segments

    def mask(self, call: dict, result: tools.ToolResult) -> tools.ToolResult:
        """Each untrusted string in the result becomes its reference, under the same field name."""
        def walk(value, key=None):
            if isinstance(value, dict):
                return {k: walk(v, k) for k, v in value.items()}
            if isinstance(value, list):
                return [walk(v, key) for v in value]
            if key in result.untrusted and isinstance(value, str):
                return self._ref(value)
            return value
        return tools.ToolResult(walk(result.data), result.untrusted)

    def check(self, call: dict, state: tools.ToolState) -> harness.Allow | harness.Refuse:
        self.state = state
        state.ask = self._ask  # the episode's quarantined reader, for call_tool
        name, args = call["name"], call["arguments"]
        if name == "ask_quarantined":
            return harness.Allow()
        for key, value in args.items():
            if name == "send_message" and key == "body":
                continue
            if REF.search(str(value)):
                return harness.Refuse(f"a reference may only be a message body, not {key!r}")
        return harness.Allow()

    def expand(self, reply: str) -> str:
        """The final reply's references, expanded for the user. The result is untrusted text: the harness scans it
        with the render policy, as it does any reply."""
        return REF.sub(lambda m: self.refs.get(m.group(0), m.group(0)), reply)

    def resolve(self, call: dict) -> dict:
        args = call["arguments"]
        if call["name"] == "send_message" and isinstance(args.get("body"), str):
            body = REF.sub(lambda m: self.refs.get(m.group(0), m.group(0)), args["body"])
            return {"name": call["name"], "arguments": dict(args, body=body)}
        return call

    def _typed(self, question: str, reply: str):
        if question == "summary":
            return reply or None
        if question == "unit":
            return reply if UNIT.fullmatch(reply) else None
        if question == "date":
            try:
                return reply if ISO.fullmatch(reply) and datetime.date.fromisoformat(reply) else None
            except ValueError:
                return None
        if question == "slot_id":
            return reply if self.state is not None and reply in self.state.slots else None
        return {"true": True, "false": False}.get(reply.lower())  # asks_for_visit

    def _ask(self, args: dict) -> tools.ToolResult:
        ref, question = args.get("ref"), args.get("question")
        if ref not in self.refs:
            return _err(f"unknown reference: {ref}")
        if question not in QUESTIONS:
            return _err(f"unknown question: {question}")
        n = self.asks
        self.asks += 1
        prompt = (QUARANTINED.read_text(encoding="utf-8") + f"\n\nQuestion: {question}\n\nText:\n{self.refs[ref]}\n")
        reply = self.model.complete(prompt, ASK_MAX, key=(self.task.id, n, "quarantined")).strip()
        value = self._typed(question, reply)
        if value is None:
            return _err(f"the answer to {question!r} is not valid")
        if question == "summary":
            return tools.ToolResult({"ref": self._ref(value)}, frozenset())
        return tools.ToolResult({question: value}, frozenset())


def dual_hooks(task: cases.Task, world: cases.World) -> harness.Hooks:
    """design-dual-llm: a fresh reference store per episode. bind gives it the episode's model."""
    dual = _Dual(task)

    def bind(model) -> harness.Hooks:
        dual.model = model
        return hooks

    hooks = harness.Hooks(name="design-dual-llm", transform_input=dual.transform, filter_tool_result=dual.mask,
                          check_call=dual.check, resolve_call=dual.resolve, bind=bind,
                          expand_reply=dual.expand, extra_tools=frozenset({"ask_quarantined"}))
    return hooks
