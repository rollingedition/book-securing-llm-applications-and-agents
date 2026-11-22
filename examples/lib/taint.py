"""Taint labels on values and tool results, with the check a tool call must pass (chapter 8, design-taint).

Exports: Label, Provenance, Tagged, tag(value, provenance), known_values(world, slots), check_call(call, provenance,
known), taint_hooks(task, world).
Introduced in: chapter 8.

This is a TEACHING APPROXIMATION. Each tool result's untrusted text (the fields listed in tools.UNTRUSTED_KEYS) is
kept as a segment with the label of the call that produced it. A string argument carries that label when it matches a
rule: a URL is labelled when its host, or a path or query part, equals or is contained in a token of a segment; any
other string is labelled when a run of MIN_CHARS characters of it appears in a segment. Segments and candidate values
are both case-folded and whitespace-collapsed before matching, so capitals and line breaks do not hide a copy. The
untrusted text of a third-party tool's definition (its description, and each parameter's description; tools.
THIRD_PARTY_TOOLS) is a segment too, labelled with that tool, so a value copied from a tool description is labelled.
The check refuses an outbound call (send_message, fetch_page, book_visit) whose argument is labelled and is
not a typed value from a known set: a tenant or slot ID the world holds, an address in the office directory, a date,
or a unit that matches the unit pattern. A value is tainted if any part of it came from untrusted text.

What this misses, and what CaMeL does instead: a value the model derives or transforms rather than copies is not matched, so a value reworded, assembled from words, spaced, defanged, percent-encoded or base64 gets through. So does any value under MIN_CHARS (8) characters, which is never labelled, and a URL whose host the model splits. A common
phrase that appears in untrusted text is refused wrongly, and that cost grows with the length of the phrase's run. CaMeL
(Debenedetti et al., 2025) does not match strings at all. It translates the request into a restricted program run by
its own interpreter, where every value is a capability whose sources and readers are tracked through each operation,
so a value's origin is known by construction rather than inferred from its text. Its published 77% against 84% is
cited in the chapter, not reproduced here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from . import tools
from .harness import Allow, Hooks, Refuse

OUTBOUND = frozenset({"send_message", "fetch_page", "book_visit"})  # side effects, or data leaving the office
MIN_CHARS = 8  # a run of this many characters of a string argument, found in a segment, is a match
MIN_PART = 4  # a URL part shorter than this ("p", "2F") matches too much of any text to carry a label
URL = re.compile(r"^https?://", re.IGNORECASE)
TOKEN_BREAK = re.compile(r"[\s/?&=#:;,()<>\[\]\"'`]+")
UNIT = re.compile(r"^\d{1,2}[A-Z]$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@dataclass(frozen=True)
class Label:
    source: str  # the tool whose result the text came from
    step: int  # the position of that call in the episode


class Tagged(str):
    """A string value with its label set. The harness builds these for argument strings it can trace."""

    labels: frozenset = frozenset()


@dataclass
class Provenance:
    """The episode's untrusted segments, each with the label of the result it came from."""

    segments: list[tuple[Label, str]] = field(default_factory=list)
    calls: int = 0

    def add_result(self, name: str, result: tools.ToolResult) -> None:
        """Record a result's untrusted strings, as the next step."""
        self.calls += 1
        label = Label(name, self.calls)
        for text in _untrusted_strings(result.data, result.untrusted):
            self.segments.append((label, _norm(text)))

    def add_schemas(self, schemas: tuple[dict, ...]) -> None:
        """Record the untrusted text of each third-party tool's definition, labelled with that tool at step 0."""
        for schema in schemas:
            function = schema.get("function", schema)
            name = function.get("name")
            if name not in tools.THIRD_PARTY_TOOLS:
                continue
            for text in _descriptions(function):
                self.segments.append((Label(name, 0), _norm(text)))

    def labels(self, value: Any) -> frozenset:
        """The labels of the segments the value takes text from (see the module docstring for the rule)."""
        if not isinstance(value, str):
            return frozenset()
        if URL.match(value):
            return self._url_labels(value)
        text = _norm(value)
        if len(text) < MIN_CHARS:
            return frozenset()
        runs = {text[i:i + MIN_CHARS] for i in range(len(text) - MIN_CHARS + 1)}
        return frozenset(label for label, seg in self.segments if any(run in seg for run in runs))

    def _url_labels(self, url: str) -> frozenset:
        parts = urlsplit(url)
        pieces = [parts.hostname or ""] + [p for p in parts.path.split("/") if p]
        pieces += [q for part in parts.query.split("&") for q in part.split("=") if q]
        pieces = [_norm(p) for p in pieces if len(p) >= MIN_PART]
        out = set()
        for label, seg in self.segments:
            tokens = [t for t in TOKEN_BREAK.split(seg) if t]
            if any(piece in token for piece in pieces for token in tokens):
                out.add(label)
        return frozenset(out)


def _norm(text: str) -> str:
    return " ".join(text.casefold().split())


def _descriptions(value: Any) -> list[str]:
    """Every string under a "description" key of a tool definition, at any depth."""
    if isinstance(value, dict):
        return [v for k, v in value.items() if k == "description" and isinstance(v, str)] + [
            s for v in value.values() for s in _descriptions(v)]
    if isinstance(value, list):
        return [s for v in value for s in _descriptions(v)]
    return []


def _untrusted_strings(value: Any, untrusted: frozenset, key: str | None = None) -> list[str]:
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in _untrusted_strings(v, untrusted, str(k))]
    if isinstance(value, list):
        return [s for v in value for s in _untrusted_strings(v, untrusted, key)]
    return [value] if key in untrusted and isinstance(value, str) else []


def tag(value: Any, provenance: Provenance) -> Any:
    """The value as a Tagged string if it carries labels, else the value itself."""
    labels = provenance.labels(value)
    if not labels:
        return value
    out = Tagged(value)
    out.labels = labels
    return out


def known_values(world: Any, slots: dict) -> frozenset[str]:
    """The typed values the check accepts as they are: tenant IDs, slot IDs and the office directory."""
    return frozenset({t.id for t in world.tenants} | set(slots) | tools.directory())


def _typed(value: str, known: frozenset[str]) -> bool:
    return value in known or bool(DATE.match(value) or UNIT.match(value))


def check_call(call: dict, provenance: Provenance, known: frozenset[str]) -> Allow | Refuse:
    """Refuse an outbound call with a labelled argument that is not a typed value from a known set."""
    name, args = call.get("name"), call.get("arguments")
    if name not in OUTBOUND or not isinstance(args, dict):
        return Allow()
    for key, value in args.items():
        labels = provenance.labels(value)
        if labels and not _typed(value, known):
            source = min(labels, key=lambda label: (label.step, label.source))  # a tie on step is broken by name, not set order
            return Refuse(f"{name}.{key}: the value comes from the result of {source.source} (untrusted), and is not "
                          "a typed value from a known set")
    return Allow()


def taint_hooks(task: Any, world: Any) -> Hooks:
    """design-taint: a fresh provenance per episode. Results are recorded as they arrive; calls are checked."""
    provenance = Provenance()
    seeded = []  # the episode's tool definitions are read once, at its first check

    def record(call: dict, result: tools.ToolResult) -> tools.ToolResult:
        provenance.add_result(call["name"], result)
        return result

    def check(call: dict, state: tools.ToolState) -> Allow | Refuse:
        if not seeded:
            provenance.add_schemas(state.schemas)
            seeded.append(True)
        return check_call(call, provenance, known_values(world, state.slots))

    return Hooks(name="design-taint", filter_tool_result=record, check_call=check)
