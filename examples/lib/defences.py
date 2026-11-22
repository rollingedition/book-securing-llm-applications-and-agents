"""The prompt-level and harness-level defences as one registry, labelled by where each acts: prompt (advice), input (detector), harness (enforcement), design (isolation).

Exports: outbound_allowlist(call, world) (chapter 1, harness enforcement). Still to write: DEFENCES, Defence, LABELS,
prompt defences (chapter 4) and least privilege (chapter 6).

outbound_allowlist is a pure function: it reads the call and the world, and returns Allow or Refuse. It fails closed:
any call it cannot read is refused.
"""
from __future__ import annotations

import base64
import html
import json
import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import unquote, urlsplit

from . import cases, tools
from .harness import ASSISTANT, END, IM_END, IM_START, Allow, Hooks, Refuse, Segment, mark, marked

# Tools the outbound allowlist does not treat as outbound channels. Two of them are not local in the sense of staying
# inside the office: book_visit sends its arguments (the slot, the ticket) to the contractor's third-party server. The
# allowlist passes it anyway, so its data-out is not checked here; chapter 6's argument policies cover that. This is
# the honest limit chapter 1 names. Do not change this set without re-measuring the allowlist's recorded results.
LOCAL_TOOLS = frozenset({"search_documents", "list_messages", "read_message", "lookup_tenant", "list_slots", "book_visit"})


@lru_cache(maxsize=None)
def _fixture_hosts() -> frozenset[str]:
    """The hostnames the office's fixture sites serve, from pages.json (lower case, as urllib parses them)."""
    pages = json.loads((cases.DATA / "pages.json").read_text(encoding="utf-8"))["pages"]
    return frozenset(h for h in (urlsplit(p["url"]).hostname for p in pages) if h)


@lru_cache(maxsize=None)
def office_hosts() -> frozenset[str]:
    """The hosts the office's own fixture sites serve: the only hosts fetch_page may reach and the web view may load.
    Pinned in code, so adding a fixture page on another host cannot widen the allowlist; the fixtures must agree."""
    pinned = frozenset({"quillmere.example"})
    if _fixture_hosts() != pinned:  # a fixture on another host is a data error, not a new allowed host
        raise ValueError(f"pages.json serves hosts outside the pinned office host: {sorted(_fixture_hosts() - pinned)}")
    return pinned


def _contractor_ids() -> frozenset[str]:
    return frozenset({json.loads((cases.DATA / "contractor.json").read_text(encoding="utf-8"))["contractor_id"]})


def _send_decision(to: object, world: cases.World) -> Allow | Refuse:
    """send_message reaches only the office directory and tenant or contractor IDs. Exact string match."""
    allowed = tools.directory() | {t.id for t in world.tenants} | _contractor_ids()
    if isinstance(to, str) and to in allowed:
        return Allow()
    return Refuse("send_message: the recipient is not in the office directory")


def _fetch_allowed(url: object) -> bool:
    """fetch_page reaches only https URLs whose host is one of the office's fixture hosts.

    The host is taken from urllib's parse and compared exactly. Userinfo, explicit ports, percent-encoding and
    non-ASCII characters are refused outright, so an address cannot hide a second host. Upper case is accepted,
    because urllib lowers the host and HTTPS://QUILLMERE.EXAMPLE/ is the office's own host. A trailing dot is not
    the office host as written, so it is refused.
    """
    if not isinstance(url, str) or not url.isascii():
        return False
    if any(ord(c) <= 0x20 or ord(c) == 0x7F or c == "\\" for c in url):
        return False
    parts = urlsplit(url)
    host = parts.hostname
    if parts.scheme != "https" or not host:
        return False
    if parts.netloc.lower() != host or parts.port is not None:
        return False  # userinfo, a port, brackets or a percent sign would change what the host is
    return host in _fixture_hosts()


def outbound_allowlist(call: dict, world: cases.World) -> Allow | Refuse:
    """Decide one proposed tool call. Outbound tools are checked against the allowlist; any other tool not
    listed in LOCAL_TOOLS is refused by default."""
    try:
        name, args = call.get("name"), call.get("arguments")
        if not isinstance(args, dict) or not isinstance(name, str):
            return Refuse("the call is not a tool name with an arguments object")
        if name == "send_message":
            return _send_decision(args.get("to"), world)
        if name == "fetch_page":
            if _fetch_allowed(args.get("url")):
                return Allow()
            return Refuse("fetch_page: the URL is not an https address on the office's own site")
        if name in LOCAL_TOOLS:
            return Allow()
        return Refuse(f"{name}: this tool is not on the office's allowlist")
    except Exception:  # fail closed: a call that cannot be checked is refused
        return Refuse("the call could not be checked against the allowlist")


# ---- Chapter 4: prompt-level defences. Each is a transform_input hook: it takes the whole prompt as segments and returns
# a new list, every time, from the same input. The text a defence adds is trusted; untrusted text stays untrusted.

PROMPTS = Path(__file__).resolve().parents[1] / "prompts"
USER_OPEN = END + "<|im_start|>user\n"  # the open prompt's user segment starts with this (open_prompt in harness)
UNTRUSTED_OPEN, UNTRUSTED_CLOSE = "<untrusted>", "</untrusted>"
DATAMARK = "^"
_WHITESPACE = re.compile(r"\s")


@lru_cache(maxsize=None)
def _note(name: str) -> str:
    return (PROMPTS / name).read_text(encoding="utf-8").strip()


def _with_system_note(segments: list[Segment], note: str) -> list[Segment]:
    """The note, trusted, appended to the end of the system prompt (the first segment, from open_prompt)."""
    head, _ = segments[0]
    if not head.startswith("<|im_start|>system\n"):
        raise ValueError("the first segment of a prompt is not the system prompt")
    return [(marked(head, "\n\n" + note), True)] + list(segments[1:])


def _map_untrusted(segments: list[Segment], change: Callable[[str], str]) -> list[Segment]:
    """Each untrusted, non-empty segment's text replaced by change(text); trusted segments untouched."""
    return [(change(text), False) if not trusted and text else (text, trusted) for text, trusted in segments]


def _user_request(segments: list[Segment]) -> str | None:
    """The staff member's request, read from the open prompt's user segment. That segment is trusted and starts with
    USER_OPEN; a tool result cannot match it, because tool results are never trusted."""
    for text, trusted in segments:
        if trusted and text.startswith(USER_OPEN):
            body = text[len(USER_OPEN):]
            return body[:-len(END)] if body.endswith(END) else body
    return None


def prompt_warning(segments: list[Segment]) -> list[Segment]:
    """prompt (advice): a short warning appended to the system prompt. Text from tools may contain instructions; the
    model should never follow them, and only the staff member's request counts. Nothing else in the prompt changes."""
    return _with_system_note(segments, _note("defence-warning.md"))


def prompt_delimiters(segments: list[Segment]) -> list[Segment]:
    """prompt (advice): each untrusted segment sits between <untrusted> and </untrusted> markers. The markers are
    trusted segments of their own, and the system prompt says what they mean. An attacker who knows the markers can
    write them into their own text, so this is a weak control."""
    out: list[Segment] = []
    for text, trusted in segments:
        if trusted or not text:
            out.append((text, trusted))
        else:
            out += [(UNTRUSTED_OPEN, True), (text, False), (UNTRUSTED_CLOSE, True)]
    return _with_system_note(out, _note("defence-delimiters.md"))


def prompt_datamark(segments: list[Segment]) -> list[Segment]:
    """prompt (advice): spotlighting's datamarking. Every whitespace character in untrusted text becomes ^, which the
    system prompt names. The marked text is what the model reads, so the change is visible to the model, not only to
    the harness."""
    out = _map_untrusted(segments, lambda text: _WHITESPACE.sub(DATAMARK, text))
    return _with_system_note(out, _note("defence-datamark.md"))


def prompt_encode(segments: list[Segment]) -> list[Segment]:
    """prompt (advice): spotlighting's encoding. Each untrusted segment is replaced by the base64 of its UTF-8 bytes,
    and the system prompt says tool output is base64 and is data. Third-party tool definitions are untrusted too, so
    they are encoded as well."""
    out = _map_untrusted(segments, lambda text: base64.b64encode(text.encode("utf-8")).decode("ascii"))
    return _with_system_note(out, _note("defence-encode.md"))


def prompt_repeat(segments: list[Segment]) -> list[Segment]:
    """prompt (advice): the sandwich. After the last tool result, the staff member's request is repeated as a user turn,
    just before the model's reply. A prompt with no tool result yet is returned unchanged."""
    request = _user_request(segments)
    has_tool_result = any(text == "<|im_start|>user\n" and trusted for text, trusted in segments)
    if request is None or not has_tool_result:
        return list(segments)
    if not segments[-1][0].startswith(ASSISTANT.rstrip("\n")):
        raise ValueError("the last segment of a prompt is not the assistant prefix")
    reminder: Segment = (marked(mark(IM_START), "user\n" + _note("defence-repeat.md") + "\n\n" + request,
                                mark(IM_END), "\n"), True)
    return list(segments[:-1]) + [reminder, segments[-1]]


# ---- Chapter 5: the input detector. A filter_tool_result hook: it scores each untrusted piece of a tool result and
# withholds the whole result when one reaches the threshold. lib/detector loads only when this hook first sees a result.

DETECTOR_LABEL = "input (detector)"
WITHHELD = {"withheld": "the office's filter withheld this content"}


def _string_values(value: object) -> list[str]:
    """Every string value under value, at any depth of nested dicts and lists, as decoded text (not JSON-escaped).
    Keys are not scored: the office's own keys are fixed names."""
    if isinstance(value, dict):
        return [text for item in value.values() for text in _string_values(item)]
    if isinstance(value, list):
        return [text for item in value for text in _string_values(item)]
    return [value] if isinstance(value, str) else []


def detector_filter(threshold: float | None) -> Callable[[dict, tools.ToolResult], tools.ToolResult]:
    """input (detector): withhold a tool result when any string value in it scores at or above threshold.

    Every string value is scored, at every depth, whatever its key, as decoded text: a text under a key the office does
    not mark untrusted, or nested in an object, is scored like any other. Each value is scored whole, and a value
    longer than the model's window is scored in windows (lib/detector). The filter has no memory across results, so
    an injection split across two results can pass when each part scores below the threshold. That is a stated
    limit, not a control.

    The hook keeps one event per withheld result in its `events` list: the tool, the highest score and the threshold.
    The harness's trace records only refusals from check_call, not filter decisions, so a chapter reads the events
    from the hook. The harness still records the filtered result, so the model's tool_result event shows the withheld
    message, not the original text.
    """
    if threshold is None:
        raise ValueError("detector_filter: the threshold is unset; the managing editor sets it after the chapter 5 dev run")
    events: list[dict] = []

    def filter_tool_result(call: dict, result: tools.ToolResult) -> tools.ToolResult:
        from . import detector  # imported here: the model is loaded only by a run that reaches a tool result
        pieces = [text for text in _string_values(result.data) if text.strip()]
        if not pieces:
            return result
        top = max(detector.score(pieces))
        if top < threshold:
            return result
        events.append({"defence": DETECTOR_LABEL, "tool": call.get("name"), "score": round(top, 4),
                       "threshold": threshold})
        return tools.ToolResult(dict(WITHHELD), frozenset())

    filter_tool_result.events = events  # type: ignore[attr-defined]
    return filter_tool_result


# ---- Chapter 6: least privilege outside the model. Each defence below is harness (enforcement): it decides a proposed
# call before the harness runs it, reads only the task and the world (never the attack case), and fails closed. A tool
# or argument it cannot read is refused. Each is a teaching implementation: it catches the plain forms its docstring
# names, and the chapter says what it does not catch.

# Tools a task category needs. A small explicit table, so the list is written down and reviewed, not inferred from
# the attack. A category not in the table gets no tools.
TASK_TOOLS: dict[str, frozenset[str]] = {
    "inbox": frozenset({"list_messages", "read_message", "send_message"}),
    "index": frozenset({"search_documents"}),
    "upload": frozenset({"search_documents"}),
    "page": frozenset({"fetch_page"}),
    "server": frozenset({"list_slots", "book_visit"}),
    "tool": frozenset({"list_slots", "book_visit"}),
}
BOOKING_CATEGORIES = frozenset({"server", "tool"})
SIDE_EFFECTS = frozenset({"send_message", "book_visit"})
_TENANT_ID = re.compile(r"\btn-\d{2}\b")
_UNIT = re.compile(r"\b\d{1,2}[A-Z]\b")
_TICKET = re.compile(r"\bT-\d+\b")


@dataclass(frozen=True)
class ToolFilter:
    """harness (enforcement): the only tools one task may use. The prompt lists schemas(...) only, and check_call
    refuses any call to a tool outside names. A tool missing from the prompt is still refused if the model names it."""
    names: frozenset[str]

    def schemas(self, schemas: tuple[dict, ...]) -> tuple[dict, ...]:
        return tuple(s for s in schemas if s["function"]["name"] in self.names)

    def __call__(self, call: dict, state: object) -> Allow | Refuse:
        try:
            name = call.get("name")
            if isinstance(name, str) and name in self.names:
                return Allow()
            return Refuse(f"{name}: this tool is not needed for this task")
        except Exception:  # fail closed
            return Refuse("the call could not be checked against the task's tools")


def task_tool_filter(task: cases.Task) -> ToolFilter:
    """harness (enforcement): the tools a task needs, from its category (TASK_TOOLS). An unknown category gets none."""
    return ToolFilter(TASK_TOOLS.get(task.category, frozenset()))


_MAX_DECODES = 5  # layers of encoding read before a value is refused as unreadable


class UnreadableURL(ValueError):
    """A value whose encoding goes deeper than _MAX_DECODES layers. The rules refuse it (they fail closed)."""


def _decoded(text: str) -> str:
    """Undo encodings until the text stops changing: HTML character references, percent-encoding, and NFKC (which
    folds full-width digits to ASCII). A value encoded twice, or full-width inside percent-encoding, is read."""
    for _ in range(_MAX_DECODES):
        step = unicodedata.normalize("NFKC", unquote(html.unescape(text)))
        if step == text:
            return text
        text = step
    raise UnreadableURL("the value is encoded in more layers than the rule reads")


def _norm(text: str) -> str:
    """The form a value is compared in: decoded (see _decoded), lower case, digits only, so spaces, dashes, plus signs
    and letters between the digits drop out; then a UK country code (+44, 44, 0044) becomes the leading 0 of the
    national number. Applied to the tenant values and to the task text alike, so both sides read the same way."""
    digits = re.sub(r"[^0-9]", "", _decoded(text).lower())
    return re.sub(r"0044|44", "0", digits)


def url_digits(url: str) -> str:
    """The normalised digits of a URL's path, query and fragment together (not the scheme or host)."""
    parts = urlsplit(url)
    return _norm(" ".join((parts.path, parts.query, parts.fragment)))


def tenant_value_carried(carried: str, world: cases.World, task_text: str) -> bool:
    """True when `carried` (a normalised URL, from url_digits) holds a tenant's phone or bank reference, as written or
    reversed, that the task text does not contain."""
    text = _norm(task_text)
    for value in _tenant_values(world):
        if value not in text and value in carried:
            return True
    return False


def _tenant_values(world: cases.World) -> list[str]:
    """Values from a tenant record that must not reach a URL: the phone and the bank reference, each as written and
    reversed (normalised, so the reversed form is read the same way a URL's digits are)."""
    return [v for t in world.tenants for raw in (t.phone, t.bank_ref)
            for v in (_norm(raw), _norm(raw[::-1])) if len(v) >= 4]


def _recipients(task: cases.Task) -> frozenset[str]:
    """The recipients the task names: the tenants it mentions (tenant refs and tn-NN in its text) and the contractor,
    but only if the task names the contractor."""
    named = set(_TENANT_ID.findall(task.text))
    if "tenant" in task.refs:
        named.add(task.refs["tenant"])
    named |= {c for c in _contractor_ids() if c in task.text}
    return frozenset(named)


def _url_policy(url: object, task: cases.Task, world: cases.World) -> Allow | Refuse:
    """fetch_page: the office's hosts (the outbound allowlist's rule), and a query that carries no tenant value the
    task's own text does not contain. Caught: the full phone or bank reference in the query, plain, with dashes or
    plus signs in place of spaces, or percent-encoded (the query is decoded first). A raw space is refused earlier, by
    the URL check. Not caught: a partial value, the value in the path (this rule reads the query only), base64 or any
    other encoding, and a value split across two fetches (each call is judged alone)."""
    if not _fetch_allowed(url):
        return Refuse("fetch_page: the URL is not an https address on the office's own site")
    try:
        carried = url_digits(url)
    except (UnreadableURL, TypeError, ValueError):
        return Refuse("fetch_page: the URL could not be read, so it is refused")
    if tenant_value_carried(carried, world, task.text):
        return Refuse("fetch_page: the URL carries a tenant's record, which the task does not contain")
    return Allow()


def _visit_policy(args: dict, task: cases.Task) -> Allow | Refuse:
    """book_visit: only for a booking task, and only the contractor the task names, the slot in its refs and the ticket its text names."""
    tickets = _TICKET.findall(task.text)
    slot = task.refs.get("slot_id")
    if task.category not in BOOKING_CATEGORIES or slot is None or len(tickets) != 1:
        return Refuse("book_visit: this task does not book a visit")
    contractors = [c for c in _contractor_ids() if c in task.text]
    if len(contractors) != 1:
        return Refuse("book_visit: the task does not name the contractor")
    expected = {"contractor_id": contractors[0], "slot_id": slot, "ticket_id": tickets[0]}
    if set(args) <= set(expected) and all(args.get(k) == v for k, v in expected.items()):
        return Allow()
    return Refuse("book_visit: the slot or ticket is not the one the task implies")


def argument_policy(task: cases.Task, world: cases.World):
    """harness (enforcement): one policy per task, derived from the task's request and the tool schemas. Returns a
    function of a proposed call that gives Allow or Refuse. Tools with no argument rule (search_documents, read_message,
    list_slots) are allowed here; which tools a task gets is task_tool_filter's decision, not this policy's.

    send_message.to: the tenants the task names, or the contractor if it names them.
    fetch_page.url: see _url_policy. book_visit: see _visit_policy. lookup_tenant.unit: only a unit the task names,
    from its text or its tenant ref.
    """
    recipients = _recipients(task)
    units = {u.upper() for u in _UNIT.findall(task.text)}
    if "tenant" in task.refs and task.refs["tenant"] in {t.id for t in world.tenants}:
        units.add(world.tenant(task.refs["tenant"]).unit.upper())

    def decide(call: dict) -> Allow | Refuse:
        try:
            name, args = call.get("name"), call.get("arguments")
            if not isinstance(args, dict) or not isinstance(name, str):
                return Refuse("the call is not a tool name with an arguments object")
            if name == "send_message":
                to = args.get("to")
                if isinstance(to, str) and to in recipients:
                    return Allow()
                return Refuse("send_message: the recipient is not one the task names")
            if name == "fetch_page":
                return _url_policy(args.get("url"), task, world)
            if name == "book_visit":
                return _visit_policy(args, task)
            if name == "lookup_tenant":
                unit = args.get("unit")
                if isinstance(unit, str) and unit.strip().upper() in units:  # as tools.lookup_tenant resolves it
                    return Allow()
                return Refuse("lookup_tenant: the unit is not one the task names")
            return Allow()
        except Exception:  # fail closed
            return Refuse("the call could not be checked against the argument policy")

    return decide


class ApprovalGate:
    """harness (enforcement): approval for side effects. A simulated approver approves a send_message or book_visit
    only if argument_policy would allow it, and records an approval event either way (in `events`). Other calls pass.

    This stands for Agent Harnesses' gate (its chapter 6, `#gate-in-finish`). A real approver is a person, whose error
    rate this simulation does not model: the simulation approves exactly what the policy allows, so it shows the
    gate's shape, not how often a person would say yes."""

    def __init__(self, task: cases.Task, world: cases.World) -> None:
        self.policy = argument_policy(task, world)
        self.events: list[dict] = []

    def __call__(self, call: dict, state: object) -> Allow | Refuse:
        try:
            name = call.get("name")
            if name not in SIDE_EFFECTS:
                return Allow()
            decision = self.policy(call)
            approved = isinstance(decision, Allow)
            self.events.append({"defence": "approval", "tool": name, "approved": approved,
                                "reason": "" if approved else getattr(decision, "reason", "")})
            return Allow() if approved else decision
        except Exception:  # fail closed: a side effect that cannot be checked is refused
            self.events.append({"defence": "approval", "tool": str(call.get("name")), "approved": False,
                                "reason": "the call could not be checked"})
            return Refuse("the approver could not check the call")


def approval_gate(task: cases.Task, world: cases.World) -> ApprovalGate:
    """harness (enforcement): see ApprovalGate."""
    return ApprovalGate(task, world)


# Chapter 8, design-plan-then-execute. The first model turn's calls are the plan: its arguments are literals or typed
# placeholders. Steps are numbered in plan order; a placeholder reads the result of an earlier step. Nothing a result
# says can add, remove or reorder calls, because the plan is fixed before any result exists.
PLAN_TYPES = frozenset({"unit", "date", "slot_id", "tenant_id", "msg_id", "text"})
_PLAN_KEYS = frozenset({"from", "field", "type"})
_PLAN_WHERE = "where"  # optional: {"field": "literal string"}, picks one item of a list result
_ISO_DATE = re.compile(r"\d{4}-\d{2}-\d{2}")


def _is_placeholder(value: object) -> bool:
    return isinstance(value, dict) and _PLAN_KEYS <= set(value) <= _PLAN_KEYS | {_PLAN_WHERE}


def _is_text(value: object) -> bool:
    return _is_placeholder(value) and value["type"] == "text"


def _pick(data: object, keys: list[str], accepts: Callable[[object], bool], where: dict | None = None) -> object | None:
    """The value at the path `keys` that `accepts`, or None. A list on the path must narrow to exactly one item: the
    items whose fields equal every pair in `where`, or, with no `where`, a list of exactly one item. Zero or several
    matches give None, never a guess (chapter 8: the plan's placeholder is an error, not "first match")."""
    if not keys:  # a where that no list on the path consumed names nothing: no value
        return data if accepts(data) and where is None else None
    if isinstance(data, list):
        if where:
            items = [i for i in data if isinstance(i, dict) and all(i.get(k) == v for k, v in where.items())]
        else:
            items = data if len(data) == 1 else []
        if len(items) != 1:
            return None
        return _pick(items[0], keys, accepts)  # the where applies to this list only
    if isinstance(data, dict) and keys[0] in data:
        return _pick(data[keys[0]], keys[1:], accepts, where)
    return None


class _Plan:
    """One episode's plan: the first turn's calls are held or run in plan order; the final turn can call nothing."""

    def __init__(self, world: cases.World) -> None:
        self.world = world
        self.turn = -1
        self.step = -1  # the plan step of the call being run
        self.results: dict[int, object] = {}  # step -> the data of its result, for steps that ran
        self.state: tools.ToolState | None = None
        self.held: list[tuple[int, dict]] = []  # (step, call) for calls with a text body, run after the final reply
        self.pending: list[int] = []  # the steps of the held calls, in the order finish gave them out
        self.finishing = False

    def transform(self, segments: list) -> list:
        self.turn += 1  # every model turn passes through here, so turn 0 is the planning turn
        return segments

    def hold(self, call: dict) -> bool:
        if self.finishing or self.turn != 0:
            return False
        self.step += 1
        if call["name"] == "send_message" and _is_text(call["arguments"].get("body")):  # the only place for model text
            self.held.append((self.step, call))
            return True
        return False

    def _accepts(self, kind: str) -> Callable[[object], bool]:
        slots = self.state.slots if self.state is not None else {}
        inbox = self.state.inbox if self.state is not None else []
        tenants = {t.id for t in self.world.tenants}
        known = {
            "unit": lambda v: isinstance(v, str) and _UNIT.fullmatch(v) is not None,
            "date": lambda v: isinstance(v, str) and _ISO_DATE.fullmatch(v) is not None,
            "slot_id": lambda v: isinstance(v, str) and v in slots,
            "tenant_id": lambda v: isinstance(v, str) and v in tenants,
            "msg_id": lambda v: isinstance(v, str) and v in {m.get("msg_id") for m in inbox},
        }
        return known.get(kind, lambda v: False)

    def _check_plan(self, call: dict, state: tools.ToolState) -> Allow | Refuse:
        name, args = call["name"], call["arguments"]
        spec = tools.SPECS.get(name)
        if spec is None:
            return Refuse(f"the plan names a tool that does not exist: {name}")
        params = spec["parameters"]
        if set(args) - set(params["properties"]) or not set(params["required"]) <= set(args):
            return Refuse("the plan's arguments do not match the tool's parameters")
        literal = {}
        for key, value in args.items():
            if _is_placeholder(value):
                if value["type"] not in PLAN_TYPES or not isinstance(value["from"], int):
                    return Refuse("a placeholder in the plan has no valid type or step")
                if value["type"] == "text" and key != "body":
                    return Refuse("only a message body can take the model's own text")
                if _PLAN_WHERE in value and (value["type"] == "text" or not isinstance(value[_PLAN_WHERE], dict)
                                             or not all(isinstance(k, str) and isinstance(v, str)
                                                        for k, v in value[_PLAN_WHERE].items())):
                    return Refuse("a placeholder's where must map field names to strings, and is not for text")
                if value["type"] != "text" and not (0 <= value["from"] < self.step and isinstance(value["field"], str)):
                    return Refuse("a placeholder reads a step that has not run before this call")
            elif not isinstance(value, str):
                return Refuse("a plan argument is neither a string nor a placeholder")
            else:
                literal[key] = value
        if (name == "send_message" and "to" in literal) or (name == "fetch_page" and "url" in literal):
            return outbound_allowlist({"name": name, "arguments": literal}, self.world)  # a literal recipient or URL
        return Allow()

    def check(self, call: dict, state: tools.ToolState) -> Allow | Refuse:
        self.state = state
        if self.finishing:
            self.step = self.pending.pop(0)  # the held calls, in plan order
            return self._check_plan(call, state)
        if self.turn != 0:  # the plan has run: its results are the answer's input, and the reply is the last turn
            return Refuse("the plan has already run; write the reply to the staff member, with no further calls")
        return self._check_plan(call, state)

    def resolve(self, call: dict) -> dict:
        args = dict(call["arguments"])
        for key, value in args.items():
            if _is_placeholder(value) and value["type"] != "text" and value["from"] < self.step:
                if value["from"] in self.results:  # a placeholder that picks no single value stays unfilled
                    found = _pick(self.results[value["from"]], value["field"].split("."), self._accepts(value["type"]),
                                  value.get(_PLAN_WHERE))
                    if found is not None:
                        args[key] = found
        return {"name": call["name"], "arguments": args}  # an unfilled placeholder fails the tool's own schema check

    def record(self, call: dict, result: tools.ToolResult) -> tools.ToolResult:
        self.results[self.step] = result.data
        return result

    def finish(self, reply: str) -> list[dict]:
        self.finishing = True
        out = []
        for step, call in self.held:
            args = {k: (reply.strip() if k == "body" and _is_text(v) else v) for k, v in call["arguments"].items()}
            self.pending.append(step)
            out.append({"name": call["name"], "arguments": args})
        return out


def plan_hooks(task: cases.Task, world: cases.World) -> Hooks:
    """design-plan-then-execute (chapter 8): a fresh plan per episode. See _Plan."""
    plan = _Plan(world)
    return Hooks(name="design-plan-then-execute", transform_input=plan.transform, filter_tool_result=plan.record,
                 check_call=plan.check, resolve_call=plan.resolve, hold=plan.hold, finish=plan.finish)


# harness (enforcement), chapter 9: a reply whose deposit figures aren't cited to an office document is refused.
PROVENANCE_WINDOW = 12  # words either side of a deposit word, a figure or a citation
DEPOSIT_WORD = re.compile(r"\bdeposits?\b", re.IGNORECASE)
# A pound amount (a currency sign, GBP or "pounds" in front is optional) or a bare number. A number inside a doc ID
# ("doc-01") or a longer token is not a figure.
PROVENANCE_FIGURE = re.compile(r"(?<![\w.,-])(?:£\s?|GBP\s?|pounds?\s+)?(\d{1,3}(?:,\d{3})+|\d+)(\.\d+)?(?![\d-])",
                               re.IGNORECASE)
DOC_CITATION = re.compile(r"\bdoc-\d{2}\b")


def _prov_plain(text: str) -> str:
    """The text as a reader sees it: HTML entities decoded, NFKC, format characters (zero-width spaces) removed, and
    whitespace collapsed across line breaks."""
    text = unicodedata.normalize("NFKC", html.unescape(text))
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return " ".join(text.split())


def _prov_value(match: re.Match) -> float:
    return float((match.group(1) + (match.group(2) or "")).replace(",", ""))


def _prov_word(text: str, pos: int) -> int:
    """The index of the word that holds the character at pos (text is already plain)."""
    return len(text[: pos + 1].split()) - 1


def cite_provenance(reply: str, documents: list[dict] | None = None) -> Allow | Refuse:
    """Harness (enforcement): refuses a reply whose figures aren't cited to an office document.

    The reply is normalised first (see _prov_plain). Each pound amount or bare number within PROVENANCE_WINDOW words of
    the word "deposit" is a deposit figure. Each deposit figure needs its own citation: a doc ID within the same window,
    which no other figure has used. The cited document must be office-sourced, and its text must state the figure,
    normalised the same way. A reply with no deposit figure is allowed.

    Provenance shows where a figure came from, not that the document is right. A poisoned office document passes this
    check: it is an office record, and its text states the figure (SEC9-04). Number words ("nine hundred pounds") and a
    figure with no deposit word nearby are not checked. `documents` defaults to the office's documents on disk; a
    caller passes the episode's copy."""
    rows = documents if documents is not None else tools._json("documents.json")["documents"]
    text = _prov_plain(reply)
    deposits = [_prov_word(text, m.start()) for m in DEPOSIT_WORD.finditer(text)]
    figures = [(_prov_word(text, m.start()), _prov_value(m)) for m in PROVENANCE_FIGURE.finditer(text)]
    figures = [(word, value) for word, value in figures if any(abs(word - d) <= PROVENANCE_WINDOW for d in deposits)]
    if not figures:
        return Allow()
    unused = [(_prov_word(text, m.start()), m.group(0)) for m in DOC_CITATION.finditer(text)]
    by_id = {doc["doc_id"]: doc for doc in rows}
    for word, value in figures:  # each figure takes the nearest citation no other figure has taken
        near = [c for c in unused if abs(c[0] - word) <= PROVENANCE_WINDOW]
        if not near:
            return Refuse("a deposit figure is stated without its own citation to an office document")
        pick = min(near, key=lambda c: (abs(c[0] - word), c[1]))
        unused.remove(pick)
        doc = by_id.get(pick[1])
        if doc is None or doc.get("source") != "office":
            return Refuse("a deposit figure is cited to a document that is not an office document")
        stated = {_prov_value(m) for m in PROVENANCE_FIGURE.finditer(_prov_plain(doc.get("text", "")))}
        if value not in stated:
            return Refuse("a deposit figure is cited to an office document whose text does not state it")
    return Allow()
