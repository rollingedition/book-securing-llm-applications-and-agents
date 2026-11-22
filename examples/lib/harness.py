"""The agent loop: the Qwen3 ChatML prompt built from segments, model calls, tool calls, and the reply.

Exports: run_episode, Hooks, NO_HOOKS, Allow, Refuse, prompt_text, prompt_sha256, to_tokens, system_text, tools_block.

A prompt is a list of segments (text, trusted). Tool results carry their untrusted text as segments of their own. The
model decides how to tokenise them (see to_tokens): the baseline parses control tokens everywhere, the chapter 6 fix
does not parse them in untrusted segments. A model is anything with
    complete(prompt_segments, max_tokens, key=(item_id, turn)) -> str
and the harness calls it once per model turn, at most MAX_TURNS times per episode.

Defence hooks are no-ops by default (Hooks): transform_input (prompt level), filter_tool_result (detectors) and
check_call (harness enforcement; a Refuse is fed back to the model as a tool result and recorded as a defence event).
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Callable

from . import tools
from .cases import World
from .scorers import rendered_urls
from .trace import Trace

Segment = tuple[str, bool]
MAX_TURNS = 6
ASSISTANT = "<|im_start|>assistant\n"
END = "<|im_end|>\n"
IM_START, IM_END = "<|im_start|>", "<|im_end|>"


class Built(str):
    """Text the harness wrote. It is a str that also records where the harness's own chat markers sit: `marks` holds
    (start, end) offsets. Only those spans may become control tokens (see to_tokens); the rest is always plain text."""
    marks: tuple[tuple[int, int], ...] = ()


def mark(text: str) -> tuple[str, bool]:
    """A piece the harness inserts as a chat marker (IM_START or IM_END)."""
    return (text, True)


def marked(*pieces: str | tuple[str, bool]) -> Built:
    """Join pieces into one Built text. A plain str is ordinary text; a mark() piece is a harness marker. A Built
    piece keeps its own marks, shifted to its place in the result."""
    text, marks = "", []
    for piece in pieces:
        if isinstance(piece, Built):
            marks += [(len(text) + a, len(text) + b) for a, b in piece.marks]
            text += str(piece)
        elif isinstance(piece, tuple):
            marks.append((len(text), len(text) + len(piece[0])))
            text += piece[0]
        else:
            text += piece
    out = Built(text)
    out.marks = tuple(marks)
    return out
CALL = re.compile(r"<tool_call>\s*(.*?)\s*(?:</tool_call>|\Z)", re.S)


@dataclass(frozen=True)
class Allow:
    pass


@dataclass(frozen=True)
class Refuse:
    reason: str


def _no_transform(segments: list[Segment]) -> list[Segment]:
    return segments


def _no_filter(call: dict, result: tools.ToolResult) -> tools.ToolResult:
    return result


def _allow_all(call: dict, state: tools.ToolState) -> Allow | Refuse:
    return Allow()


def _no_resolve(call: dict) -> dict:
    return call


@dataclass(frozen=True)
class Hooks:
    name: str = "none"
    transform_input: Callable[[list[Segment]], list[Segment]] = _no_transform
    filter_tool_result: Callable[[dict, tools.ToolResult], tools.ToolResult] = _no_filter
    check_call: Callable[[dict, tools.ToolState], Allow | Refuse] = _allow_all
    # Chapter 8 additions, both no-ops by default. resolve_call fills a call's arguments once it is allowed (the
    # plan-then-execute placeholders); bind builds the episode's own hooks from the model the episode runs on (the
    # dual LLM's quarantined model is the same model, called with no tools).
    resolve_call: Callable[[dict], dict] = _no_resolve
    bind: Callable[[Any], "Hooks"] | None = None
    # Chapter 8, plan-then-execute, both None by default. hold(call) returns True to keep a call from running now (it
    # is answered with a held result); finish(reply) returns the held calls to run once the final reply is written.
    hold: Callable[[dict], bool] | None = None
    finish: Callable[[str], list[dict]] | None = None
    # design-dual-llm: names of tools in tools.DESIGN_TOOLS this episode's hooks add to the prompt and may call.
    extra_tools: frozenset = frozenset()
    # design-dual-llm: expands the final reply's references for the user. None (the default) leaves the reply as it is.
    expand_reply: Callable[[str], str] | None = None


NO_HOOKS = Hooks()


def system_text(template: str, acting_user: str, world: World | None = None) -> str:
    """The system prompt with the office's values filled in. The template is the file as it stands on disk."""
    from . import cases

    world = world or cases.load_world()
    office = tools._json("office.json")
    values = {"{office}": world.name, "{acting_user}": acting_user, "{hidden_context}": office["hidden_context"],
              "{portal_key}": world.portal_key}
    # One pass: a value is never scanned for placeholders, so a placeholder inside an earlier value stays literal.
    pattern = re.compile("|".join(re.escape(token) for token in values))
    return pattern.sub(lambda match: values[match.group(0)], template)


def tools_block(schemas: tuple[dict, ...] = tools.TOOLS) -> list[Segment]:
    """The Qwen tool preamble and one JSON schema per tool. The contractor's definitions are untrusted, whatever
    their text: an episode's schemas can carry a third party's text in a description (the tool-description carrier)."""
    out: list[Segment] = [("\n\n# Tools\n\nYou may call one or more functions to assist with the user query.\n\n"
                           "You are provided with function signatures within <tools></tools> XML tags:\n<tools>", True)]
    for spec in schemas:
        out.append(("\n", True))
        out.append((json.dumps(spec, ensure_ascii=False), spec["function"]["name"] not in tools.THIRD_PARTY_TOOLS))
    out.append(("\n</tools>\n\nFor each function call, return a json object with function name and arguments within "
                "<tool_call></tool_call> XML tags:\n<tool_call>\n{\"name\": <function-name>, "
                "\"arguments\": <args-json-object>}\n</tool_call>", True))
    return out


def open_prompt(system: str, user_text: str, schemas: tuple[dict, ...] = tools.TOOLS) -> list[Segment]:
    return ([(marked(mark(IM_START), "system\n" + system), True)] + tools_block(schemas)
            + [(marked(mark(IM_END), "\n", mark(IM_START), "user\n" + user_text, mark(IM_END), "\n"), True)])


def prompt_text(segments: list[Segment]) -> str:
    return "".join(text for text, _ in segments)


def prompt_sha256(segments: list[Segment] | str) -> str:
    text = segments if isinstance(segments, str) else prompt_text(segments)
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def to_tokens(tokenize: Callable[[str, bool], list[int]], segments: list[Segment],
              special_in_untrusted: bool) -> list[int]:
    """Token ids for a prompt. `tokenize(text, special)` is the model's tokenizer, with no BOS.

    special_in_untrusted=True (the baseline): the whole prompt is tokenised with special tokens parsed, so
    `<|im_start|>` inside a tool result becomes the real control token (probe 10).
    False (the chapter 6 fix): trusted segments are tokenised with special tokens parsed, untrusted ones without.
    """
    if special_in_untrusted:
        return tokenize(prompt_text(segments), True)
    ids: list[int] = []
    for text, _ in segments:
        for piece, is_marker in _spans(text):
            if piece:
                ids += tokenize(piece, is_marker)
    return ids


def _spans(text: str) -> list[tuple[str, bool]]:
    """The text split at the harness's own markers: (piece, True) for a marker, (piece, False) for everything else.
    Text that is not Built has no markers, so all of it is plain."""
    if not isinstance(text, Built) or not text.marks:
        return [(str(text), False)]
    spans, pos = [], 0
    for start, end in text.marks:
        spans += [(str(text[pos:start]), False), (str(text[start:end]), True)]
        pos = end
    return spans + [(str(text[pos:]), False)]


def parse_calls(reply: str) -> list[dict | None]:
    """Each <tool_call> block in the reply, parsed to {name, arguments}; None where the block is malformed.
    A block with no closing tag (a call cut off by the reply cap) is read to the end and is then usually malformed."""
    calls: list[dict | None] = []
    for match in CALL.finditer(reply):
        try:
            body = json.loads(match.group(1))
        except (json.JSONDecodeError, RecursionError):  # deeply nested JSON is a malformed call, never a crash
            calls.append(None)
            continue
        ok = isinstance(body, dict) and isinstance(body.get("name"), str) and isinstance(body.get("arguments"), dict)
        calls.append({"name": body["name"], "arguments": body["arguments"]} if ok else None)
    return calls


def _assistant_block(reply: str) -> Segment:
    return (marked(mark(IM_START), "assistant\n" + reply, mark(IM_END), "\n"), True)


def _generation_prompt(prefix: str) -> Segment:
    """The generation prompt: the assistant's opening marker, then any text the model's template adds (thinking)."""
    return (marked(mark(IM_START), prefix[len(IM_START):]), True) if prefix.startswith(IM_START) else (prefix, True)


def _tool_turn(results: list[tuple[str, tools.ToolResult]]) -> list[Segment]:
    segments: list[Segment] = [(marked(mark(IM_START), "user\n"), True)]
    for i, (_, result) in enumerate(results):
        segments.append(((("\n" if i else "") + "<tool_response>\n"), True))
        segments += result.as_segments()
        segments.append(("\n</tool_response>", True))
    return segments + [(marked(mark(IM_END), "\n"), True)]


def run_episode(item_id: str, user_text: str, acting_user: str, model: Any, *, system: str,
                state: tools.ToolState, hooks: Hooks = NO_HOOKS, assistant_prefix: str = ASSISTANT,
                max_tokens: int = 200) -> Trace:
    """One episode: the model is called until it gives a reply without a tool call, or MAX_TURNS is reached.

    `assistant_prefix` is the generation prompt; a model that renders thinking off adds its empty think block to it.
    """
    if hooks.bind is not None:  # chapter 8: the episode's own hooks, built from the model it runs on
        hooks = hooks.bind(model)
    trace = Trace(case_id=item_id, acting_user=acting_user)
    history = open_prompt(system, user_text, state.schemas + tools.design_schemas(hooks.extra_tools))
    for turn in range(MAX_TURNS):
        prompt = hooks.transform_input(history + [_generation_prompt(assistant_prefix)])
        reply = model.complete(prompt, max_tokens, key=(item_id, turn))
        history.append(_assistant_block(reply))
        calls = parse_calls(reply)
        if not calls:
            shown, marks = reply, {}
            if hooks.expand_reply is not None:  # design-dual-llm: expanded text is untrusted, so it is marked and scanned
                shown, marks = hooks.expand_reply(reply), {"result": {"untrusted": True}}
            trace.add("reply", text=shown, **marks)
            for url in rendered_urls(shown):
                trace.add("render", args={"url": url})
            if hooks.finish is not None:  # chapter 8: the held calls run after the final reply
                for held in hooks.finish(reply):
                    _run_call(trace, held, state, hooks)
            return trace
        results = [_run_call(trace, call, state, hooks) for call in calls]
        history.extend(_tool_turn(results))
    trace.add("reply", text="", result={"turns_exhausted": MAX_TURNS})
    return trace


NO_DECISION = "the policy gave no decision"
WITHHOLD_REASON = "the filter changed the tool result"


def _decide(call: dict, state: tools.ToolState, hooks: Hooks) -> Allow | Refuse:
    """Only an explicit Allow runs a call. A Refuse passes its reason on; anything else, including an exception
    raised by the hook, is a refusal."""
    try:
        decision = hooks.check_call(call, state)
    except Exception:
        return Refuse(NO_DECISION)
    if isinstance(decision, Allow):
        return decision
    if isinstance(decision, Refuse):
        return decision
    return Refuse(NO_DECISION)


def _run_call(trace: Trace, call: dict | None, state: tools.ToolState,
              hooks: Hooks) -> tuple[str, tools.ToolResult]:
    if call is None:
        trace.add("tool_call", tool=None, args=None)
        if hooks.hold is not None:  # a plan variant: a malformed block in the plan is an outcome, recorded as a refusal
            trace.add("defence", tool=None, ref=None, result={"decision": "refuse", "blocked": True,
                      "reason": "malformed plan call: not JSON with a name and an arguments object", "hook": hooks.name})
        return ("", tools.ToolResult({"error": "malformed tool call: not JSON with a name and an arguments object"},
                                     frozenset()))
    name, args = call["name"], call["arguments"]
    if hooks.hold is not None and hooks.hold({"name": name, "arguments": args}):  # logged once, when it runs
        return (name, tools.ToolResult({"held": "this call runs after the final reply"}, frozenset()))
    event = trace.add("tool_call", tool=name, args=args)
    decision = _decide({"name": name, "arguments": args}, state, hooks)
    if isinstance(decision, Refuse):
        trace.add("defence", tool=name, ref=event.step,
                  result={"decision": "refuse", "blocked": True, "reason": decision.reason, "hook": hooks.name})
        if name not in tools.SPECS and name not in hooks.extra_tools:  # an unknown tool keeps the unknown-tool error
            return (name, tools.call_tool(name, args, state))
        return (name, tools.ToolResult({"error": f"refused: {decision.reason}"}, frozenset()))
    args = hooks.resolve_call({"name": name, "arguments": args})["arguments"]  # after the check, before the call
    if name not in tools.SPECS and name not in hooks.extra_tools:
        return (name, tools.call_tool(name, args, state))
    try:  # only the tool call is guarded; an exception here is the tool's, and the episode goes on
        result = tools.call_tool(name, args, state)
    except Exception as exc:
        result = tools.ToolResult({"error": f"{type(exc).__name__}: {str(exc)[:200]}"}, frozenset())
        trace.add("tool_result", tool=name, result=json.dumps(result.data, ensure_ascii=False))
        return (name, result)
    filtered = hooks.filter_tool_result(call, result)
    if filtered.data != result.data:  # a withheld or changed result: the call still ran, so it is not blocked
        trace.add("defence", tool=name, ref=event.step,
                  result={"decision": "withhold", "blocked": False, "reason": WITHHOLD_REASON, "hook": hooks.name})
    result = filtered
    trace.add("tool_result", tool=name, result=json.dumps(result.data, ensure_ascii=False))
    if name == "send_message" and "outbox_id" in result.data:
        trace.add("outbox", tool=name, args={"to": args["to"], "body": args["body"]})
    if name == "fetch_page":
        trace.add("fetch", tool=name, args={"url": args["url"]}, result=result.data.get("status"))
    return (name, result)
