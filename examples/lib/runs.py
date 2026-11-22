"""Replay the recorded runs of the office assistant, for the examples that score them.

Each function replays one recording through the harness: one episode per task or attack case, each in a fresh
state, each with the system prompt the recording was made with. Results are keyed by ID and built in sorted ID
order, so the same recording gives the same output on every machine.
"""
from lib import cases, defences, harness, replay, scorers, tokens, tools, variants  # lib first: threads and seeds are fixed here

from pathlib import Path
from functools import lru_cache
from urllib.parse import urlsplit

ANSWER_TOKENS = 200  # the recording's answer cap (its manifest); a tool call is capped inside the model
PROMPTS = Path(__file__).resolve().parents[1] / "prompts"
TEMPLATE = (PROMPTS / "assistant-system.md").read_text(encoding="utf-8")
_CASES = cases  # replay_set takes a `cases` argument, which shadows the module inside that function


def _template(variant):
    """The system prompt text of a replay: None without a variant (the baseline TEMPLATE, which a caller may swap), else
    the prompt file the variant's recording was made with (its `system` field in lib/variants.py)."""
    if variant is None:
        return None
    return _prompt_file(variants.VARIANTS[variant].system)


@lru_cache(maxsize=None)
def _prompt_file(name):
    return (PROMPTS / name).read_text(encoding="utf-8")


def _episode(model, item_id, text, acting_user, state, hooks, world, prefix=harness.ASSISTANT, template=None):
    """One episode, replayed from the model with the system prompt for this user: `template`, or the baseline TEMPLATE.
    `prefix` is the generation prompt the recording was made with: the baseline's, unless a variant's entry says
    otherwise."""
    return harness.run_episode(item_id, text, acting_user, model,
                               system=harness.system_text(template or TEMPLATE, acting_user, world),
                               state=state, hooks=hooks or harness.NO_HOOKS,
                               assistant_prefix=prefix,  # the generation prompt the recording was made with
                               max_tokens=ANSWER_TOKENS)


def _replay_settings(variant, hooks):
    """The hooks, the generation prompt and the plan name of a replay. With `variant`, they come from lib/variants.py
    (so a 0.6B recording replays with thinking off); a plan name is set when the variant has a per-task plan, and then
    the hooks are built per episode. Without `variant`, the hooks given are used with the baseline prompt. Giving both
    is refused, since the table already holds the hooks."""
    if variant is None:
        return hooks, harness.ASSISTANT, None
    if hooks is not None:
        raise ValueError("give a variant or hooks, not both")
    entry = variants.VARIANTS[variant]  # KeyError for a name the table does not list
    return entry.hooks, entry.prefix, variant if variant in variants.PLANS else None


def _run(model, item_id, task, world, hooks, prefix, plan, case=None, template=None):
    """One episode of a task, or of an attack case beside its task. A plan builds the hooks from the task, and its
    schema filter (if any) narrows the tool schemas after the carrier, as the recorded prompt was built."""
    if case is None:
        state = tools.ToolState.new(task.acting_user)
    else:
        state = tools.ToolState.new(task.acting_user, carrier=case.carrier, injection=case.injection)
    if plan is not None:
        hooks = variants.PLANS[plan](task, world)
        schema = variants.schema_filter(plan, task)
        if schema is not None:
            state.schemas = schema(state.schemas)
    return _episode(model, item_id, task.text, task.acting_user, state, hooks, world, prefix, template)


def replay_tasks(recording, tasks, hooks=None, variant=None, model=None):
    """Replay each benign task on its own, with no attack in its state. Returns a trace per task ID. `variant` names
    a row of lib/variants.py, instead of passing hooks. `model` is a replay model already open on the recording."""
    hooks, prefix, plan = _replay_settings(variant, hooks)
    template = _template(variant)
    world = cases.load_world()
    if model is None:
        model = replay.ReplayModel(recording)  # one model for the whole recording: it reads the file once
    return {task.id: _run(model, task.id, task, world, hooks, prefix, plan, template=template)
            for task in sorted(tasks, key=lambda t: t.id)}


def replay_cases(recording, attack_cases, hooks=None, variant=None, model=None):
    """Replay each attack case beside its benign task, with the case's injected message in its carrier. Returns a trace
    per case ID. The benign task a case sits beside is the task whose ID the case names. `variant` and `model` as in
    replay_tasks."""
    hooks, prefix, plan = _replay_settings(variant, hooks)
    template = _template(variant)
    world = cases.load_world()
    if model is None:
        model = replay.ReplayModel(recording)
    base_tasks = {t.id: t for t in cases.load_tasks()}  # every task, so each case finds the one it names
    return {case.id: _run(model, case.id, base_tasks[case.task], world, hooks, prefix, plan, case, template)
            for case in sorted(attack_cases, key=lambda c: c.id)}


def replay_dev(name, benign, attacks):
    """The dev split under one defence, as (benign traces, attack traces): the baseline with no hooks, or a defence
    by its variant, with one model for both sets. `benign` and `attacks` are as in replay_tasks and replay_cases."""
    if name == "baseline":
        return replay_tasks("baseline-dev", benign), replay_cases("baseline-dev", attacks)
    model = replay.ReplayModel(f"{name}-dev")  # one model per recording: it reads its file once
    return (replay_tasks(f"{name}-dev", benign, variant=name, model=model),
            replay_cases(f"{name}-dev", attacks, variant=name, model=model))


def allowlist_hooks():
    """The hooks that switch the outbound allowlist on: each proposed call is checked against it, with the
    case world. The harness also passes the episode's state, which the allowlist does not need."""
    world = cases.load_world()
    return harness.Hooks(name="allowlist",
                         check_call=lambda call, state: defences.outbound_allowlist(call, world))


def tool_sequence(trace):
    """The tool calls of one trace in order, by tool name and, for a fetch, by host only. A name the schema does
    not list is printed as 'unknown', so no model-written text reaches the output."""
    parts = []
    for event in trace.tool_calls():
        name = event.tool if event.tool in tools.SPECS else "unknown"
        if name == "fetch_page":
            host = urlsplit(str((event.args or {}).get("url", ""))).hostname
            parts.append(f"fetch_page host={host}")
        else:
            parts.append(name)
    return " -> ".join(parts) or "none"


def refused_tools(trace):
    """The tool names of the calls a defence refused in one trace. A refusal points back at the call it blocked,
    so the name comes from that call's step; a name the schema does not list is 'unknown'."""
    by_step = {e.step: e for e in trace.events}
    names = []
    for event in trace.events:
        if event.kind == "defence" and isinstance(event.result, dict) and event.result.get("blocked"):
            call = by_step.get(event.ref)
            names.append(call.tool if call and call.tool in tools.SPECS else "unknown")
    return names


def replay_set(recording, hooks=None, variant=None, cases=None, tasks=None):
    """The benign tasks and attack cases of one recording: by default the 10 benign tasks and the 20 rough attack
    cases. `cases` and `tasks` name other sets (the control-token set, say), and `variant` is as in replay_tasks.
    Returns (benign utility, attacks), where attacks maps case ID to (case, base task, trace)."""
    all_tasks = {t.id: t for t in _CASES.load_tasks()}
    benign_tasks = tasks if tasks is not None else _CASES.load_rough_tasks()
    attack_cases = cases if cases is not None else _CASES.load_cases("rough")
    benign_traces = replay_tasks(recording, benign_tasks, hooks, variant)
    attack_traces = replay_cases(recording, attack_cases, hooks, variant)
    benign = {t.id: scorers.utility(t, benign_traces[t.id]) for t in benign_tasks}
    attacks = {c.id: (c, all_tasks[c.task], attack_traces[c.id]) for c in attack_cases}
    return benign, attacks


class Capture(replay.ReplayModel):
    """The replay model, which also keeps each prompt it was given, by item, so a token count reads the same prompts."""

    def __init__(self, name):
        super().__init__(name)
        self.prompts = {}

    def complete(self, prompt, max_tokens=None, key=None):
        self.prompts.setdefault(key[0], []).append(prompt)
        return super().complete(prompt, max_tokens, key=key)


def reached(segments, special, marker):
    """True when an untrusted segment holds token id `marker` in this tokenisation mode (tokens.ids). Each segment is
    tokenised alone, which matches the whole prompt except at the segment edges. Trusted segments hold the book's own
    template, so they are not counted."""
    return any(marker in tokens.ids(text, special) for text, trusted in segments if not trusted)
