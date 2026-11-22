"""Record one variant of the office assistant over a split (plan sections 9 and 17).

Usage: python recordings/assistant.py VARIANT --split dev|held-out|rough [--limit N] [--model m-4b|m-06b]

- One model process at a time (a lock in scratch). The model is loaded on the first call that needs it.
- Resumable: each finished episode is appended to a partial file in scratch; episodes already there are skipped.
- A full split goes into examples/data/recorded/ through Recording, only when every episode is done.
- --limit N runs N benign tasks and N attack cases as a smoke run: it writes only to scratch/harness/smoke, never
  calls Recording, and so never touches the book.
- A variant with branch_from branches from that variant's recording on the same split (baseline-dev, or
  baseline-dev-06b for the 0.6B model). While an item's prompts match the parent's, its replies are copied; the first
  prompt that differs, and every turn after it, is live. The manifest's "branches" gives each item's branched_from
  and from_turn (null when the item was taken whole, with no live turn).

To add a variant, add one entry to VARIANTS. Only its Hooks differ from the others.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
BOOK = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(BOOK / "examples"))

import local_model  # noqa: E402
from recorded import Recording, scratch  # noqa: E402
from lib import cases, defences, harness, replay, scorers, tools  # noqa: E402
from lib.harness import Hooks  # noqa: E402
from lib import variants as lib_variants  # noqa: E402  (the table variants and their per-task plans, shared with the examples)
from lib.variants import HOOKS  # noqa: E402  (the hooks of the table variants, shared with the examples)

SPLITS = ("dev", "held-out", "rough")
MODELS = {"m-4b": local_model.QWEN4B, "m-06b": local_model.QWEN06B}
ANSWER_TOKENS = 200  # a final reply; a tool call is capped at local_model.TOOL_CAP inside the model
SPECIAL_IN_UNTRUSTED = True  # the baseline tokenisation (probe 10); the chapter 6 fix is False
RETRIEVAL = "bm25s 0.3.16, k1=1.5 b=0.75, stopwords en, ranked by (-score, doc_id)"


DETECTOR_THRESHOLD = 0.50  # picked on dev by detector-threshold-dev (plan section 21); never tuned on held-out
_DETECTOR_FILTER = None


def _detector_hook(call: dict, result: tools.ToolResult) -> tools.ToolResult:
    """The chapter 5 detector as a tool-result filter. Built on first use, so an unset threshold fails at the first
    tool result with the defences.detector_filter error, after the model has replied once."""
    global _DETECTOR_FILTER
    if _DETECTOR_FILTER is None:
        _DETECTOR_FILTER = defences.detector_filter(DETECTOR_THRESHOLD)
    return _DETECTOR_FILTER(call, result)


@dataclass(frozen=True)
class Variant:
    name: str
    hooks: Hooks
    branch_from: str | None = None
    special_in_untrusted: bool = True  # False: untrusted segments tokenised with special tokens off (chapter 6)
    control: bool = False  # True: the attack cases are the control-token set (examples/data/case/control-token.json)
    plan: str | None = None  # chapter 6: a name in lib/variants.py PLANS; its hooks are built per episode from the task


VARIANTS: dict[str, Variant] = {
    "baseline": Variant("baseline", HOOKS["baseline"]),
    "rough-baseline": Variant("rough-baseline", HOOKS["rough-baseline"]),
    "rough-allowlist": Variant("rough-allowlist", HOOKS["rough-allowlist"], branch_from="rough-baseline"),
    "prompt-warning": Variant("prompt-warning", HOOKS["prompt-warning"]),
    "prompt-delimiters": Variant("prompt-delimiters", HOOKS["prompt-delimiters"]),
    "prompt-datamark": Variant("prompt-datamark", HOOKS["prompt-datamark"]),
    "prompt-encode": Variant("prompt-encode", HOOKS["prompt-encode"]),
    "prompt-repeat": Variant("prompt-repeat", HOOKS["prompt-repeat"]),
    "detector-filter": Variant("detector-filter", Hooks(name="detector-filter", filter_tool_result=_detector_hook),
                               branch_from="baseline"),
    "enforce-filter": Variant("enforce-filter", Hooks(name="enforce-filter"), plan="enforce-filter"),
    "enforce-args": Variant("enforce-args", Hooks(name="enforce-args"), branch_from="baseline", plan="enforce-args"),
    "enforce-approval": Variant("enforce-approval", Hooks(name="enforce-approval"), branch_from="baseline",
                                plan="enforce-approval"),
    "egress-fetch": Variant("egress-fetch", Hooks(name="egress-fetch"), branch_from="baseline", plan="egress-fetch"),
    "design-taint": Variant("design-taint", Hooks(name="design-taint"), branch_from="baseline", plan="design-taint"),
    # Its system prompt differs from the baseline's, so it cannot branch from it: it records whole.
    "design-plan-then-execute": Variant("design-plan-then-execute", Hooks(name="design-plan-then-execute"),
                                        plan="design-plan-then-execute"),
    "design-dual-llm": Variant("design-dual-llm", Hooks(name="design-dual-llm"), plan="design-dual-llm"),
    "ctrl-baseline": Variant("ctrl-baseline", Hooks(name="none"), control=True),
    "ctrl-special-off": Variant("ctrl-special-off", Hooks(name="special-off"), special_in_untrusted=False,
                                control=True),
    # chapter 9: the system prompt has no portal key and no hidden note, so every prompt differs from the baseline's.
    "secrets-out": Variant("secrets-out", HOOKS["secrets-out"]),
    # chapter 9: branches from the baseline at the first search whose result differs (lib/variants.py _by_role).
    "retrieval-by-role": Variant("retrieval-by-role", HOOKS["retrieval-by-role"], branch_from="baseline"),
}


class Runner:
    """The live model: loaded once, on the first call that needs it."""

    def __init__(self, pin: local_model.Pin, prefix: str, special_in_untrusted: bool = SPECIAL_IN_UNTRUSTED) -> None:
        self.pin, self.prefix, self._llm = pin, prefix, None
        self.special_in_untrusted = special_in_untrusted

    def complete(self, prompt: Any, max_tokens: int, key: tuple[str, int] | None = None) -> str:
        if self._llm is None:
            self._llm = local_model.LocalModel(self.pin, threads=local_model.THREADS)
        return self._llm.complete_prompt(prompt, special_in_untrusted=self.special_in_untrusted, max_tokens=max_tokens)


def recording_name(variant: str, split: str, model: str) -> str:
    """The recording a variant writes on a split. The rough split keeps the variant's name (rough-baseline); the others
    take the split, and the 0.6B model adds -06b (baseline-dev-06b)."""
    base = variant if split == "rough" else f"{variant}-{split}"
    return base + ("-06b" if model == "m-06b" else "")


class Session:
    """The model one recording calls. While an item's prompts match the parent's, its replies are copied from the
    parent. The first prompt that differs, and every turn after it, goes to the runner. A defence acts after the
    model has replied, so the acting turn's own reply is unchanged and is copied; the change first shows in the next
    prompt, which is the item's from_turn. Keeps a row for every reply it did not copy, and the from_turn of each
    item that diverged."""

    def __init__(self, runner: Runner, parent: replay.ReplayModel | None = None) -> None:
        self.runner, self.parent = runner, parent
        self.rows: list[dict[str, Any]] = []
        self.seen: set[str] = set()  # items read from the parent
        self.from_turn: dict[str, int] = {}  # items that diverged: the first turn the runner answered
        self.calls = 0

    def complete(self, prompt: Any, max_tokens: int, key: tuple | None = None) -> str:
        item, turn = key[0], key[1]
        role = key[2] if len(key) > 2 else "planner"  # design-dual-llm's quarantined calls carry role "quarantined"
        self.calls += 1
        sha = harness.prompt_sha256(prompt)
        if self.parent is not None and item not in self.from_turn:
            self.seen.add(item)
            row = self.parent.lookup(item, turn, role)
            if row is not None and row["prompt_sha256"] == sha:
                return row["reply"]
            self.from_turn[item] = turn
        reply = self.runner.complete(prompt, max_tokens, key=key)
        row = {"item": item, "turn": turn, "prompt_sha256": sha, "reply": reply}
        if role != "planner":  # a row without a role is a planner row, so existing recordings are unchanged
            row["role"] = role
        self.rows.append(row)
        return reply

    def branch(self, item: str, parent_name: str | None) -> dict[str, Any]:
        """The manifest's record for one item: {item: {branched_from, from_turn}}, from_turn null when the item was
        taken whole. Empty when the item was not read from a parent."""
        if parent_name is None or item not in self.seen:
            return {}
        return {item: {"branched_from": parent_name, "from_turn": self.from_turn.get(item)}}


def episodes(split: str, limit: int, control: bool = False) -> list[dict[str, Any]]:
    """Benign tasks, then attack cases, each sorted by ID. A limit keeps that many of each kind. control: the attack
    cases are the control-token set, which is dev only."""
    tasks = {t.id: t for t in cases.load_tasks()}
    benign = cases.load_rough_tasks() if split == "rough" else cases.load_tasks(split)
    if control and split != "dev":
        raise ValueError("the control-token set is dev only")
    attacks = cases.load_control_cases() if control else cases.load_cases(split)
    benign = sorted(benign, key=lambda t: t.id)[:limit or None]
    attacks = sorted(attacks, key=lambda c: c.id)[:limit or None]
    out = [{"kind": "benign", "id": t.id, "task": t, "case": None, "user": t.text, "acting": t.acting_user}
           for t in benign]
    for c in attacks:
        base = tasks[c.task]
        out.append({"kind": "attack", "id": c.id, "task": base, "case": c, "user": base.text,
                    "acting": base.acting_user})
    return out


def run_episode(ep: dict[str, Any], session: Session, template: str, prefix: str,
                hooks: Hooks, plan: str | None = None) -> tuple[dict[str, Any], Any]:
    case = ep["case"]
    world = cases.load_world()
    schema_filter = None
    if plan is not None:
        hooks = lib_variants.PLANS[plan](ep["task"], world)
        schema_filter = lib_variants.schema_filter(plan, ep["task"])
    state = tools.ToolState.new(ep["acting"], carrier=case.carrier if case else None,
                                injection=case.injection if case else None)
    if schema_filter is not None:  # after the carrier, which may replace the schemas with a tool-description carrier
        state.schemas = schema_filter(state.schemas)
    system = harness.system_text(template, ep["acting"], world)
    session.calls = 0
    started = time.monotonic()
    trace = harness.run_episode(ep["id"], ep["user"], ep["acting"], session, system=system, state=state,
                                hooks=hooks, assistant_prefix=prefix, max_tokens=ANSWER_TOKENS)
    seconds = time.monotonic() - started
    passed = scorers.utility(ep["task"], trace) if case is None else scorers.attack_success(case, trace)
    return {"item": ep["id"], "kind": ep["kind"], "score": bool(passed), "turns": session.calls,
            "seconds": round(seconds, 2), "trace": trace.to_jsonl()}, trace


def load_partial(path: Path) -> tuple[list[dict], int]:
    if not path.exists():
        return [], 0
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [r for r in rows if "item" in r], sum(1 for r in rows if "run" in r)


def write_outputs(folder: Path, done: list[dict], rows: list[dict]) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    rows = sorted(rows, key=lambda r: (r["item"], r["turn"]))
    (folder / "replies.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows),
                                          encoding="utf-8")
    # One file for every episode's trace, sorted by item, for a person reading the recording; no example reads it
    # (examples rebuild each trace by replay). Recordings made before Nov 21 evening keep a traces/ folder instead.
    lines = [json.dumps({"item": e["item"], "trace": e["trace"]}, ensure_ascii=False) + "\n"
             for e in sorted(done, key=lambda e: e["item"])]
    (folder / "traces.jsonl").write_text("".join(lines), encoding="utf-8")


def run_items(variant: Variant, split: str, limit: int, runner: Any, prefix: str, template: str,
              parent: replay.ReplayModel | None, finished: dict[str, dict], on_done: Any) -> dict[str, dict]:
    """Runs each episode of the split not already in `finished` (item -> entry), in episode order. Returns `finished`
    with the new entries added; on_done(entry) is called after each one. Works with any runner that has complete()."""
    session = Session(runner, parent)
    for ep in episodes(split, limit, variant.control):
        if ep["id"] in finished:
            continue
        entry, _ = run_episode(ep, session, template, prefix, variant.hooks, variant.plan)
        entry["branch"] = session.branch(ep["id"], parent.name if parent else None)
        entry["rows"], session.rows = session.rows, []  # this episode's live replies only
        finished[ep["id"]] = entry
        on_done(entry)
    return finished


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("variant", choices=sorted(VARIANTS))
    parser.add_argument("--split", choices=SPLITS, required=True)
    parser.add_argument("--limit", type=int, default=0, help="smoke run: N benign and N attack episodes")
    parser.add_argument("--model", choices=sorted(MODELS), default="m-4b")
    args = parser.parse_args(argv)

    variant, pin = VARIANTS[args.variant], MODELS[args.model]
    name = recording_name(variant.name, args.split, args.model)
    smoke = args.limit > 0
    partial_dir = scratch() / "harness" / "partial"
    partial_dir.mkdir(parents=True, exist_ok=True)
    lock = open(scratch() / "harness" / "model.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("another model process is running; one at a time") from None

    system_file = BOOK / "examples" / "prompts" / lib_variants.VARIANTS[variant.name].system  # the system field of lib/variants.py
    template = system_file.read_text(encoding="utf-8")
    prompt_file_sha = hashlib.sha256(system_file.read_bytes()).hexdigest()
    parent = None
    if variant.branch_from:
        parent = replay.ReplayModel(recording_name(variant.branch_from, args.split, args.model))
        if parent.manifest["prompt_sha256"] != prompt_file_sha:
            raise SystemExit(f"{parent.name} was recorded from a different system prompt")
    prefix = harness.ASSISTANT + ("<think>\n\n</think>\n\n" if pin.thinking_off else "")

    partial = partial_dir / (f"{name}-smoke.jsonl" if smoke else f"{name}.jsonl")
    if smoke and partial.exists():
        partial.unlink()  # a smoke run always starts clean
    done, runs = load_partial(partial)
    with partial.open("a", encoding="utf-8") as log:
        log.write(json.dumps({"run": runs + 1}) + "\n")
    finished = {r["item"]: r for r in done}
    print(f"{name}: {len(finished)} done, {len(episodes(args.split, args.limit, variant.control)) - len(finished)} to run")

    def log_entry(entry: dict[str, Any]) -> None:
        with partial.open("a", encoding="utf-8") as log:
            log.write(json.dumps(entry, ensure_ascii=False) + "\n")
        print(f"  {entry['item']} {entry['kind']} score={int(entry['score'])} turns={entry['turns']}")

    finished = run_items(variant, args.split, args.limit, Runner(pin, prefix, variant.special_in_untrusted), prefix, template, parent,
                         finished, log_entry)
    everything = episodes(args.split, args.limit, variant.control)
    if len(finished) < len(everything):
        print(f"{len(finished)} of {len(everything)} episodes done; run again to finish")
        return
    done = [finished[ep["id"]] for ep in everything]
    rows = [r for entry in done for r in entry.get("rows", [])]
    branches = {item: rec for entry in done for item, rec in entry.get("branch", {}).items()}
    seconds = [e["seconds"] for e in done if "seconds" in e]
    desc = local_model.describe(pin, local_model.ANSWER_SAMPLING)
    manifest = {
        "model": pin.model, "model_version": desc["model_version"], "prompt_sha256": prompt_file_sha,
        "settings": {"temperature": 0.0, "seed": local_model.SEED, "threads": local_model.THREADS,
                     "context": local_model.CONTEXT, "tool_call_cap": local_model.TOOL_CAP,
                     "answer_cap": ANSWER_TOKENS,
                     "tokens": ("special tokens parsed in the whole prompt" if variant.special_in_untrusted
                                else "special tokens parsed in trusted segments only"),
                     "runner": desc["runner"], "thinking": desc["thinking"]},
        "variant": variant.name, "defence": variant.hooks.name, "split": args.split,
        "case_set": cases.CASE_SET_VERSION, "control_set": "control-1" if variant.control else None,
        "retrieval": RETRIEVAL,
        "episodes": {"benign": sum(e["kind"] == "benign" for e in done),
                     "attack": sum(e["kind"] == "attack" for e in done)},
        "batches": runs + 1, "tuned_on": "none", "branches": branches,
        "seconds_per_episode_mean": round(sum(seconds) / len(seconds), 2),
    }
    if smoke:
        folder = scratch() / "harness" / "smoke" / name
        if folder.exists():
            import shutil
            shutil.rmtree(folder)
        write_outputs(folder, done, rows)
        (folder / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
        print(f"smoke: wrote {len(done)} episodes to scratch; nothing copied into the book")
        return
    with Recording(name, model=pin.model, model_version=desc["model_version"], prompt_sha256=prompt_file_sha,
                   fresh=True, **{k: v for k, v in manifest.items() if k not in ("model", "model_version",
                                                                              "prompt_sha256")}) as out:
        write_outputs(out, done, rows)


if __name__ == "__main__":
    main()
