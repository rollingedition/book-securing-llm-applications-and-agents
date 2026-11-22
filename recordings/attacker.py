"""Record the adaptive attacker: each dev case under each defence, up to ROUNDS attacker turns (chapter 11).

Usage: python recordings/attacker.py [--limit N] [--dry]

One model process at a time (the lock). Every call (target episode or attacker turn) is appended to a working file in
scratch as it finishes, so a run stopped part-way resumes without repeating a call. The book gets one recording,
adaptive-round-5, only when every chain is done. --dry uses a scripted model, writes only into scratch, and never
touches the book. Examples replay the recording and never load a model.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import shutil
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))  # so `lib` imports, as assistant.py does
import local_model  # noqa: E402
from recorded import Recording, scratch  # noqa: E402
from lib import adaptive, cases, harness  # noqa: E402

RECORDING = f"adaptive-round-{adaptive.ROUNDS}"
PROMPT_FILE = adaptive.PROMPT


class Live:
    """The 4B model, loaded on the first call. A target episode passes segments; an attacker turn passes chat
    messages as JSON text (adaptive.attacker_messages), which the model answers in chat form."""

    def __init__(self) -> None:
        self.llm = None

    def complete(self, prompt: Any, max_tokens: int | None = None, key: tuple | None = None) -> str:
        if self.llm is None:
            self.llm = local_model.LocalModel(local_model.QWEN4B, threads=local_model.THREADS)
        if isinstance(prompt, str):
            return self.llm.complete(json.loads(prompt))
        return self.llm.complete_prompt(prompt, special_in_untrusted=True, max_tokens=max_tokens or 200)


class DryModel:
    """A scripted model for the dry run: a fixed benign reply to the target and a fixed note from the attacker."""

    def complete(self, prompt: Any, max_tokens: int | None = None, key: tuple | None = None) -> str:
        item, _turn = key
        return "Please check the office's policy page." if item.endswith("/attacker") else "I can't help with that."


class Recorder:
    """Wraps a model: a call already in the working file is answered from it, others are called and appended."""

    def __init__(self, model: Any, path: Path) -> None:
        self.model, self.path, self.rows = model, path, {}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                row = json.loads(line)
                self.rows[(row["item"], row["turn"])] = row
        self.calls = 0

    def complete(self, prompt: Any, max_tokens: int | None = None, key: tuple | None = None) -> str:
        item, turn = key
        row = self.rows.get((item, turn))
        if row is None:
            reply = self.model.complete(prompt, max_tokens, key=key)
            row = {"item": item, "turn": turn, "prompt_sha256": harness.prompt_sha256(prompt), "reply": reply}
            self.rows[(item, turn)] = row
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
            self.calls += 1
        return row["reply"]


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--limit", type=int, default=0, help="first N cases of the first defence only")
    parser.add_argument("--dry", action="store_true", help="scripted model; writes into scratch, not the book")
    args = parser.parse_args(argv)

    chosen = adaptive.select_cases(cases.load_cases("dev"))
    defences = adaptive.DEFENCES
    if args.limit:
        chosen, defences = chosen[: args.limit], defences[:1]

    work = scratch() / ("adaptive-dry" if args.dry else "adaptive")
    work.mkdir(parents=True, exist_ok=True)
    lock = open(work / "model.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit("another model process is running; one at a time") from None
    partial = work / "replies.jsonl"
    if args.dry and partial.exists():
        partial.unlink()  # a dry run always starts clean

    recorder = Recorder(DryModel() if args.dry else Live(), partial)
    started = time.monotonic()
    chains: dict[str, list[adaptive.Round]] = {}
    for defence in defences:
        for case in chosen:
            chain = adaptive.attack_loop(case, defence, *adaptive.model_calls(recorder))
            chains[f"{defence}/{case.id}"] = chain
            # IDs, round numbers and counts only: no attacker or target text is printed
            print(f"{defence} {case.id} rounds={len(chain) - 1} success={chain[-1].success}")
    print(f"{len(chains)} chains, {recorder.calls} new calls, {time.monotonic() - started:.0f} s")
    if args.dry:
        return

    target_calls = sum(1 for row in recorder.rows.values() if row["item"].endswith("/target"))
    attacker_calls = len(recorder.rows) - target_calls
    model = local_model.describe(local_model.QWEN4B, local_model.ANSWER_SAMPLING)
    chains_out = [{"defence": k.split("/")[0], "case": k.split("/")[1],
                   "rounds": [{"n": r.n, "injection": r.injection, "success": r.success, "feedback": r.feedback}
                              for r in chain]} for k, chain in sorted(chains.items())]
    with Recording(RECORDING, model=local_model.QWEN4B.model, model_version=model["model_version"],
                   prompt_sha256=hashlib.sha256(PROMPT_FILE.read_bytes()).hexdigest(), fresh=True,
                   defences=list(defences), cases=[c.id for c in chosen], rounds=adaptive.ROUNDS,
                   attacker_tokens=adaptive.ATTACKER_TOKENS, attacker_calls=attacker_calls,
                   target_episodes=target_calls, seconds_per_target_episode=round(
                       (time.monotonic() - started) / max(target_calls, 1), 2),
                   timing_note="includes the attacker turns; a bound on the target's own episode time",
                   settings={"temperature": 0.0, "seed": local_model.SEED, "threads": local_model.THREADS,
                             "context": local_model.CONTEXT, "runner": model["runner"]}) as out:
        shutil.copy(partial, out / "replies.jsonl")
        with (out / "chains.jsonl").open("w", encoding="utf-8") as f:
            for chain in chains_out:
                f.write(json.dumps(chain, ensure_ascii=False, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
