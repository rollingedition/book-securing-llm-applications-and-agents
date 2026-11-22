"""ReplayModel: the recorded replies of one recording, read back by (item, turn), and ScriptedModel: canned replies.

A recording is a folder with manifest.json and replies.jsonl. Each row is
{"item": ID, "turn": N, "prompt_sha256": HASH, "reply": TEXT}. A lookup checks the SHA-256 of the prompt it is given
against the row's, and raises PromptMismatch when they differ, so a changed prompt or harness can't replay stale
replies.

A branched recording (plan section 17, decision 2) lists in its manifest, per item, `branched_from` (a recording in the
same root) and `from_turn`: the item's turns before from_turn are read from that recording, the rest from this one.
`from_turn` null means the item was taken whole from the base. Older manifests write {"from", "turns"} instead, where
turns is the count copied; both forms read the same way.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .harness import prompt_sha256

RECORDED = Path(__file__).resolve().parent.parent / "data" / "recorded"


class PromptMismatch(ValueError):
    """The prompt given to the replay is not the prompt the reply was recorded for."""


class ReplayMiss(KeyError):
    """The recording has no reply for this item and turn."""


def branch_map(manifest: dict[str, Any]) -> dict[str, tuple[str, int | None]]:
    """item -> (recording it branched from, first turn read from this recording, or None when taken whole)."""
    out: dict[str, tuple[str, int | None]] = {}
    for item, branch in manifest.get("branches", {}).items():
        if "branched_from" in branch:
            out[item] = (branch["branched_from"], branch["from_turn"])
        else:
            out[item] = (branch["from"], branch["turns"])
    return out


class ReplayModel:
    def __init__(self, name: str, folder: Path | None = None, expect_prompt_file: str | None = None,
                 root: Path = RECORDED) -> None:
        self.name = name
        self.root = root  # where the recordings this one branches from are found
        self.folder = folder or root / name
        self.manifest = json.loads((self.folder / "manifest.json").read_text(encoding="utf-8"))
        if expect_prompt_file is not None and self.manifest["prompt_sha256"] != expect_prompt_file:
            raise PromptMismatch(f"recording {name!r} was made from a different system prompt file")
        self._rows: dict[tuple[str, int, str], dict[str, Any]] = {}
        for line in (self.folder / "replies.jsonl").read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            self._rows[(row["item"], row["turn"], row.get("role", "planner"))] = row  # a row without a role is planner
        self._branches = branch_map(self.manifest)
        self._parents: dict[str, ReplayModel] = {}

    def _parent(self, name: str) -> "ReplayModel":
        if name not in self._parents:
            self._parents[name] = ReplayModel(name, root=self.root)
        return self._parents[name]

    def lookup(self, item: str, turn: int, role: str = "planner") -> dict[str, Any] | None:
        """The row for (item, turn, role): from the recording the item branched from, for a turn before from_turn or
        for an item taken whole; otherwise from this recording. None if absent."""
        if item in self._branches:
            parent, from_turn = self._branches[item]
            if from_turn is None or turn < from_turn:
                return self._parent(parent).lookup(item, turn, role)
        return self._rows.get((item, turn, role))

    def complete(self, prompt: Any, max_tokens: int | None = None, key: tuple | None = None) -> str:
        if key is None:
            raise ValueError("a replay needs key=(item, turn) or (item, turn, role)")
        role = key[2] if len(key) > 2 else "planner"  # the role is the third element; a two-part key is a planner call
        row = self.lookup(key[0], key[1], role)
        if row is None:
            raise ReplayMiss(f"recording {self.name!r} has no reply for item {key[0]!r}, turn {key[1]}")
        got = prompt_sha256(prompt)
        if got != row["prompt_sha256"]:
            raise PromptMismatch(f"recording {self.name!r}: the prompt for {key[0]!r} turn {key[1]} differs from "
                                 "the one recorded; the harness, a tool or the system prompt has changed")
        return row["reply"]

    def items(self) -> list[str]:
        return sorted({key[0] for key in self._rows} | set(self._branches))  # a row key is (item, turn, role)


class ScriptedModel:
    """Canned replies for tests and Lab assignments: {item: [reply for turn 0, reply for turn 1, ...]}."""

    def __init__(self, replies: dict[str, list[str]]) -> None:
        self.replies = replies

    def complete(self, prompt: Any, max_tokens: int | None = None, key: tuple[str, int] | None = None) -> str:
        if key is None:
            raise ValueError("a scripted model needs key=(item, turn)")
        item, turn = key
        if item not in self.replies or turn >= len(self.replies[item]):
            raise ReplayMiss(f"no scripted reply for item {item!r}, turn {turn}")
        return self.replies[item][turn]
