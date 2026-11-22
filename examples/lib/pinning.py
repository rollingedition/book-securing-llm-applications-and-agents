"""Hashes of tool definitions, the check that refuses a definition that changed after it was pinned, and the checks
that compare a tool's declared effect and arguments with what it does.

Exports: definition_hash(tool), pin_tools(server), check_pins(pins, server), listable(pins, server),
load_json_strict(text), read_pins(path, server_name), write_pins(path, server_name, pins); for claims,
declared_effect(tool), ReadRecorder(args), claim_verdict(declared, writes, approved_writes), rugged_copy(server, name,
sentence); and for model folders, unpinned_files(folder, pinned).
Introduced in: chapter 10. Only standard-library modules are imported; no model or tool code loads.

A definition is the whole object a server sends for one tool: every key, not a chosen subset. It is hashed as canonical
JSON: strings in Unicode NFC form, keys sorted, no insignificant whitespace, numbers as JSON gives them. A key that
would collide with another after NFC is refused. A pin is the hash taken when a person approved the definition.

The listing gate offers only tools that verify. Any tool whose name appears more than once in a server's listing makes
the whole server unlistable. What the gate returns is a frozen copy, made after the check, so a caller cannot change
what was verified and the model sees exactly the canonical form that was hashed.

The behaviour check compares what a definition declares (its annotations, and the names in its parameters) with what
its tool does: the tables it writes on a fresh call, and the arguments its code reads. It does not judge the text of
a description. An instruction written into a description is tool poisoning; this check does not detect it.
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import unicodedata
from pathlib import Path

SCHEMA = 1  # the pins file's format version


def _canon(value):
    """The value with every string in NFC form. Two keys that collide after NFC are refused, not merged."""
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            norm = _canon(key)
            if norm in out:
                raise ValueError(f"two keys are the same after NFC normalisation: {norm!r}")
            out[norm] = _canon(item)
        return out
    if isinstance(value, (list, tuple)):
        return [_canon(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("a definition may not contain NaN or infinity")
    return value


def _no_duplicates(pairs: list) -> dict:
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate key in a definition: {key!r}")
        out[key] = value
    return out


def load_json_strict(text: str):
    """json.loads that refuses an object with a repeated key, rather than keeping the last one."""
    return json.loads(text, object_pairs_hook=_no_duplicates)


def definition_hash(tool: dict) -> str:
    """SHA-256 of the canonical JSON of every key of one tool definition."""
    canonical = json.dumps(_canon(tool), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _names(server: list[dict]) -> list[str]:
    return [tool["name"] for tool in server]


def duplicate_names(server: list[dict]) -> list[str]:
    """Tool names that appear more than once in a server's listing, in name order."""
    names = _names(server)
    return sorted({name for name in names if names.count(name) > 1})


def pin_tools(server: list[dict]) -> dict[str, str]:
    """Name -> hash for every tool the server offers, in name order. A server with a duplicate name is not pinned."""
    if duplicate_names(server):
        raise ValueError("a server with a duplicate tool name cannot be pinned")
    return {tool["name"]: definition_hash(tool) for tool in sorted(server, key=lambda t: t["name"])}


def check_pins(pins: dict[str, str], server: list[dict]) -> dict[str, str]:
    """A verdict per tool name: verified, changed (the hash differs), unpinned (offered but never approved),
    removed (pinned but no longer offered), or duplicate (the name is offered more than once)."""
    dupes = set(duplicate_names(server))
    current = {tool["name"]: tool for tool in server if tool["name"] not in dupes}
    verdicts = {}
    for name in sorted(set(pins) | set(_names(server))):
        if name in dupes:
            verdicts[name] = "duplicate"
        elif name not in current:
            verdicts[name] = "removed"
        elif name not in pins:
            verdicts[name] = "unpinned"
        elif definition_hash(current[name]) == pins[name]:
            verdicts[name] = "verified"
        else:
            verdicts[name] = "changed"
    return verdicts


class Frozen(dict):
    """A dict that cannot be changed. Copying it gives an ordinary dict the caller owns."""

    def _refuse(self, *args, **kwargs):
        raise TypeError("a verified tool definition cannot be changed")

    __setitem__ = __delitem__ = clear = pop = popitem = setdefault = update = __ior__ = _refuse

    def __reduce__(self):
        return (dict, (dict(self),))


def _freeze(value):
    if isinstance(value, dict):
        return Frozen((key, _freeze(item)) for key, item in value.items())
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def listable(pins: dict[str, str], server: list[dict]) -> tuple[dict, ...]:
    """The frozen, verified definitions the harness may list to the model, in name order. The copy is taken and
    verified first, and the frozen copy is made from the canonical form that was hashed. A server with a duplicate
    name lists nothing: the whole server is refused, not one copy of it."""
    if duplicate_names(server):
        return ()
    copies = {tool["name"]: _canon(copy.deepcopy(tool)) for tool in server}
    verdicts = check_pins(pins, list(copies.values()))
    return tuple(_freeze(copies[name]) for name in sorted(copies) if verdicts[name] == "verified")


def read_pins(path: Path, server_name: str | None = None) -> dict[str, str]:
    """The tool pins from a pins file written by write_pins. With server_name, a file for another server is refused."""
    data = load_json_strict(path.read_text(encoding="utf-8"))
    if data.get("schema") != SCHEMA:
        raise ValueError(f"pins file has schema {data.get('schema')!r}, expected {SCHEMA}")
    if server_name is not None and data.get("server") != server_name:
        raise ValueError(f"pins file is for server {data.get('server')!r}, not {server_name!r}")
    return dict(data["tools"])


def write_pins(path: Path, server_name: str, pins: dict[str, str]) -> None:
    """Write the pins with the hash's rule beside them, so a reader can recompute each hash."""
    data = {
        "schema": SCHEMA,
        "server": server_name,
        "hash": "sha256 of canonical JSON of the whole definition: every key; NFC strings; sorted keys, no spaces",
        "tools": dict(sorted(pins.items())),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


# Claims: what a definition declares about its effect, checked against what its tool does on a fresh call.

def declared_effect(tool: dict) -> str:
    """The effect the annotations declare: read-only, write, undeclared, conflict or invalid. The description's text is
    not read: a first word is not a claim."""
    annotations = tool.get("annotations", {})
    read_only, destructive = annotations.get("readOnlyHint"), annotations.get("destructiveHint")
    if any(v is not None and not isinstance(v, bool) for v in (read_only, destructive)):
        return "invalid"
    if read_only is True:
        return "conflict" if destructive is True else "read-only"
    if read_only is False or destructive is True:
        return "write"
    return "undeclared"


def claim_verdict(declared: str, writes, approved_writes=()) -> str:
    """Whether the declared effect agrees with the tables written. A read-only claim is wrong if anything was written.
    A write claim agrees only when the tables written are exactly the tables approved at pin time. A tool that declares
    nothing agrees only if it writes nothing. Anything else disagrees."""
    written, approved = set(writes), set(approved_writes)
    if declared == "read-only":
        return "agrees" if not written else "disagrees"
    if declared == "write":
        return "agrees" if written and written == approved else "disagrees"
    if declared == "undeclared":
        return "disagrees" if written else "undeclared"
    return "disagrees"


class ReadRecorder(dict):
    """An argument dict that records each key the code names: a subscript, get() or `in`. The tool's own code fills the
    record. Iterating the whole dict is not recorded, because the harness's schema check iterates every argument; a
    branch that reads arguments by iterating is therefore not seen, and the chapter says so."""

    def __init__(self, data: dict):
        super().__init__(data)
        self.read: set[str] = set()

    def __getitem__(self, key):
        self.read.add(key)
        return super().__getitem__(key)

    def get(self, key, default=None):
        self.read.add(key)
        return super().get(key, default)

    def __contains__(self, key):
        self.read.add(key)
        return super().__contains__(key)


def rugged_copy(server: list[dict], tool_name: str, sentence: str) -> list[dict]:
    """A copy of the server in which one tool's description gains a sentence: a rug pull, built for the example."""
    copied = copy.deepcopy(server)
    for tool in copied:
        if tool["name"] == tool_name:
            tool["description"] = f"{tool['description']} {sentence}"
    return copied


# Model folders: the folder must hold exactly the pinned files. Names are listed; no file is opened.

def unpinned_files(folder: Path, pinned: set[str]) -> list[str]:
    """Every entry in the folder, at any depth, whose relative path is not pinned, in order. Only names are read."""
    found = []
    for root, dirs, files in sorted(os.walk(folder)):
        for entry in dirs + files:
            rel = (Path(root) / entry).relative_to(folder).as_posix()
            if rel not in pinned:
                found.append(rel)
    return sorted(found)


# Dependency pins: every line of a requirements file is either a comment, a blank line, the one reviewed option, or an
# exact name==version pin. Nothing else passes: no wildcard, marker, URL, extra, include, index or hash line.

ALLOWED_OPTIONS = ("--extra-index-url https://download.pytorch.org/whl/cpu",)  # the index the book uses
_NAME = r"[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?"
_PEP440 = (r"(\d+!)?\d+(\.\d+)*((a|b|rc)\d+)?(\.post\d+)?(\.dev\d+)?"  # the public version, release and suffixes
           r"(\+[a-z0-9]+(\.[a-z0-9]+)*)?")  # an optional local label
_PIN = re.compile(rf"{_NAME}==({_PEP440})")


def line_verdict(raw: str) -> str:
    """'skip' for a blank or comment line, 'option allowed' or 'option refused' for a line that starts with '-', and
    'pinned' or 'refused' for a requirement line. A requirement is judged on its exact text: a leading space, a
    trailing space, a marker, a URL or a wildcard makes it refused."""
    if raw.strip() == "" or raw.lstrip().startswith("#"):
        return "skip"
    if raw.startswith("-"):
        return "option allowed" if raw in ALLOWED_OPTIONS else "option refused"
    return "pinned" if _PIN.fullmatch(raw) else "refused"


def lockfile_verdicts(text: str) -> dict[str, int]:
    """Counts of each verdict over the lines of a requirements file; 'hash' counts every line that names a hash."""
    counts = {"skip": 0, "pinned": 0, "refused": 0, "option allowed": 0, "option refused": 0, "hash": 0}
    for raw in text.splitlines():
        counts[line_verdict(raw)] += 1
        counts["hash"] += raw.count("--hash")
    return counts
