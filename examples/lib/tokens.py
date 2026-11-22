"""Token counts for the book's prompts, on the pinned Qwen3-0.6B tokenizer.

Exports: count(text, special=True) -> int, ids(text, special=True) -> list[int], tokenizer() -> the tokenizers.Tokenizer.
Introduced in: chapter 4. The `tokenizers` library loads when the tokenizer first runs, never at import.

The tokenizer is the Qwen3-0.6B tokenizer.json at the commit that examples/models.toml pins. It is read offline from the
Hugging Face cache, and its size and SHA-256 are checked against the pin before it loads, as lib/detector.py does.

Agreement with the 4B model's tokenizer: see notes/probes.md, probe P-1. On 30 of the book's texts, the counts and ids
match the 4B GGUF's tokenizer exactly when control tokens are parsed, which is the recorder's baseline tokenisation of
the whole prompt. With control tokens switched off (the chapter 6 fix for untrusted text), the two differ on every text
that contains a marker such as <|im_start|>: 8 of the 30 texts. The default, special=True, parses them, so it is the
baseline count; special=False reads a marker as ordinary text, as the chapter 6 fix does.
"""
from __future__ import annotations

import hashlib
import json
import tomllib
from pathlib import Path

REPO = "Qwen/Qwen3-0.6B"
MODELS_TOML = Path(__file__).resolve().parent.parent / "models.toml"
FILE = "tokenizer.json"

_tokenizer = None  # the tokenizers.Tokenizer, once loaded
_plain_tokenizer = None  # the same tokenizer with its added (special) tokens removed, once built


def _pin() -> dict:
    """The models.toml entry for REPO. Raises KeyError when the repository is not pinned."""
    for entry in tomllib.loads(MODELS_TOML.read_text(encoding="utf-8")).get("model", []):
        if entry["repo"] == REPO:
            return entry
    raise KeyError(f"{REPO!r} is not pinned in examples/models.toml")


REVISION = str(_pin()["revision"])


def _verify(path: Path) -> None:
    """The file matches its pinned size and SHA-256. Raises ValueError when it does not."""
    pin = _pin()["files"][FILE]
    if path.stat().st_size != pin["size"]:
        raise ValueError(f"{FILE}: size {path.stat().st_size} is not the pinned {pin['size']}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    if digest.hexdigest() != pin["sha256"]:
        raise ValueError(f"{FILE}: SHA-256 does not match the pin in examples/models.toml")


def _load():
    """Load the tokenizer once, offline, from the pinned file."""
    global _tokenizer
    if _tokenizer is None:
        from huggingface_hub import snapshot_download
        from tokenizers import Tokenizer

        folder = Path(snapshot_download(REPO, revision=REVISION, allow_patterns=[FILE], local_files_only=True))
        _verify(folder / FILE)
        _tokenizer = Tokenizer.from_file(str(folder / FILE))
    return _tokenizer


def _plain():
    """The pinned tokenizer with its added tokens removed: special tokens off, so a chat marker is ordinary text."""
    global _plain_tokenizer
    if _plain_tokenizer is None:
        from tokenizers import Tokenizer

        spec = json.loads(_load().to_str())
        spec["added_tokens"] = []
        _plain_tokenizer = Tokenizer.from_str(json.dumps(spec))
    return _plain_tokenizer


def tokenizer():
    """The pinned tokenizers.Tokenizer, with its special tokens parsed (the baseline)."""
    return _load()


def ids(text: str, special: bool = True) -> list[int]:
    """The token ids of `text`, with no special tokens added at the start or end (no BOS, no EOS). special=False
    reads a chat marker such as <|im_start|> as ordinary text."""
    encoder = _load() if special else _plain()
    return encoder.encode(text, add_special_tokens=False).ids


def count(text: str, special: bool = True) -> int:
    """The number of tokens in `text` on the pinned tokenizer: len(ids(text, special))."""
    return len(ids(text, special))


def is_schema(text: str) -> bool:
    """True for one tool definition's JSON schema, as harness.tools_block writes it."""
    try:
        spec = json.loads(text)
    except ValueError:
        return False
    return isinstance(spec, dict) and "function" in spec


def growth(segments, changed, prompt_text):
    """The tokens a defence adds to one prompt, as (whole prompt, tool definitions). `segments` is the prompt before
    the defence and `changed` the prompt after it; prompt_text joins (text, role) segments into the prompt text. A
    defence that only adds a segment leaves the definitions as they were, so its share on them is 0."""
    added = count(prompt_text(changed)) - count(prompt_text(segments))
    idx = [i for i, (text, _) in enumerate(segments) if is_schema(text)]
    if not idx or len(changed) != len(segments):  # no definitions, or a segment added rather than changed in place
        return added, 0
    return added, (count("".join(changed[i][0] for i in idx))
                   - count("".join(segments[i][0] for i in idx)))


def sum_growth(growths):
    """One task's sums over its model calls, from a list of growth() pairs: (added, on tool definitions, calls)."""
    return sum(a for a, _ in growths), sum(s for _, s in growths), len(growths)


def columns(by_task):
    """The per-task sums from sum_growth, sorted by task ID, as four lists: added, on tool definitions, elsewhere
    and model calls."""
    rows = [by_task[task] for task in sorted(by_task)]
    added = [a for a, _, _ in rows]
    schemas = [s for _, s, _ in rows]
    return added, schemas, [a - s for a, s, _ in rows], [c for _, _, c in rows]
