"""The pinned models the recordings run, on the CPU with llama.cpp. Recording-side only: no example imports this.

- QWEN4B: Qwen3-4B-Instruct-2507, Q4_K_M GGUF (Unsloth's conversion, Apache-2.0). The assistant under test, and the
  attacker in chapter 11. The 2507 Instruct model has no thinking switch, so its template is used as shipped.
- QWEN06B: Qwen3-0.6B, Q8_0 GGUF (Qwen's own, Apache-2.0). The smaller model in chapter 4. Thinking is off by
  rendering the chat template ourselves with enable_thinking=False and completing the raw prompt.

Each file is pinned by repository, commit and SHA-256. `fetch()` downloads a file once into the folder named by the
RE_MODELS environment variable (default: a folder named scratch/rec/models under the home folder) and checks its hash
before use. `fetch()` needs only the standard library, so the pins can be checked without the recording runtime.

Sampling is per recording (see the constants below). Every call takes a seed, so a variance recording can vary it.
"""
from __future__ import annotations

import hashlib
import os
import urllib.request
from dataclasses import dataclass
from pathlib import Path

SEED = 4217
THREADS = 4
CONTEXT = 4096
ANSWER_SAMPLING = {"temperature": 0.0, "max_tokens": 160}
JUDGE_SAMPLING = {"temperature": 0.0, "max_tokens": 160}
VARIANCE_SAMPLING = {"temperature": 0.7, "top_p": 0.8, "top_k": 20, "min_p": 0.0, "max_tokens": 160}
TOOL_CAP = 96  # output tokens for a tool call; a final reply may run to 200 (plan section 17, decision 1)


@dataclass(frozen=True)
class Pin:
    """One GGUF file: where it comes from, what it is, and how it is run."""

    model: str
    repository: str
    revision: str
    filename: str
    sha256: str
    licence: str
    thinking_off: bool


QWEN4B = Pin(
    model="Qwen/Qwen3-4B-Instruct-2507",
    repository="unsloth/Qwen3-4B-Instruct-2507-GGUF",
    revision="a06e946bb6b655725eafa393f4a9745d460374c9",
    filename="Qwen3-4B-Instruct-2507-Q4_K_M.gguf",
    sha256="3605803b982cb64aead44f6c1b2ae36e3acdb41d8e46c8a94c6533bc4c67e597",
    licence="Apache-2.0",
    thinking_off=False,
)
QWEN06B = Pin(
    model="Qwen/Qwen3-0.6B",
    repository="Qwen/Qwen3-0.6B-GGUF",
    revision="23749fefcc72300e3a2ad315e1317431b06b590a",
    filename="Qwen3-0.6B-Q8_0.gguf",
    sha256="9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031",
    licence="Apache-2.0",
    thinking_off=True,
)


def models_folder() -> Path:
    """The folder the model files live in: RE_MODELS, else scratch/rec/models under the home folder."""
    return Path(os.environ.get("RE_MODELS") or Path.home() / "scratch" / "rec" / "models")


def fetch(pin: Pin) -> Path:
    """The model file for this pin, downloaded at its revision if absent, and checked against its SHA-256."""
    folder = models_folder()
    path = folder / pin.filename
    if not path.exists():
        folder.mkdir(parents=True, exist_ok=True)
        url = f"https://huggingface.co/{pin.repository}/resolve/{pin.revision}/{pin.filename}"
        partial = path.with_suffix(".part")
        urllib.request.urlretrieve(url, partial)
        partial.rename(path)
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    if digest.hexdigest() != pin.sha256:
        raise RuntimeError(f"{pin.filename} doesn't match its pinned SHA-256; delete it and fetch it again")
    return path


class LocalModel:
    """A pinned model with one method: complete(messages, seed) -> the raw reply text."""

    def __init__(self, pin: Pin = QWEN4B, sampling: dict | None = None, threads: int = THREADS) -> None:
        from llama_cpp import Llama

        self.pin = pin
        self.sampling = dict(ANSWER_SAMPLING if sampling is None else sampling)
        self.llm = Llama(model_path=str(fetch(pin)), n_ctx=CONTEXT, n_threads=threads, seed=SEED, verbose=False)
        self._template = self.llm.metadata.get("tokenizer.chat_template", "")

    def _render(self, messages: list[dict[str, str]]) -> str:
        """The chat template rendered with thinking off, ending in the generation prompt."""
        import jinja2

        env = jinja2.Environment(trim_blocks=False, lstrip_blocks=False)

        def raise_exception(message: str) -> None:
            raise jinja2.TemplateError(message)

        env.globals["raise_exception"] = raise_exception
        template = env.from_string(self._template)
        return template.render(messages=messages, add_generation_prompt=True, enable_thinking=False)

    def _tokenize(self, text: str, special: bool) -> list[int]:
        return self.llm.tokenize(text.encode("utf-8", "surrogatepass"), add_bos=False, special=special)

    def complete_prompt(self, segments: list, *, special_in_untrusted: bool = True, max_tokens: int = 200) -> str:
        """The reply to a prompt built as segments (examples/lib/harness.py), tokenised as the mode says.

        A tool call is capped at TOOL_CAP tokens: the first pass stops at </tool_call>. A reply with no tool call
        that hit the cap is generated again up to max_tokens, from the same prompt (temperature 0, so the same text
        comes first). A call cut off by the cap is returned as it is, and the harness records it as malformed.
        """
        from lib.harness import to_tokens  # assistant.py puts examples/ on the path

        self.llm.set_seed(SEED)
        tokens = to_tokens(self._tokenize, segments, special_in_untrusted)
        text, finish = self._generate(tokens, TOOL_CAP)
        if "<tool_call>" not in text and finish == "length" and max_tokens > TOOL_CAP:
            text, _ = self._generate(tokens, max_tokens)
        return text

    def _generate(self, tokens: list[int], max_tokens: int) -> tuple[str, str]:
        out = self.llm.create_completion(tokens, max_tokens=max_tokens, temperature=0.0, seed=SEED,
                                         stop=["</tool_call>"])
        choice = out["choices"][0]
        return choice["text"], choice["finish_reason"]

    def complete(self, messages: list[dict[str, str]], seed: int = SEED) -> str:
        """The model's reply to the messages, as raw text. Every call starts from `seed`."""
        self.llm.set_seed(seed)
        if self.pin.thinking_off:
            out = self.llm.create_completion(self._render(messages), seed=seed, stop=["<|im_end|>"], **self.sampling)
            return out["choices"][0]["text"]
        out = self.llm.create_chat_completion(messages=messages, seed=seed, **self.sampling)
        return out["choices"][0]["message"]["content"]


def describe(pin: Pin, sampling: dict) -> dict:
    """What a manifest records about the model and how it ran. Contains no paths."""
    import llama_cpp

    return {
        "model": pin.model,
        "model_version": f"{pin.repository}@{pin.revision} {pin.filename} sha256:{pin.sha256}",
        "licence": pin.licence,
        "runner": f"llama-cpp-python {llama_cpp.__version__}, CPU, {THREADS} threads",
        "sampling": dict(sampling),
        "seed": SEED,
        "thinking": "off (template rendered with enable_thinking=False)" if pin.thinking_off else "none in this model",
    }
