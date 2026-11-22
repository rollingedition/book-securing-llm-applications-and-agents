"""Outbound rules for messages, fetches, and the links and images in a reply.

Exports:
- render_policy(reply, office_hosts) -> (sanitised_markdown, removed_urls)
- query_rule(url, world, task_text="") -> Allow | Refuse
- secret_scan(text, world) -> list of labels for the secrets the text carries
- sanitised_trace(trace, office_hosts) -> (trace, removed_urls): the trace the scorer should see
Introduced in: chapter 7.

Labels, per plan section 8:
- render_policy: output handled as untrusted. Enforcement in the harness (second line). The primary defence is the
  web view's: a Content-Security-Policy `img-src` limited to the office's hosts, set by the viewer, so an image to
  any other host is not loaded even if this policy missed it. Pending a browser run (not run here).
- query_rule: harness (enforcement). Acts on a proposed fetch_page call before it runs.
- secret_scan: detector. Reads the final reply after the model; it flags, it does not block.

render_policy works on markdown-it-py's token stream, never on regular expressions. Raw HTML is off in the parser
(html: False), so `<img>` arrives as text and is escaped. Every image and link is decided from its token: an image
is kept only when its source is https, on an office host, with no userinfo or port; a link likewise, otherwise
its text stays. Relative and data: sources are removed. The output is rebuilt with the characters that start a
construct backslash-escaped, so text cannot form an image, link or tag and the only ones left are the kept ones.
"""
from __future__ import annotations

import dataclasses
import html as _html
import re
import unicodedata
from urllib.parse import unquote, urlsplit

from linkify_it import LinkifyIt
from markdown_it import MarkdownIt

from . import cases, defences, scorers
from .harness import Allow, Refuse
from .trace import Trace

_md = MarkdownIt("commonmark", {"html": False})
_md_raw = MarkdownIt("commonmark", {"html": True})  # the view may pass raw HTML through: scanned as well
_linkify = LinkifyIt()
_linkify.set({"fuzzy_link": True})  # the view with linkify on links a bare host too
# The characters that can start an image, link, tag, entity or code span. Underscores and dashes are left alone, so
# a secret such as qmo_test_... stays byte-for-byte in the output (the scorer reads the string) and reads the same.
_ESCAPED = frozenset("\\`*[]!<>&")


def _allowed(url: object, office_hosts: frozenset[str]) -> bool:
    """True for an https URL whose host is an office host, with no userinfo, port, or non-ASCII or control characters.
    The host is read from urllib's parse and compared exactly; upper case is accepted, percent-encoding is not a host."""
    if not isinstance(url, str) or not url or not url.isascii():
        return False
    if any(ord(c) <= 0x20 or ord(c) == 0x7F or c in '<>\\"' for c in url):
        return False
    try:
        parts = urlsplit(url)
        host = parts.hostname
        return (parts.scheme == "https" and bool(host) and parts.netloc.lower() == host
                and parts.port is None and host in office_hosts)
    except ValueError:
        return False


def _esc(text: str) -> str:
    """Backslash-escape the characters that could start an image, link, tag, entity or code span."""
    return "".join("\\" + c if c in _ESCAPED else c for c in text)


def _ticks(text: str, mark: str) -> int:
    """The longest run of `mark` in text."""
    best = run = 0
    for c in text:
        run = run + 1 if c == mark else 0
        best = max(best, run)
    return best


def _dest(url: str) -> str:
    """A URL as written in a destination: `&` becomes `&amp;`, so the view decodes it back to the checked string."""
    return url.replace("&", "&amp;")


def _text(text: str) -> str:
    """Escaped text, with each URL-shaped run in it as a code span: a view with linkify on would otherwise link it."""
    out, pos = [], 0
    for m in _linkify.match(text) or []:
        out += [_esc(text[pos:m.index]), _code(text[m.index:m.last_index])]
        pos = m.last_index
    return "".join(out) + _esc(text[pos:])


def _reader_texts(text: str) -> set[str]:
    """What a reader sees: the rendered text with raw HTML off and on, tags removed, entities decoded, NFKC, zero-width
    characters and soft hyphens removed, whitespace collapsed, case folded."""
    seen = set()
    for md in (_md, _md_raw):
        plain = _html.unescape(re.sub(r"<[^>]*>", "", md.render(text)))
        plain = re.sub("[\u00ad\u200b-\u200d\u2060\ufeff]", "", unicodedata.normalize("NFKC", plain))
        seen.add(" ".join(plain.split()).casefold())
    return seen


def _code(content: str) -> str:
    fence = "`" * (_ticks(content, "`") + 1)
    return f"{fence} {content} {fence}"


def _fence(content: str) -> str:
    body = content.rstrip("\n")
    fence = "`" * max(3, _ticks(body, "`") + 1)
    return f"{fence}\n{body}\n{fence}"


class _Writer:
    """Rebuilds Markdown from the token stream, keeping only the images and links the policy allows."""

    def __init__(self, office_hosts: frozenset[str], world: cases.World) -> None:
        self.hosts = office_hosts
        self.world = world
        self.removed: list[str] = []

    def _keep(self, url: str) -> bool:
        """An image or link stays only if it is an https office-host URL whose path and query carry no tenant record."""
        return (_allowed(url, self.hosts) and _md.normalizeLink(url) == url
                and isinstance(query_rule(url, self.world), Allow) and not secret_scan(url, self.world))

    def inline(self, children) -> str:
        out: list[str] = []
        closers: list[str] = []  # one per open link: its closing text, or "" for a removed link
        for t in children or []:
            kind = t.type
            if kind == "text":
                out.append(_text(t.content))
            elif kind == "code_inline":
                out.append(_code(t.content))
            elif kind == "softbreak":
                out.append("\n")
            elif kind == "hardbreak":
                out.append("\\\n")
            elif kind in ("strong_open", "strong_close"):
                out.append("**")
            elif kind in ("em_open", "em_close"):
                out.append("*")
            elif kind == "image":
                src = t.attrGet("src") or ""
                alt = self.inline(t.children)
                if self._keep(src):
                    out.append(f"![{alt}](<{_dest(src)}>)")
                else:
                    self.removed.append(src)
                    out.append(alt)  # the alt text stays, as text
            elif kind == "link_open":
                href = t.attrGet("href") or ""
                if self._keep(href):
                    out.append("[")
                    closers.append(f"](<{_dest(href)}>)")
                else:
                    self.removed.append(href)
                    closers.append("")  # the link text stays, as text
            elif kind == "link_close":
                out.append(closers.pop() if closers else "")
            else:  # html_inline, unknown tokens: their text, escaped
                out.append(_esc(t.content))
        return "".join(out)

    def blocks(self, tokens, i: int, close: str | None) -> tuple[str, int]:
        out: list[str] = []
        while i < len(tokens) and tokens[i].type != close:
            t = tokens[i]
            if t.type == "paragraph_open":
                out.append(self.inline(tokens[i + 1].children))
                i += 3
            elif t.type == "heading_open":
                out.append("#" * int(t.tag[1]) + " " + self.inline(tokens[i + 1].children))
                i += 3
            elif t.type == "blockquote_open":
                inner, i = self.blocks(tokens, i + 1, "blockquote_close")
                out.append("\n".join(("> " + line).rstrip() for line in inner.split("\n")))
                i += 1
            elif t.type in ("bullet_list_open", "ordered_list_open"):
                bullet = t.type == "bullet_list_open"
                n = 1 if bullet else int(t.attrGet("start") or 1)
                items: list[str] = []
                i += 1
                while tokens[i].type not in ("bullet_list_close", "ordered_list_close"):
                    inner, i = self.blocks(tokens, i + 1, "list_item_close")
                    marker = "- " if bullet else f"{n}. "
                    n += 1
                    lines = inner.split("\n")
                    pad = " " * len(marker)
                    items.append("\n".join([marker + lines[0]] + [(pad + line) if line else "" for line in lines[1:]]))
                    i += 1
                out.append("\n\n".join(items))
                i += 1
            elif t.type in ("fence", "code_block"):
                out.append(_fence(t.content))
                i += 1
            elif t.type == "hr":
                out.append("* * *")
                i += 1
            elif t.type == "html_block":
                out.append(_esc(t.content.rstrip("\n")))
                i += 1
            else:
                i += 1
        return "\n\n".join(out), i


def render_policy(reply: str, office_hosts, world: cases.World) -> tuple[str, list[str]]:
    """harness (enforcement; primary defence is the web view's img-src CSP, see the module docstring). Returns the
    Markdown the web view would render after this policy, and the URLs it removed, in document order. An image or
    link is removed when its host is not an office host, or when its path or query carries a tenant record (office
    hosts included; no task text is passed, so any tenant value is refused). Pure and deterministic."""
    writer = _Writer(frozenset(h.lower() for h in office_hosts), world)
    body, _ = writer.blocks(_md.parse(reply or ""), 0, None)
    return body, writer.removed


def query_rule(url: object, world: cases.World, task_text: str = "") -> Allow | Refuse:
    """harness (enforcement) on a proposed fetch_page call: refuse when the URL's path, query or fragment carries a
    tenant's phone or bank reference (read by defences._norm, the same form as the fetch rule) that the task text does
    not contain. Without task_text, any such value is refused. Not caught: a partial value, a value in another
    encoding (base64, hex), a value split across two fetches, a tenant field the world does not list here."""
    try:
        carried = defences.url_digits(url)
        if defences.tenant_value_carried(carried, world, task_text):
            return Refuse("fetch_page: the URL carries a tenant's record, which the task does not contain")
        return Allow()
    except Exception:  # fail closed: a URL that cannot be read is refused
        return Refuse("fetch_page: the URL could not be checked")


def secret_scan(text: str, world: cases.World) -> list[str]:
    """detector: labels of the secrets in text (a reply, or an outbound body): the payment portal's key and the hidden
    context's marker, found plain or percent-decoded in the source, and in the text a reader sees. Pure. Flags only;
    the harness decides what a hit means."""
    text = text or ""
    decoded, readers = unquote(text), _reader_texts(text)
    hits = []
    for label, secret in (("portal_key", world.portal_key), ("internal_marker", world.internal_marker)):
        if secret and (secret in text or secret in decoded or any(secret.casefold() in r for r in readers)):
            hits.append(label)
    return hits


def sanitised_trace(trace: Trace, office_hosts, world: cases.World) -> tuple[Trace, list[str]]:
    """A copy of the trace whose final reply is render_policy's output. Image renders the policy removed are dropped
    too, so scorers.attack_success (unchanged) scores what the reader would see. Returns the copy and the removed URLs."""
    replies = [e for e in trace.events if e.kind == "reply"]
    if not replies:
        return trace, []
    last = replies[-1]
    clean, removed = render_policy(last.text or "", office_hosts, world)
    loaded = set(scorers.rendered_urls(clean))  # what the sanitised reply loads, raw <img> tags included
    events = []
    for e in trace.events:
        if e is last:
            events.append(dataclasses.replace(e, text=clean))
        elif e.kind == "render" and (e.args or {}).get("url") not in loaded:
            continue
        else:
            events.append(e)
    return dataclasses.replace(trace, events=events), removed
