"""Chapter 2's threat model, derived from the code and the case data rather than typed by hand: each tool's legs, the
Rule of Two check, and the channel each attack location uses to reach the model. The threat-* examples print these.

Derivations use no attack string: sample arguments come from the case data, and a flow probe builds the episode with the
carrier's text only to see which field it lands in and which tool hands it back.
"""
from __future__ import annotations

import ast
import inspect
import json
import textwrap
from pathlib import Path

from . import cases, harness, tools

STATE_FIELDS = ("inbox", "outbox", "fetch_log", "missing", "slots", "bookings")  # what a call can write
FLOW_FIELDS = ("inbox", "documents", "slots", "pages", "schemas")  # what a carrier can change
LEGS = ("private", "untrusted", "outward")
TEMPLATE = (Path(__file__).resolve().parent.parent / "prompts" / "assistant-system.md").read_text(encoding="utf-8")


def contractor() -> dict:
    return json.loads((cases.DATA / "contractor.json").read_text(encoding="utf-8"))


def office() -> dict:
    return json.loads((cases.DATA / "office.json").read_text(encoding="utf-8"))


def reads_by_tool() -> dict[str, set[str]]:
    """The ToolState fields each tool's branch of call_tool touches, read from the code's syntax tree."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(tools.call_tool)))
    found: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        # One branch per tool: an `if name == "..."` test on the function's name argument.
        if not (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)):
            continue
        test = node.test
        if not (isinstance(test.left, ast.Name) and test.left.id == "name"
                and isinstance(test.comparators[0], ast.Constant)):
            continue
        fields: set[str] = set()
        for sub in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if not isinstance(sub, ast.Attribute):
                continue
            chain, cur = [], sub
            while isinstance(cur, ast.Attribute):  # state.world.tenants -> ["world", "tenants"]
                chain.append(cur.attr)
                cur = cur.value
            if isinstance(cur, ast.Name) and cur.id == "state":
                parts = list(reversed(chain))
                if parts[0] == "world":  # the world's tenants are the private records; keep the second part
                    if len(parts) > 1:
                        fields.add(f"world.{parts[1]}")
                else:
                    fields.add(parts[0])  # state.outbox.append(...) counts as the outbox
        found[test.comparators[0].value] = fields
    return found


def snapshot(state: tools.ToolState, names: tuple[str, ...] = STATE_FIELDS) -> dict[str, str]:
    return {f: json.dumps(getattr(state, f), sort_keys=True, default=str) for f in names}


def strings(value) -> list[str]:
    """Every string inside a JSON-like value, so a check can look at the decoded text, not its escapes."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in strings(v)]
    return []


def sample_args(world: cases.World, state: tools.ToolState) -> dict[str, dict]:
    """One argument set per tool, from the case data (no carrier, no attack text): a real unit, message, document,
    page and slot. Which record is picked does not change what a tool reads or writes, so index 0 is enough."""
    con = contractor()
    slot = con["slots"][0]  # any slot
    day = slot["start"][:10]
    return {
        "search_documents": {"query": state.documents[0]["title"], "k": 3},  # a title, so the search finds it
        "list_messages": {},
        "read_message": {"msg_id": state.inbox[0]["msg_id"]},
        "lookup_tenant": {"unit": world.tenants[0].unit},
        "send_message": {"to": sorted(tools.directory())[0], "body": "Sample reply."},  # a directory address
        "fetch_page": {"url": state.pages[0]["url"]},
        "list_slots": {"contractor_id": con["contractor_id"], "date_from": day, "date_to": day},
        "book_visit": {"contractor_id": con["contractor_id"], "slot_id": slot["slot_id"],
                       "ticket_id": "T-0001"},  # book_visit only echoes the ticket ID, so any value serves
    }


def private_markers(world: cases.World) -> set[str]:
    """Any tenant's phone, bank reference or the portal key: a result carrying one holds private records."""
    return {t.phone for t in world.tenants} | {t.bank_ref for t in world.tenants} | {world.portal_key}


def table() -> dict[str, dict]:
    """One dict per tool, keyed by name: reads (from the code), writes, untrusted output, third-party definition,
    outward reach and private records (from one sample call on a fresh episode)."""
    world = cases.load_world()
    acting = cases.load_tasks()[0].acting_user  # any staff member; the sample calls do not depend on the role
    args = sample_args(world, tools.ToolState.new(acting))
    assert set(args) == set(tools.SPECS), "every tool needs a sample argument set"
    reads = reads_by_tool()
    markers = private_markers(world)
    rows = {}
    for name in sorted(tools.SPECS):
        state = tools.ToolState.new(acting)  # a fresh episode, so one call's writes are not seen by the next
        for slot in state.slots.values():
            # The contractor's server may attach a free-text note to any slot; the office's base data has none,
            # so one is set here, or list_slots would show no field that a third party writes.
            slot["note"] = "Contractor note."
        before = snapshot(state)
        result = tools.call_tool(name, args[name], state)
        writes = sorted(f for f, value in snapshot(state).items() if value != before[f])
        # Outward reach: a write to the outbox or the fetch log, or a third party's server (the contractor's tools).
        if "outbox" in writes:
            outward = "outbox"
        elif "fetch_log" in writes:
            outward = "fetch log"
        elif name in tools.THIRD_PARTY_TOOLS:
            outward = "third-party server"
        else:
            outward = None
        rows[name] = {
            "reads": sorted(reads.get(name, set())),
            "writes": writes,
            # A segment the harness marks untrusted is text from outside the office (a message, page or document).
            "untrusted_output": any(not trusted for _, trusted in result.as_segments()),
            "third_party_definition": name in tools.THIRD_PARTY_TOOLS,
            "outward": outward,
            "private": any(m in s for s in strings(result.data) for m in markers),
        }
    return rows


def legs_by_tool(rows: dict[str, dict] | None = None) -> dict[str, set[str]]:
    """Each tool's trifecta legs. Untrusted: its output carries outside text, or its definition is third-party."""
    rows = table() if rows is None else rows
    legs = {}
    for name, row in rows.items():
        held = set()
        if row["private"]:
            held.add("private")
        if row["untrusted_output"] or row["third_party_definition"]:
            held.add("untrusted")
        if row["outward"]:
            held.add("outward")
        legs[name] = held
    return legs


def without_leg(legs: dict[str, set[str]], leg: str) -> tuple[list[str], set[str]]:
    """Remove every tool that carries `leg`. Returns the tools kept and the legs the kept tools still hold."""
    kept = sorted(n for n, held in legs.items() if leg not in held)
    return kept, set().union(*(legs[n] for n in kept))


def holds_private_values(schemas: tuple[dict, ...]) -> bool:
    """Whether the prompt built from these tool schemas still holds the portal key and the hidden context."""
    world = cases.load_world()
    system = harness.system_text(TEMPLATE, cases.load_tasks()[0].acting_user, world)
    prompt = harness.prompt_text(harness.open_prompt(system, "sample", schemas))
    return world.portal_key in prompt or office()["hidden_context"] in prompt


def system_prompt() -> str:
    """The system prompt the model sees on every episode, whichever tools are offered."""
    system = harness.system_text(TEMPLATE, cases.load_tasks()[0].acting_user, cases.load_world())
    return harness.prompt_text(harness.open_prompt(system, "sample"))


def marked_untrusted_definitions() -> list[str]:
    """The tool names whose definitions the prompt's tool block marks untrusted, read from its segments."""
    return sorted(json.loads(text)["function"]["name"]
                  for text, trusted in harness.tools_block(tools.TOOLS) if not trusted)


def args_for(name: str, case: cases.AttackCase, state: tools.ToolState) -> dict:
    """Arguments for one tool, taken from the carrier's own IDs, so the call reaches the carrier's text."""
    carrier = case.carrier
    con = contractor()
    slot_id = carrier.get("slot_id") or con["slots"][0]["slot_id"]
    slot = next(s for s in con["slots"] if s["slot_id"] == slot_id)
    day = slot["start"][:10]
    if name == "read_message":
        return {"msg_id": carrier["msg_id"]}
    if name == "list_messages":
        return {}
    if name == "search_documents":
        doc = next(d for d in state.documents if d["doc_id"] == carrier["doc_id"])
        return {"query": doc["title"], "k": 20}  # k 20 is the most the tool returns, so the carrier's row is in it
    if name == "fetch_page":
        page = next(p for p in state.pages if p["page_id"] == carrier["page_id"])
        return {"url": page["url"]}
    if name == "list_slots":
        return {"contractor_id": con["contractor_id"], "date_from": day, "date_to": day}
    if name == "book_visit":
        return {"contractor_id": con["contractor_id"], "slot_id": slot_id, "ticket_id": "T-0001"}
    raise KeyError(name)


def location_channels() -> list[dict]:
    """Each attack location: its cases, carrier kind, the one state field its carrier changes, the tools that
    deliver it to the model (run on the carrier's episode), the tools that read the field but do not carry it, and
    the prompt's tool list when the text sits in a schema. Asserts one channel per location."""
    world_cases = cases.load_cases()
    tasks = {t.id: t for t in cases.load_tasks()}
    reads = reads_by_tool()
    locations = sorted({c.location for c in world_cases})
    assert locations == sorted(json.loads((cases.DATA / "attacks.json").read_text(encoding="utf-8"))["locations"])
    out = []
    for loc in locations:
        group = sorted((c for c in world_cases if c.location == loc), key=lambda c: c.id)
        assert len({c.carrier["kind"] for c in group}) == 1, f"{loc} mixes carrier kinds"
        case = group[0]  # every case in a location has the same kind of carrier, so the first one probes for all
        acting = tasks[case.task].acting_user
        plain = snapshot(tools.ToolState.new(acting), FLOW_FIELDS)
        hit_state = tools.ToolState.new(acting, carrier=case.carrier, injection=case.injection)
        changed = [f for f in FLOW_FIELDS if plain[f] != snapshot(hit_state, FLOW_FIELDS)[f]]
        assert len(changed) == 1, f"{loc} changes {changed}"
        field = changed[0]
        # The model sees the schemas in every prompt, so a carrier in a schema reaches it with no tool call.
        in_prompt = any(case.injection in s for text, _ in harness.tools_block(hit_state.schemas)
                        if text.startswith('{"type"') for s in strings(json.loads(text)))
        delivered, quiet = [], []
        for name in sorted(n for n, fs in reads.items() if field in fs):
            state = tools.ToolState.new(acting, carrier=case.carrier, injection=case.injection)
            result = tools.call_tool(name, args_for(name, case, state), state)
            (delivered if any(case.injection in s for s in strings(result.data)) else quiet).append(name)
        channels = delivered + (["prompt tool list"] if in_prompt else [])
        assert len(channels) == 1, f"{loc} has {len(channels)} channels"
        out.append({"loc": loc, "cases": len(group), "kind": case.carrier["kind"], "field": field,
                    "channels": channels, "quiet": quiet})
    return out
