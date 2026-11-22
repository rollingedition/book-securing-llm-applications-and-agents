"""BM25 retrieval over the office's documents, with an access check per document (chapter 9).

Exports: label(doc), may_read(label, user), visible(documents, user), search(query, user, k, documents).
Introduced in: chapter 9.

The access label comes from the case data, with no new field: an external document (a tenant's letter, a contractor's
quote) is about one person or job, so it is owner-only; an office policy that states a figure is staff; any other office
document (a template, a rota, house rules) is public. A staff label needs a staff role in office.json; an owner-only
label needs the office manager's role.

The filter runs before ranking. tools.search_documents builds its index from the rows it is given, so a document the
user cannot read never enters the index or the IDF. Filtering the top k afterwards would leak through the scores.
"""
from __future__ import annotations

import json

from . import cases

PUBLIC, STAFF, OWNER_ONLY = "public", "staff", "owner-only"
OWNER_ROLE = "office manager"


def label(doc: dict) -> str:
    """The access label of a document, from its source and its fact (see the module docstring). It fails closed: a
    missing, unknown or odd-cased source (SEC9-05) is owner-only, so only an exact 'office' source can be public."""
    source = doc.get("source")
    if source == "office":
        return STAFF if doc.get("fact") else PUBLIC
    return OWNER_ONLY  # 'external', and any source the labels do not name


def _role(user: str) -> str | None:
    """The user's role in office.json's staff list. A user not on the list has no role."""
    staff = json.loads((cases.DATA / "office.json").read_text(encoding="utf-8"))["staff"]
    return next((member["role"] for member in staff if member["id"] == user), None)


def may_read(doc_label: str, user: str) -> bool:
    """Whether the user may read a document with this label."""
    if doc_label == PUBLIC:
        return True
    if doc_label == STAFF:
        return _role(user) is not None
    return _role(user) == OWNER_ROLE


def visible(documents: list[dict], user: str) -> list[dict]:
    """The documents the user may read, in their given order."""
    return [doc for doc in documents if may_read(label(doc), user)]


def search(query: str, user: str, k: int = 5, documents: list[dict] | None = None) -> list[dict]:
    """The best k documents the user may read, ranked by (-score, doc_id) over those documents only."""
    from . import tools  # imported here: tools loads bm25s, and this module stays light until a search runs

    rows = documents if documents is not None else json.loads((cases.DATA / "documents.json").read_text(encoding="utf-8"))["documents"]
    return tools.search_documents(query, k, visible(rows, user))
