"""The closed typed term language every ``sec_*`` module shares.

Pure data plus validation — no z3, no file IO, and no imports from
:mod:`gcp_grounding.constraints` or :mod:`gcp_grounding.reasoner`. This module
is the vocabulary the requirements compiler (``sx-sec-compile``), the encoder
(``sx-sec-encode``) and the artifact writer (``sx-sec-artifact``) all agree on.

An AST is a tree of plain ``dict`` nodes, each carrying a ``"node"`` key naming
its kind. Terms carry a *sort* drawn from :data:`SORTS`; :func:`validate` is one
recursive pass that rejects every ill-typed or ill-formed shape, naming the
offending path (e.g. ``and.args[1].cmp.right``). :func:`canonical` gives a
deterministic normal form so the committed artifact is byte-stable under trivial
source reorderings, mirroring ``fetch.write_snapshot`` at fetch.py:344-349.

Collections referenced by quantifiers come from :data:`COLLECTIONS`, a registry
seeded with the four base entries and extended by the six domain sections
through :func:`register_collection`. The domain collections are resolved lazily
by :func:`_ensure_domains`, fail-open exactly like ``preflight._tf_plan_extractor``
so a checkout without ``sec_domains`` simply keeps the four base collections and
reports :class:`UnknownCollection` for every domain promise.
"""

from __future__ import annotations

import importlib
import json
import re
from dataclasses import dataclass
from typing import Mapping

from .core.log import get_logger

logger = get_logger(__name__)

__all__ = [
    "SORTS", "BV_WIDTHS", "TIERS", "MAX_DEPTH",
    "CollectionSpec", "COLLECTIONS", "tier_rank", "register_collection",
    "reset_domain_cache",
    "UnknownCollection", "InvalidAst",
    "validate", "sort_of", "canonical", "dumps", "render_sexpr",
    "collections_used", "derived_tier", "free_consts",
    "has_existential", "is_forall_rooted", "depth",
]


# -- exceptions ---------------------------------------------------------------

class UnknownCollection(Exception):
    """A quantifier or lookup named a collection no registry knows about."""


class InvalidAst(Exception):
    """An AST is ill-formed or ill-typed; the message names the node path."""


# -- sorts --------------------------------------------------------------------

#: The closed set of term sorts. ``Cidr`` is a (base, mask) pair and never a
#: scalar, which is why :func:`validate` confines it to the ``cidr`` operand of
#: ``cidr_contains``.
SORTS = ("Bool", "Str", "Int", "Ip4", "Cidr", "Port", "Proto", "Real")

#: Bitvector widths for the sorts that encode as fixed-width bitvectors.
BV_WIDTHS = {"Ip4": 32, "Cidr": 32, "Port": 16, "Proto": 8}


# -- collection registry ------------------------------------------------------

#: Tier names, ordered weakest-first: a ``proposal`` rule needs only the change
#: itself, a ``pair`` rule needs the old/new pair, an ``estate`` rule needs the
#: whole snapshot.
TIERS = ("proposal", "pair", "estate")


def tier_rank(tier: str) -> int:
    """The 0-based rank of *tier* in :data:`TIERS` (weakest = 0)."""
    try:
        return TIERS.index(tier)
    except ValueError:
        raise ValueError(f"unknown tier {tier!r}; expected one of {TIERS}") from None


@dataclass(frozen=True)
class CollectionSpec:
    """A named record collection: its evaluation *tier* and its typed fields."""

    name: str
    tier: str
    fields: Mapping[str, str]

    def __post_init__(self) -> None:
        if self.tier not in TIERS:
            raise ValueError(f"collection {self.name!r} has unknown tier {self.tier!r}; "
                             f"expected one of {TIERS}")
        for field, sort in self.fields.items():
            if sort not in SORTS:
                raise ValueError(f"collection {self.name!r} field {field!r} has unknown "
                                 f"sort {sort!r}; expected one of {SORTS}")
        # Store a private copy so a later mutation of the caller's dict cannot
        # silently rewrite a registered spec.
        object.__setattr__(self, "fields", dict(self.fields))


#: Fields shared by every IAM-binding collection.
_IAM_FIELDS = {"role": "Str", "member": "Str", "condition": "Str", "has_condition": "Bool"}
#: Fields of an org-policy rule collection.
_ORG_FIELDS = {"constraint": "Str", "is_list": "Bool", "enforce": "Bool", "value": "Str"}

#: The registry. Seeded with exactly the four base collections that match the
#: fixture corpus; the domain sections add to it through
#: :func:`register_collection`, resolved lazily by :func:`_ensure_domains`.
COLLECTIONS: dict[str, CollectionSpec] = {
    "iam_bindings": CollectionSpec("iam_bindings", "proposal", _IAM_FIELDS),
    "org_policy_rules": CollectionSpec("org_policy_rules", "proposal", _ORG_FIELDS),
    "new_iam_bindings": CollectionSpec("new_iam_bindings", "pair", _IAM_FIELDS),
    "old_iam_bindings": CollectionSpec("old_iam_bindings", "pair", _IAM_FIELDS),
}


def register_collection(spec: CollectionSpec) -> None:
    """Register *spec*, the extension hook the domain sections call.

    Re-registering the same name with a *different* spec raises ``ValueError``;
    re-registering an identical spec is an idempotent no-op, so a double import
    of a domain module cannot break a run.
    """
    if not isinstance(spec, CollectionSpec):
        raise TypeError(f"register_collection expects a CollectionSpec, got "
                        f"{type(spec).__name__}")
    existing = COLLECTIONS.get(spec.name)
    if existing is not None:
        if existing == spec:
            return
        raise ValueError(f"collection {spec.name!r} is already registered with a "
                         f"different spec")
    COLLECTIONS[spec.name] = spec


# -- domain resolution hook ---------------------------------------------------
#
# The six domain collections would exist only if something happened to import
# ``sec_domains`` first. ``_ensure_domains`` closes that gap: it runs once at the
# top of ``validate``, ``derived_tier`` and ``collections_used``, importing and
# registering the domains lazily and fail-open — exactly like
# ``registry._providers()`` and ``preflight._tf_plan_extractor``. Because the
# import happens from inside a function, long after this module is fully
# initialized, ``sec_domains`` may import ``sec_ast`` at module level without a
# cycle.

_DOMAINS_RESOLVED = False


def reset_domain_cache() -> None:
    """Forget that the domains were resolved, so the next lazy call retries.

    For tests; production code never needs it.
    """
    global _DOMAINS_RESOLVED
    _DOMAINS_RESOLVED = False


def _ensure_domains() -> None:
    """Import and register the domain collections once, caching the outcome."""
    global _DOMAINS_RESOLVED
    if _DOMAINS_RESOLVED:
        return
    # Cache the attempt before it runs so a failure is not retried on every call.
    _DOMAINS_RESOLVED = True
    try:
        module = importlib.import_module("gcp_grounding.sec_domains")
        module.register()
    except (ImportError, AttributeError) as exc:
        logger.debug("sec_domains not available (%s); using the four base "
                     "collections only", exc)


# -- node vocabulary ----------------------------------------------------------

MAX_DEPTH = 64

_CMP_OPS = frozenset({"eq", "ne", "lt", "le", "gt", "ge"})
_ORDER_OPS = frozenset({"lt", "le", "gt", "ge"})

#: Single-node child slots per node kind (``args`` lists handled separately).
_CHILD_SLOTS: dict[str, tuple[str, ...]] = {
    "not": ("arg",),
    "implies": ("if", "then"),
    "forall": ("body",),
    "exists": ("body",),
    "in": ("term", "set"),
    "cmp": ("left", "right"),
    "prefix": ("term",),
    "suffix": ("term",),
    "contains": ("term",),
    "cidr_contains": ("cidr", "addr"),
    "port_in": ("term",),
}

# Strict dotted quad, each octet 0..255, with an optional /0..32 prefix. Leading
# zeros are rejected (``[1-9]?[0-9]`` never matches ``01``).
_OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"
_PREFIX = r"(?:3[0-2]|[12]?[0-9])"
_IP_RE = re.compile(rf"^{_OCTET}\.{_OCTET}\.{_OCTET}\.{_OCTET}(?:/{_PREFIX})?$")


def _children(node) -> list:
    """The child *node* dicts of *node* (terms count; ``set`` items do not)."""
    if not isinstance(node, Mapping):
        return []
    kind = node.get("node")
    if kind in ("and", "or", "atmost", "atleast"):
        args = node.get("args")
        return [a for a in args if isinstance(a, Mapping)] if isinstance(args, list) else []
    out = []
    for slot in _CHILD_SLOTS.get(kind, ()):
        child = node.get(slot)
        if isinstance(child, Mapping):
            out.append(child)
    return out


def depth(node) -> int:
    """The height of the AST rooted at *node* (a leaf has depth 1)."""
    kids = _children(node)
    if not kids:
        return 1
    return 1 + max(depth(k) for k in kids)


# -- lookups ------------------------------------------------------------------

def _spec_for(name, registry) -> CollectionSpec:
    spec = registry.get(name) if isinstance(registry, Mapping) else None
    if spec is None:
        raise UnknownCollection(f"collection {name!r} is not registered")
    return spec


def sort_of(term, env) -> str:
    """The sort of *term* given *env* mapping bound var → collection name.

    Reused by ``sx-sec-encode``; raises :class:`InvalidAst` if *term* is not a
    well-formed term and :class:`UnknownCollection` for an unregistered binding.
    """
    if not isinstance(term, Mapping):
        raise InvalidAst(f"sort_of: expected a term node, got {term!r}")
    kind = term.get("node")
    if kind == "lit":
        sort = term.get("sort")
        if sort not in SORTS:
            raise InvalidAst(f"lit.sort: unknown sort {sort!r}")
        return sort
    if kind == "field":
        var = term.get("var")
        if var not in env:
            raise InvalidAst(f"field.var: {var!r} is not bound by an enclosing quantifier")
        spec = _spec_for(env[var], COLLECTIONS)
        fname = term.get("field")
        if fname not in spec.fields:
            raise InvalidAst(f"field.field: {fname!r} is not a field of collection "
                             f"{env[var]!r}")
        return spec.fields[fname]
    raise InvalidAst(f"sort_of: node {kind!r} is not a term")


# -- validation ---------------------------------------------------------------

def _require_keys(node, allowed, here) -> None:
    keys = set(node.keys())
    missing = allowed - keys
    if missing:
        raise InvalidAst(f"{here}: missing keys {sorted(missing)}")
    extra = keys - allowed
    if extra:
        raise InvalidAst(f"{here}: unexpected keys {sorted(extra)}")


def _check_lit_value(sort, value, here) -> None:
    if sort in ("Int", "Port", "Proto"):
        if not isinstance(value, int) or isinstance(value, bool):
            raise InvalidAst(f"{here}.value: sort {sort} requires an integer, got {value!r}")
        if sort == "Port" and not (0 <= value <= 65535):
            raise InvalidAst(f"{here}.value: Port literal {value} is outside 0..65535")
        if sort == "Proto" and not (0 <= value <= 255):
            raise InvalidAst(f"{here}.value: Proto literal {value} is outside 0..255")
    elif sort in ("Ip4", "Cidr"):
        if not isinstance(value, str) or not _IP_RE.match(value):
            raise InvalidAst(f"{here}.value: sort {sort} literal {value!r} is not a "
                             f"dotted quad with an optional /0..32 prefix")
    elif sort == "Bool":
        if not isinstance(value, bool):
            raise InvalidAst(f"{here}.value: Bool literal must be true or false, got {value!r}")
    elif sort == "Real":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise InvalidAst(f"{here}.value: Real literal must be a number, got {value!r}")
    else:  # Str
        if not isinstance(value, str):
            raise InvalidAst(f"{here}.value: Str literal must be a string, got {value!r}")


def _check_set(node, path) -> str:
    here = "set" if not path else f"{path}.set"
    if not isinstance(node, Mapping) or node.get("node") != "set":
        raise InvalidAst(f"{here}: expected a set literal, got {node!r}")
    _require_keys(node, {"node", "sort", "items"}, here)
    sort = node["sort"]
    if sort not in SORTS:
        raise InvalidAst(f"{here}.sort: unknown sort {sort!r}")
    items = node["items"]
    if not isinstance(items, list) or not all(isinstance(x, str) for x in items):
        raise InvalidAst(f"{here}.items: expected a list of strings")
    return sort


def _check_term(term, env, registry, path, *, cidr_ok) -> str:
    """Validate a term node and return its sort.

    A term of sort ``Cidr`` is rejected unless *cidr_ok* — a CIDR is a
    (base, mask) pair with no scalar encoding, so it may appear only as the
    ``cidr`` operand of ``cidr_contains``.
    """
    if not isinstance(term, Mapping) or "node" not in term:
        raise InvalidAst(f"{path or '<root>'}: expected a term node, got {term!r}")
    kind = term["node"]
    here = kind if not path else f"{path}.{kind}"
    if kind == "lit":
        _require_keys(term, {"node", "sort", "value"}, here)
        sort = term["sort"]
        if sort not in SORTS:
            raise InvalidAst(f"{here}.sort: unknown sort {sort!r}")
        _check_lit_value(sort, term["value"], here)
    elif kind == "field":
        _require_keys(term, {"node", "var", "field"}, here)
        var = term["var"]
        fname = term["field"]
        if var not in env:
            raise InvalidAst(f"{here}.var: {var!r} is not bound by an enclosing quantifier")
        coll = env[var]
        spec = _spec_for(coll, registry)
        if fname not in spec.fields:
            raise InvalidAst(f"{here}.field: {fname!r} is not a field of collection {coll!r}")
        sort = spec.fields[fname]
        if sort == "Cidr":
            mask = f"{fname}_mask"
            if spec.fields.get(mask) != "Ip4":
                raise InvalidAst(f"{here}.field: Cidr field {fname!r} of collection "
                                 f"{coll!r} lacks a companion {mask!r} of sort Ip4")
    else:
        raise InvalidAst(f"{here}: expected a term (field or lit), got node {kind!r}")
    if sort == "Cidr" and not cidr_ok:
        raise InvalidAst(f"{here}: a term of sort Cidr may appear only as the cidr operand "
                         f"of cidr_contains")
    return sort


def _validate(node, env, registry, path) -> None:
    if not isinstance(node, Mapping) or "node" not in node:
        raise InvalidAst(f"{path or '<root>'}: expected a node object with a 'node' key, "
                         f"got {node!r}")
    kind = node["node"]
    here = kind if not path else f"{path}.{kind}"

    if kind in ("true", "false"):
        _require_keys(node, {"node"}, here)
        return

    if kind == "not":
        _require_keys(node, {"node", "arg"}, here)
        _validate(node["arg"], env, registry, f"{here}.arg")
        return

    if kind in ("and", "or"):
        _require_keys(node, {"node", "args"}, here)
        args = node["args"]
        if not isinstance(args, list) or len(args) < 1:
            raise InvalidAst(f"{here}.args: expected a non-empty list")
        for i, arg in enumerate(args):
            _validate(arg, env, registry, f"{here}.args[{i}]")
        return

    if kind in ("atmost", "atleast"):
        _require_keys(node, {"node", "k", "args"}, here)
        k = node["k"]
        if not isinstance(k, int) or isinstance(k, bool):
            raise InvalidAst(f"{here}.k: expected an integer, got {k!r}")
        args = node["args"]
        if not isinstance(args, list) or len(args) < 1:
            raise InvalidAst(f"{here}.args: expected a non-empty list")
        for i, arg in enumerate(args):
            _validate(arg, env, registry, f"{here}.args[{i}]")
        return

    if kind == "implies":
        _require_keys(node, {"node", "if", "then"}, here)
        _validate(node["if"], env, registry, f"{here}.if")
        _validate(node["then"], env, registry, f"{here}.then")
        return

    if kind in ("forall", "exists"):
        _require_keys(node, {"node", "var", "collection", "body"}, here)
        var = node["var"]
        coll = node["collection"]
        if not isinstance(var, str) or not var:
            raise InvalidAst(f"{here}.var: expected a non-empty variable name")
        if not isinstance(coll, str) or not coll:
            raise InvalidAst(f"{here}.collection: expected a collection name")
        if var in env:
            raise InvalidAst(f"{here}.var: {var!r} shadows an enclosing quantifier variable")
        _spec_for(coll, registry)  # raises UnknownCollection for an unknown name
        inner = dict(env)
        inner[var] = coll
        _validate(node["body"], inner, registry, f"{here}.body")
        return

    if kind == "cmp":
        _require_keys(node, {"node", "op", "left", "right"}, here)
        op = node["op"]
        if op not in _CMP_OPS:
            raise InvalidAst(f"{here}.op: unknown comparison op {op!r}")
        lsort = _check_term(node["left"], env, registry, f"{here}.left", cidr_ok=False)
        rsort = _check_term(node["right"], env, registry, f"{here}.right", cidr_ok=False)
        if lsort != rsort:
            raise InvalidAst(f"{here}.right: operands have different sorts "
                             f"({lsort} vs {rsort})")
        if op in _ORDER_OPS and lsort in ("Str", "Bool"):
            raise InvalidAst(f"{here}.op: ordering op {op!r} is undefined on sort {lsort}")
        return

    if kind == "in":
        _require_keys(node, {"node", "term", "set"}, here)
        tsort = _check_term(node["term"], env, registry, f"{here}.term", cidr_ok=False)
        ssort = _check_set(node["set"], f"{here}")
        if tsort != ssort:
            raise InvalidAst(f"{here}.set: set sort {ssort} differs from term sort {tsort}")
        return

    if kind in ("prefix", "suffix", "contains"):
        _require_keys(node, {"node", "term", "value"}, here)
        tsort = _check_term(node["term"], env, registry, f"{here}.term", cidr_ok=False)
        if tsort != "Str":
            raise InvalidAst(f"{here}.term: {kind} requires a Str term, got {tsort}")
        if not isinstance(node["value"], str):
            raise InvalidAst(f"{here}.value: expected a string")
        return

    if kind == "cidr_contains":
        _require_keys(node, {"node", "cidr", "addr"}, here)
        csort = _check_term(node["cidr"], env, registry, f"{here}.cidr", cidr_ok=True)
        if csort != "Cidr":
            raise InvalidAst(f"{here}.cidr: cidr operand must be sort Cidr, got {csort}")
        asort = _check_term(node["addr"], env, registry, f"{here}.addr", cidr_ok=False)
        if asort != "Ip4":
            raise InvalidAst(f"{here}.addr: addr operand must be sort Ip4, got {asort}")
        return

    if kind == "port_in":
        _require_keys(node, {"node", "term", "lo", "hi"}, here)
        _check_term(node["term"], env, registry, f"{here}.term", cidr_ok=False)
        lo, hi = node["lo"], node["hi"]
        for label, value in (("lo", lo), ("hi", hi)):
            if not isinstance(value, int) or isinstance(value, bool):
                raise InvalidAst(f"{here}.{label}: expected an integer, got {value!r}")
            if not (0 <= value <= 65535):
                raise InvalidAst(f"{here}.{label}: {value} is outside 0..65535")
        if lo > hi:
            raise InvalidAst(f"{here}.lo: lo {lo} is greater than hi {hi}")
        return

    if kind == "cel":
        _require_keys(node, {"node", "expr"}, here)
        if not isinstance(node["expr"], str):
            raise InvalidAst(f"{here}.expr: expected a string")
        return

    if kind in ("field", "lit"):
        raise InvalidAst(f"{here}: a term node is not a boolean-valued formula here")
    if kind == "set":
        raise InvalidAst(f"{here}: a set literal is not a boolean-valued formula here")

    raise InvalidAst(f"{here}: unknown node kind {kind!r}")


def validate(node, *, collections=None) -> None:
    """One recursive well-formedness and type pass over *node*.

    Raises :class:`InvalidAst` (naming the offending path) or
    :class:`UnknownCollection`. Pass *collections* to validate against an
    explicit registry instead of the global :data:`COLLECTIONS`.
    """
    _ensure_domains()
    registry = COLLECTIONS if collections is None else collections
    if depth(node) > MAX_DEPTH:
        raise InvalidAst(f"<root>: AST depth exceeds MAX_DEPTH ({MAX_DEPTH})")
    kind = node.get("node") if isinstance(node, Mapping) else None
    if kind in ("field", "lit"):
        _check_term(node, {}, registry, "", cidr_ok=False)
    elif kind == "set":
        _check_set(node, "")
    else:
        _validate(node, {}, registry, "")


# -- canonicalization ---------------------------------------------------------

def canonical(node):
    """A deterministic normal form: sort and dedupe commutative operands.

    ``args`` of ``and``/``or``/``atmost``/``atleast`` are sorted by their JSON
    encoding and de-duplicated; a 1-arg ``and``/``or`` collapses to its single
    child; ``set.items`` are sorted and de-duplicated. Idempotent.
    """
    if not isinstance(node, Mapping) or "node" not in node:
        return node
    kind = node["node"]
    out = dict(node)
    if kind in ("and", "or", "atmost", "atleast"):
        args = [canonical(a) for a in node.get("args", [])]
        args.sort(key=lambda c: json.dumps(c, sort_keys=True, ensure_ascii=False))
        deduped = []
        seen = set()
        for arg in args:
            key = json.dumps(arg, sort_keys=True, ensure_ascii=False)
            if key not in seen:
                seen.add(key)
                deduped.append(arg)
        if kind in ("and", "or") and len(deduped) == 1:
            return deduped[0]
        out["args"] = deduped
        return out
    if kind == "set":
        out["items"] = sorted(set(node.get("items", [])))
        return out
    for slot in _CHILD_SLOTS.get(kind, ()):
        if slot in out:
            out[slot] = canonical(out[slot])
    return out


def dumps(node) -> str:
    """Canonicalize and serialize *node* to a byte-stable JSON string.

    Mirrors ``fetch.write_snapshot`` (fetch.py:344-349).
    """
    return json.dumps(canonical(node), indent=2, sort_keys=True, ensure_ascii=False)


# -- s-expression rendering ---------------------------------------------------
#
# THE ONE FORM. An artifact's ``sexpr`` has exactly one rendering, and this is
# it: derived purely from the (already canonical) AST, never from ``str(formula)``
# or ``formula.sexpr()``, so the committed bytes are z3-INDEPENDENT and survive a
# solver upgrade — the same reason witnesses are re-classified rather than
# re-minted. It lives in this leaf, which both the compiler (stage 1, which
# WRITES the field) and the rule loader (stage 2, which RE-CHECKS it) already
# import, so neither stage has to reach across for the other's renderer.

def _render_term(term) -> str:
    if term.get("node") == "field":
        return f"{term['var']}.{term['field']}"
    sort, value = term.get("sort"), term.get("value")
    if sort == "Str":
        return _quote(value)
    if sort == "Bool":
        return "true" if value else "false"
    return str(value)


def _quote(text: str) -> str:
    return '"' + str(text).replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_sexpr(node) -> str:
    """*node* rendered as the artifact's committed s-expression string."""
    kind = node["node"]
    if kind in ("true", "false"):
        return kind
    if kind == "not":
        return f"(not {render_sexpr(node['arg'])})"
    if kind in ("and", "or"):
        return f"({kind} " + " ".join(render_sexpr(a) for a in node["args"]) + ")"
    if kind == "implies":
        return f"(=> {render_sexpr(node['if'])} {render_sexpr(node['then'])})"
    if kind in ("atmost", "atleast"):
        return (f"({kind} {node['k']} "
                + " ".join(render_sexpr(a) for a in node["args"]) + ")")
    if kind in ("forall", "exists"):
        return (f"({kind} (({node['var']} {node['collection']})) "
                f"{render_sexpr(node['body'])})")
    if kind == "cmp":
        return f"({node['op']} {_render_term(node['left'])} {_render_term(node['right'])})"
    if kind == "in":
        items = " ".join(_quote(x) for x in node["set"]["items"])
        return f"(in {_render_term(node['term'])} (set {items}))"
    if kind in ("prefix", "suffix", "contains"):
        return f"({kind} {_render_term(node['term'])} {_quote(node['value'])})"
    if kind == "cidr_contains":
        return f"(cidr_contains {_render_term(node['cidr'])} {_render_term(node['addr'])})"
    if kind == "port_in":
        return f"(port_in {_render_term(node['term'])} {node['lo']} {node['hi']})"
    if kind == "cel":
        return f"(cel {_quote(node['expr'])})"
    return f"({kind})"


# -- analysis helpers ---------------------------------------------------------

def _collect_collections(node, seen) -> None:
    if not isinstance(node, Mapping):
        return
    if node.get("node") in ("forall", "exists"):
        coll = node.get("collection")
        if isinstance(coll, str):
            seen.add(coll)
    for child in _children(node):
        _collect_collections(child, seen)


def collections_used(node) -> list:
    """The sorted collection names quantified over anywhere in *node*."""
    _ensure_domains()
    seen: set = set()
    _collect_collections(node, seen)
    return sorted(seen)


def derived_tier(node, *, collections=None) -> str:
    """The strongest tier over :func:`collections_used`, or ``"proposal"``.

    Raises :class:`UnknownCollection` if a used collection is unregistered.
    """
    _ensure_domains()
    registry = COLLECTIONS if collections is None else collections
    used = collections_used(node)
    if not used:
        return "proposal"
    best = -1
    for name in used:
        spec = _spec_for(name, registry)
        best = max(best, tier_rank(spec.tier))
    return TIERS[best]


def _collect_consts(node, env, out) -> None:
    if not isinstance(node, Mapping):
        return
    kind = node.get("node")
    if kind in ("forall", "exists"):
        var = node.get("var")
        coll = node.get("collection")
        inner = dict(env)
        if isinstance(var, str) and isinstance(coll, str):
            inner[var] = coll
        _collect_consts(node.get("body"), inner, out)
        return
    if kind == "field":
        var = node.get("var")
        fname = node.get("field")
        coll = env.get(var)
        if coll is not None and isinstance(fname, str):
            spec = COLLECTIONS.get(coll)
            if spec is not None and fname in spec.fields:
                out.add((f"{coll}#{var}.{fname}", spec.fields[fname]))
        return
    for child in _children(node):
        _collect_consts(child, env, out)


def free_consts(node) -> list:
    """Sorted ``(name, sort)`` pairs for every field reference in *node*.

    ``name`` is ``f"{collection}#{var}.{field}"`` — the stable witness key. This
    naming MUST NOT change without a schema bump.
    """
    out: set = set()
    _collect_consts(node, {}, out)
    return sorted(out)


def has_existential(node) -> bool:
    """True if any ``exists`` quantifier appears in *node*."""
    if not isinstance(node, Mapping):
        return False
    if node.get("node") == "exists":
        return True
    return any(has_existential(child) for child in _children(node))


def is_forall_rooted(node) -> bool:
    """True if *node*'s outermost quantifier is a ``forall``."""
    return isinstance(node, Mapping) and node.get("node") == "forall"
