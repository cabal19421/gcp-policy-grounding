"""Cloud Armor match-expression grounding: a closed, offline-decidable subset.

A Cloud Armor security-policy rule matches on ``match.expr.expression`` — a CEL
dialect *distinct* from IAM Conditions (different attributes, different built-in
functions). :class:`gcp_grounding.constraints._CelToZ3` hardcodes ``request.time``
as a Real and ``resource.name`` as a String for the IAM dialect and must not be
touched; this module is its sibling for the Armor dialect, built to the same
shape and the same honesty contract: z3 is passed in (never imported here), the
supported subset is translated exactly, and anything outside it raises
:class:`UnsupportedArmorExpr` naming the offending token so the caller can
abstain (``unverified``) rather than mint a false verdict. NEVER approximate an
unsupported predicate as ``True`` or ``False`` — that is the only way a false
``contradicted`` could reach the report.

Supported grammar (recursive descent, mirroring ``_CelToZ3``'s
``_or`` / ``_and`` / ``_unary`` / ``_atom``):

- ``inIpRange(origin.ip, '<cidr>')`` → :func:`gcp_grounding.packet.cidr_match`
  over the shared source-address BitVec; IPv6 / malformed CIDRs (via
  :func:`gcp_grounding.packet.parse_cidr`) become :class:`UnsupportedArmorExpr`.
- ``origin.region_code == '<CC>'`` / ``!= '<CC>'`` → string (in)equality.
- ``origin.region_code in ['US', 'CA']`` → an ``Or`` over the literal list.
- ``evaluatePreconfiguredExpr('<id>')`` and
  ``evaluatePreconfiguredWaf('<id>', ...)`` → an opaque ``Bool`` ``waf:<id>``,
  created on demand and cached per :class:`ArmorVars` (the ``Waf`` form's second
  argument — a sensitivity / opt-out mapping — is parsed and discarded).
- ``true``, ``false``, ``&&``, ``||``, ``!`` and parentheses.
- Anything else — ``request.headers[...]``, ``request.path.matches(...)``,
  ``origin.asn``, ``has(...)``, arithmetic — raises :class:`UnsupportedArmorExpr`.

``!`` binds tighter than the comparisons, exactly as in ``_CelToZ3``: it may
precede another ``!``, a parenthesized group, a boolean literal, or a
boolean-valued predicate (``inIpRange`` / the two ``evaluatePreconfigured*``
forms), but not ``origin.region_code`` — ``!origin.region_code == 'US'`` would
mean ``(!origin.region_code) == 'US'``, a type error the encoding cannot
represent, so it raises rather than mis-parse.

Deeply nested expressions are the *caller's* responsibility: :func:`translate`
recurses once per nesting level and lets :class:`RecursionError` propagate to
the same abstain path a caller already uses for ``_CelToZ3``, rather than
catching it and corrupting state.

Vocabulary rule for preconfigured expression ids: :data:`PRECONFIGURED_EXPR_IDS`
is a curated snapshot and is *inherently incomplete*. An id that is not in it
still translates — to its own opaque ``Bool`` — because an unknown id is
ignorance, not evidence of a hallucination. :func:`referenced_expr_ids` lets the
caller enumerate the ids an expression names so it can emit an ``unverified``
note about the unrecognized ones rather than an ``ungrounded`` verdict.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from . import packet

__all__ = [
    "UnsupportedArmorExpr",
    "PRECONFIGURED_EXPR_IDS",
    "ArmorVars",
    "armor_vars",
    "translate",
    "referenced_expr_ids",
]


class UnsupportedArmorExpr(Exception):
    """The expression uses Armor CEL outside the supported offline subset."""


# A curated snapshot of the WAF preconfigured expression-set ids (OWASP CRS
# sensitivity rule sets plus canaries). Inherently incomplete: an id absent
# from this tuple is treated as unknown-not-hallucinated (see module docstring).
PRECONFIGURED_EXPR_IDS: tuple[str, ...] = (
    "sqli-v33-stable",
    "xss-v33-stable",
    "lfi-v33-stable",
    "rfi-v33-stable",
    "rce-v33-stable",
    "methodenforcement-v33-stable",
    "scannerdetection-v33-stable",
    "protocolattack-v33-stable",
    "php-v33-stable",
    "sessionfixation-v33-stable",
    "java-v33-stable",
    "nodejs-v33-stable",
    "cve-canary",
    "json-sqli-canary",
)


@dataclass(frozen=True)
class ArmorVars:
    """The free z3 variables an Armor expression ranges over.

    - ``src`` — the source IPv4 address, a 32-bit BitVec shared with
      :attr:`gcp_grounding.packet.PacketVars.src` (same name → same z3 constant,
      so an Armor ``inIpRange`` and a firewall source range are comparable).
    - ``region`` — ``origin.region_code`` as ``z3.String("origin.region_code")``.
    - ``preconfigured`` — a cache mapping each referenced expr id to its opaque
      ``z3.Bool("waf:<id>")``, populated on demand by :func:`translate` so
      repeated references to one id within a single ``ArmorVars`` share a Bool.
    """

    src: Any
    region: Any
    preconfigured: dict = field(default_factory=dict)


def armor_vars(z3, src=None) -> ArmorVars:
    """Fresh :class:`ArmorVars`. ``src`` defaults to the shared
    :attr:`gcp_grounding.packet.PacketVars.src` BitVec so Armor and firewall
    reasoning agree on the source-address variable."""
    if src is None:
        src = packet.packet_vars(z3).src
    return ArmorVars(src=src, region=z3.String("origin.region_code"), preconfigured={})


# -- tokenizer ---------------------------------------------------------------

# Multi-char operators precede their single-char prefixes ('!=' before '!').
# '[' ']' ',' delimit region lists; '{' '}' ':' appear only inside the
# discarded second argument of evaluatePreconfiguredWaf and are tokenized only
# so that argument can be skipped by bracket balancing.
_TOKEN = re.compile(
    r"\s*(?:(?P<op>&&|\|\||==|!=|!|\(|\)|\[|\]|\{|\}|,|:)"
    r"|(?P<string>\"[^\"\\]*\"|'[^'\\]*')"
    r"|(?P<number>\d+(?:\.\d+)?)"
    r"|(?P<name>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*))"
)


def _tokenize(expression: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    pos = 0
    while pos < len(expression):
        match = _TOKEN.match(expression, pos)
        if match is None or match.end() == pos:
            rest = expression[pos:].strip()
            if not rest:
                break
            raise UnsupportedArmorExpr(f"unrecognized syntax at {rest[:20]!r}")
        pos = match.end()
        if match.lastgroup == "string":
            tokens.append(("str", match.group("string")[1:-1]))
        else:
            group = match.lastgroup or "op"
            tokens.append((group, match.group(group)))
    return tokens


# Names that begin a boolean-valued atom, so '!' may precede them (see the
# !-binding note in the module docstring).
_NEGATABLE_ATOM_NAMES = (
    "true", "false", "inIpRange",
    "evaluatePreconfiguredExpr", "evaluatePreconfiguredWaf",
)


class _ArmorToZ3:
    """Recursive-descent translation of the supported Armor CEL subset to a z3
    boolean formula, mirroring :class:`_CelToZ3`."""

    def __init__(self, z3, expression: str, v: ArmorVars) -> None:
        self._z3 = z3
        self._vars = v
        self._tokens = _tokenize(expression)
        self._pos = 0

    def translate(self):
        formula = self._or()
        tok = self._peek()
        if tok is not None:
            raise UnsupportedArmorExpr(f"unsupported trailing syntax at {tok[1]!r}")
        return formula

    # grammar: or := and ("||" and)* ; and := unary ("&&" unary)* ;
    # unary := "!" (boolean atom) | "(" or ")" | atom

    def _or(self):
        formula = self._and()
        while self._match("op", "||"):
            if self._peek() is None:
                raise UnsupportedArmorExpr("expression ends after '||' where a "
                                           "condition was expected")
            formula = self._z3.Or(formula, self._and())
        return formula

    def _and(self):
        formula = self._unary()
        while self._match("op", "&&"):
            if self._peek() is None:
                raise UnsupportedArmorExpr("expression ends after '&&' where a "
                                           "condition was expected")
            formula = self._z3.And(formula, self._unary())
        return formula

    def _unary(self):
        if self._match("op", "!"):
            tok = self._peek()
            ok = tok in (("op", "!"), ("op", "(")) or (
                tok is not None and tok[0] == "name" and tok[1] in _NEGATABLE_ATOM_NAMES)
            if not ok:
                got = "end of expression" if tok is None else repr(tok[1])
                raise UnsupportedArmorExpr(
                    f"'!' immediately before {got} — '!' binds tighter than the "
                    "comparisons, so it may only precede '!', '(', a boolean literal, "
                    "or a boolean predicate (inIpRange / evaluatePreconfiguredExpr / "
                    "evaluatePreconfiguredWaf)")
            return self._z3.Not(self._unary())
        if self._match("op", "("):
            formula = self._or()
            self._expect(")")
            return formula
        return self._atom()

    def _atom(self):
        tok = self._peek()
        if tok is None:
            raise UnsupportedArmorExpr("expression ends where a condition was expected")
        kind, value = tok
        if kind == "name" and value in ("true", "false"):
            self._pos += 1
            return self._z3.BoolVal(value == "true")
        if kind == "name" and value == "inIpRange":
            self._pos += 1
            return self._in_ip_range()
        if kind == "name" and value in ("evaluatePreconfiguredExpr",
                                        "evaluatePreconfiguredWaf"):
            self._pos += 1
            return self._preconfigured(value)
        if kind == "name" and value == "origin.region_code":
            self._pos += 1
            return self._region()
        raise UnsupportedArmorExpr(f"unsupported predicate {value!r}")

    # -- atoms ---------------------------------------------------------------

    def _in_ip_range(self):
        self._expect("(")
        kind, value = self._next("the first argument of inIpRange")
        if not (kind == "name" and value == "origin.ip"):
            raise UnsupportedArmorExpr(
                f"inIpRange's first argument must be origin.ip, got {value!r}")
        self._expect(",")
        cidr = self._string_literal("inIpRange")
        self._expect(")")
        try:
            return packet.cidr_match(self._z3, self._vars.src, cidr)
        except ValueError as exc:
            raise UnsupportedArmorExpr(
                f"inIpRange CIDR {cidr!r} is not an offline-decidable IPv4 "
                f"range ({exc})") from exc

    def _preconfigured(self, func: str):
        self._expect("(")
        expr_id = self._string_literal(func)
        # evaluatePreconfiguredWaf's remaining argument(s) are a sensitivity /
        # opt-out mapping: parse and discard by bracket balancing.
        while self._match("op", ","):
            self._skip_argument(func)
        self._expect(")")
        cache = self._vars.preconfigured
        if expr_id not in cache:
            cache[expr_id] = self._z3.Bool(f"waf:{expr_id}")
        return cache[expr_id]

    def _region(self):
        tok = self._peek()
        if tok == ("op", "=="):
            self._pos += 1
            return self._vars.region == self._z3.StringVal(
                self._string_literal("origin.region_code =="))
        if tok == ("op", "!="):
            self._pos += 1
            return self._vars.region != self._z3.StringVal(
                self._string_literal("origin.region_code !="))
        if tok == ("name", "in"):
            self._pos += 1
            return self._region_in()
        got = "end of expression" if tok is None else repr(tok[1])
        raise UnsupportedArmorExpr(
            f"origin.region_code must be compared with '==', '!=' or 'in', got {got}")

    def _region_in(self):
        self._expect("[")
        literals: list[str] = []
        if self._peek() != ("op", "]"):
            literals.append(self._string_literal("a region-code list"))
            while self._match("op", ","):
                literals.append(self._string_literal("a region-code list"))
        self._expect("]")
        if not literals:
            return self._z3.BoolVal(False)
        return self._z3.Or([self._vars.region == self._z3.StringVal(x) for x in literals])

    # -- token plumbing ------------------------------------------------------

    def _skip_argument(self, func: str) -> None:
        """Consume one argument (possibly a nested list / map), stopping at the
        top-level ',' or ')' that follows it."""
        depth = 0
        while True:
            tok = self._peek()
            if tok is None:
                raise UnsupportedArmorExpr(f"{func}()'s argument list is unterminated")
            kind, value = tok
            if depth == 0 and kind == "op" and value in (",", ")"):
                return
            if kind == "op" and value in ("(", "[", "{"):
                depth += 1
            elif kind == "op" and value in (")", "]", "}"):
                depth -= 1
            self._pos += 1

    def _string_literal(self, what: str) -> str:
        kind, value = self._next(f"a string literal for {what}")
        if kind != "str":
            raise UnsupportedArmorExpr(f"{what} expects a string literal, got {value!r}")
        return value

    def _peek(self) -> Optional[tuple[str, str]]:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _match(self, kind: str, value: str) -> bool:
        if self._peek() == (kind, value):
            self._pos += 1
            return True
        return False

    def _expect(self, op: str) -> None:
        if not self._match("op", op):
            tok = self._peek()
            got = "end of expression" if tok is None else repr(tok[1])
            raise UnsupportedArmorExpr(f"expected {op!r}, got {got}")

    def _next(self, what: str) -> tuple[str, str]:
        tok = self._peek()
        if tok is None:
            raise UnsupportedArmorExpr(f"expression ends where {what} was expected")
        self._pos += 1
        return tok


def translate(z3, expression: str, v: ArmorVars):
    """Translate a Cloud Armor match expression to a z3 boolean over *v*.

    Raises :class:`UnsupportedArmorExpr` for anything outside the supported
    subset (naming the offending token) and lets :class:`RecursionError`
    propagate for deeply nested input — both are the caller's abstain paths.
    """
    return _ArmorToZ3(z3, expression, v).translate()


def referenced_expr_ids(expression: str) -> tuple[str, ...]:
    """The preconfigured expression ids an expression names, in first-appearance
    order without duplicates.

    A pure token scan (needs no z3) over ``evaluatePreconfiguredExpr('<id>')``
    and ``evaluatePreconfiguredWaf('<id>', ...)`` occurrences anywhere in the
    expression's nested boolean structure. The caller intersects the result with
    :data:`PRECONFIGURED_EXPR_IDS` to decide which ids to flag as merely
    unverified (see the vocabulary rule in the module docstring).
    """
    tokens = _tokenize(expression)
    ids: list[str] = []
    seen: set[str] = set()
    for i, (kind, value) in enumerate(tokens):
        if kind == "name" and value in ("evaluatePreconfiguredExpr",
                                        "evaluatePreconfiguredWaf"):
            if (i + 2 < len(tokens)
                    and tokens[i + 1] == ("op", "(")
                    and tokens[i + 2][0] == "str"):
                expr_id = tokens[i + 2][1]
                if expr_id not in seen:
                    seen.add(expr_id)
                    ids.append(expr_id)
    return tuple(ids)
