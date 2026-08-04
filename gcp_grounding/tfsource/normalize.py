"""Attribute VALUE normalization for the two domain mappers, and nothing else.

THE RULE IS BROADER THAN KEY BUILDING. Key builders AND SELF-LINK HANDLING both
live in :mod:`gcp_grounding.identity`, and NEITHER may be duplicated here.
Stripping a self link down to a name is the first half of a key build, so a
second implementation of it is a second canonicaliser wearing a different name.
Honesty invariant 13 is explicit that two such implementations do not
cross-check each other: a value normalised one way at map time and another way
at compare time never matches, the miss reads as *absent*, and absence against a
view believed complete is reported as a confident answer about a resource that
certainly exists. :func:`strip_self_link` is therefore a ONE-LINE delegation to
:func:`gcp_grounding.identity.normalize_self_link` that adds only this module's
keyword-only ``path`` threading, and :func:`service_account_email` delegates the
same way, because the canonical service-account value IS its estate key.

What is left is genuinely value-level: :func:`protocol`, :func:`ports`,
:func:`cidrs`, :func:`string_list`, :func:`bool_or`, :func:`int_or`,
:func:`project_of`, :func:`service_account_email`, :func:`principal`,
:func:`network_tag` and :func:`restricted_service`.

THE UNIVERSAL CONTRACT, obeyed by every function here:

1. it returns a canonical value or a :class:`gcp_grounding.facts.Unresolved`,
   **never ``None`` and never a guess** — ``None`` is a value a document may
   legitimately carry, so returning one for *could not resolve* is the same
   silent demotion :class:`~gcp_grounding.facts.Unresolved` exists to prevent;
2. it takes a keyword-only ``path``, threaded into the marker, so every
   abstention names the attribute it is about;
3. it short-circuits an :class:`~gcp_grounding.facts.Unresolved` input UNCHANGED
   — the marker keeps the path where it was first minted, so a reader's reason
   survives the mapper.

Two functions are ALL-OR-NOTHING on purpose. :func:`cidrs` and :func:`ports`
answer with one marker for the WHOLE tuple when a single member is unparseable,
because a partially parsed range or port set silently SHRINKS a rule's reach —
and a shrunken deny rule reads as a rule that does not block the traffic it
blocks. :func:`string_list` refuses any interpolated member for the same reason.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Sequence

from .. import facts, identity
from ..core.log import get_logger

logger = get_logger(__name__)

__all__ = [
    "MAX_PORT",
    "MAX_TAG",
    "ANY_RANGE",
    "PRINCIPAL_PREFIXES",
    "UNPREFIXED_PRINCIPALS",
    "strip_self_link",
    "protocol",
    "ports",
    "cidrs",
    "string_list",
    "bool_or",
    "int_or",
    "project_of",
    "service_account_email",
    "principal",
    "network_tag",
    "restricted_service",
]

#: The highest port number a range may name.
MAX_PORT = 65535

#: The longest network tag GCP accepts.
MAX_TAG = 63

#: Cloud Armor spells "every source" as a literal ``"*"`` rather than as
#: ``0.0.0.0/0``, and the estate stores that spelling verbatim. :func:`cidrs`
#: passes it through: refusing it would make an ALL-sources rule unresolvable,
#: which is the one direction that cannot shrink a rule's reach.
ANY_RANGE = "*"

#: The closed principal-type vocabulary, in the casing IAM stores. Matched
#: case-INSENSITIVELY and returned in this casing: the vocabulary is closed, so
#: folding the prefix is a canonicalisation and not a guess. The identity after
#: the colon is NEVER case-folded — an email local part is case-sensitive.
PRINCIPAL_PREFIXES = ("user", "serviceAccount", "group", "domain", "principal",
                      "principalSet", "principalHierarchy", "deleted")

#: The two principals that carry no type prefix at all.
UNPREFIXED_PRINCIPALS = ("allUsers", "allAuthenticatedUsers")

_TRUE_SPELLINGS = ("true",)
_FALSE_SPELLINGS = ("false",)


# -- the shared entry checks --------------------------------------------------


def _marker(reason: str, path: str, where: str, detail: str = "") -> facts.Unresolved:
    """One marker, always attributable. ``path`` falls back to this module and
    the function that minted it, because :class:`~gcp_grounding.facts.Unresolved`
    refuses an unattributed marker outright."""
    return facts.Unresolved(reason, path or f"normalize.{where}", facts.truncate(detail))


def _scalar(value: Any, path: str, where: str) -> str | facts.Unresolved:
    """The entry check every scalar function starts with: a marker passes
    through unchanged, a non-string is ``unparsed``, an interpolated string is
    ``interpolation`` (a SUBSTRING test — ``roles/${var.tier}.admin`` is a
    program too), and an empty one is ``ambiguous_key``, the spelling
    :mod:`gcp_grounding.identity` already uses for a part that names nothing."""
    if facts.is_unresolved(value):
        return value
    if not isinstance(value, str):
        return _marker("unparsed", path, where,
                       f"expected a string, got {facts.safe_repr(value)}")
    if facts.is_interpolated(value):
        return _marker("interpolation", path, where,
                       "the value is a program, not a literal")
    text = value.strip()
    if not text:
        return _marker("ambiguous_key", path, where,
                       "the value is empty; nothing can be named from nothing")
    return text


def _members(value: Any, path: str, where: str) -> list[Any] | facts.Unresolved:
    """The entry check every list function starts with. A string is a scalar
    here, never a sequence of characters, and a marker ANYWHERE in the list
    fails the WHOLE list — the marker is returned unchanged, so it keeps the
    path the reader minted it at."""
    if facts.is_unresolved(value):
        return value
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        return _marker("unparsed", path, where,
                       f"expected a list, got {facts.safe_repr(value)}")
    members = list(value)
    for member in members:
        if facts.is_unresolved(member):
            return member
    return members


# -- the two delegations ------------------------------------------------------


def strip_self_link(value: Any, *, path: str) -> str | facts.Unresolved:
    """A GCP self link stripped to its relative resource form.

    A ONE-LINE delegation to :func:`gcp_grounding.identity.normalize_self_link`,
    which is THE only self-link implementation in this tree. This wrapper adds
    this module's ``path`` threading and the universal entry check, and no logic
    of its own — a second implementation of the same string surgery is a second
    place for it to be wrong, silently.
    """
    text = _scalar(value, path, "strip_self_link")
    if facts.is_unresolved(text):
        return text
    return identity.normalize_self_link(text)


def service_account_email(value: Any, *, path: str) -> str | facts.Unresolved:
    """A bare service-account email — the ``serviceAccount:`` prefix and any
    ``projects/<p>/serviceAccounts/`` prologue removed, case PRESERVED.

    Delegated to :func:`gcp_grounding.identity.key_or_unresolved` for the same
    reason :func:`strip_self_link` is delegated: the canonical value for this
    attribute IS the ``service_accounts`` estate key, so building it here would
    be a second key builder wearing a value-helper's name. The only check added
    on top is value-level — an address with no ``@`` is not an email, and
    emitting it would ground a name nobody could ever match.
    """
    text = _scalar(value, path, "service_account_email")
    if facts.is_unresolved(text):
        return text
    email = identity.key_or_unresolved("service_accounts", name=text, path=path)
    if facts.is_unresolved(email):
        return email
    if "@" not in email:
        return _marker("unparsed", path, "service_account_email",
                       "a service account is an email address and this has no '@'")
    return email


# -- the value-level helpers --------------------------------------------------


def protocol(value: Any, *, path: str) -> str | facts.Unresolved:
    """An IP protocol, LOWERCASED.

    Folding the case is safe and required: the provider declares
    ``CaseDiffSuppress`` on this attribute (so ``TCP`` and ``tcp`` are the same
    configuration to terraform), and the packet-algebra module compares
    lowercase protocol names only. A numeric protocol (``6``) is legal in the
    provider and is rendered as its decimal string, which is how the API returns
    it.
    """
    if facts.is_unresolved(value):
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    text = _scalar(value, path, "protocol")
    if facts.is_unresolved(text):
        return text
    if any(character.isspace() for character in text) or "/" in text:
        return _marker("unparsed", path, "protocol",
                       "a protocol is one bare token")
    return text.lower()


def _port_token(token: Any) -> str | None:
    """One canonical ``"N"`` or ``"A-B"`` port token, or ``None`` for junk.
    Private, so the ``None`` here can never reach a caller of this module."""
    if isinstance(token, bool):
        return None
    if isinstance(token, int):
        return str(token) if 0 <= token <= MAX_PORT else None
    if not isinstance(token, str):
        return None
    text = token.strip()
    if not text or facts.is_interpolated(text):
        return None
    halves = text.split("-")
    if len(halves) > 2 or not all(half.isdigit() for half in halves):
        return None
    numbers = [int(half) for half in halves]
    if any(number > MAX_PORT for number in numbers):
        return None
    if len(numbers) == 2 and numbers[0] > numbers[1]:
        return None
    return "-".join(str(number) for number in numbers)


def ports(value: Any, *, path: str) -> tuple[str, ...] | facts.Unresolved:
    """A firewall port list as canonical ``"N"`` / ``"A-B"`` strings.

    ALL-OR-NOTHING, for :func:`cidrs`' reason: one unparseable member makes the
    whole tuple unresolved, because a port set with a member quietly dropped
    describes a rule that reaches fewer ports than the rule reaches.

    An EMPTY list is returned as an empty tuple and is not an error: the
    provider spells "every port of this protocol" as an absent or empty ``ports``
    attribute, and what that means is the mapper's decision, not this module's.
    """
    members = _members(value, path, "ports")
    if facts.is_unresolved(members):
        return members
    out: list[str] = []
    for index, member in enumerate(members):
        token = _port_token(member)
        if token is None:
            return _marker("unparsed", path, "ports",
                           f"member {index} is not a port or port range "
                           f"({facts.safe_repr(member)}); the WHOLE list is "
                           f"unresolved rather than silently shrunk")
        out.append(token)
    return tuple(out)


def cidrs(value: Any, *, path: str) -> tuple[str, ...] | facts.Unresolved:
    """A range list, VALIDATED as IP networks and returned verbatim.

    ALL-OR-NOTHING: one unparseable member makes the WHOLE tuple unresolved,
    because a partially parsed range set silently SHRINKS a rule's reach and a
    shrunken deny rule reads as a rule that does not block the traffic it
    blocks.

    Members are validated and NOT rewritten. The estate stores the spelling the
    API returned, so re-rendering ``10.0.0.0/8`` through :mod:`ipaddress` here
    would invent a second spelling of the same range for the compare step to
    miss. :data:`ANY_RANGE` passes through as itself.
    """
    members = _members(value, path, "cidrs")
    if facts.is_unresolved(members):
        return members
    out: list[str] = []
    for index, member in enumerate(members):
        if not isinstance(member, str) or facts.is_interpolated(member):
            return _marker("unparsed" if not isinstance(member, str) else "interpolation",
                           path, "cidrs",
                           f"member {index} is not a literal range "
                           f"({facts.safe_repr(member)}); the WHOLE list is "
                           f"unresolved rather than silently shrunk")
        text = member.strip()
        if text == ANY_RANGE:
            out.append(text)
            continue
        try:
            ipaddress.ip_network(text, strict=False)
        except ValueError:
            return _marker("unparsed", path, "cidrs",
                           f"member {index} is not an IP range; the WHOLE list is "
                           f"unresolved rather than silently shrunk")
        out.append(text)
    return tuple(out)


def string_list(value: Any, *, path: str) -> tuple[str, ...] | facts.Unresolved:
    """A list of literal strings, stripped.

    Refuses ANY interpolated member — and refuses the whole list when it does,
    for the same shrink argument :func:`cidrs` states: a tag or member list with
    one entry dropped is a narrower rule than the one that was written.
    """
    members = _members(value, path, "string_list")
    if facts.is_unresolved(members):
        return members
    out: list[str] = []
    for index, member in enumerate(members):
        if not isinstance(member, str):
            return _marker("unparsed", path, "string_list",
                           f"member {index} is not a string "
                           f"({facts.safe_repr(member)})")
        if facts.is_interpolated(member):
            return _marker("interpolation", path, "string_list",
                           f"member {index} is a program, not a literal; the WHOLE "
                           f"list is unresolved rather than silently shrunk")
        out.append(member.strip())
    return tuple(out)


def bool_or(value: Any, *, path: str) -> bool | facts.Unresolved:
    """A real boolean.

    Accepts the provider's STRING spellings — ``"TRUE"`` and ``"FALSE"``, which
    is how ``google_org_policy_policy`` writes its enforcement flag — as well as
    real booleans, case-insensitively. Nothing else: a ``0``/``1`` integer or an
    empty string becomes a marker rather than a default, because a boolean
    guessed wrong is a policy that reads as enforced when it is not.
    """
    if facts.is_unresolved(value):
        return value
    if isinstance(value, bool):
        return value
    text = _scalar(value, path, "bool_or")
    if facts.is_unresolved(text):
        return text
    folded = text.lower()
    if folded in _TRUE_SPELLINGS:
        return True
    if folded in _FALSE_SPELLINGS:
        return False
    return _marker("unparsed", path, "bool_or",
                   "not a boolean; the provider spells one true/false or "
                   "\"TRUE\"/\"FALSE\" and nothing else is guessed at")


def int_or(value: Any, *, path: str) -> int | facts.Unresolved:
    """A real integer, from an integer or from the decimal string spelling.

    A ``bool`` is REFUSED even though Python calls it an integer: silently
    reading ``True`` as priority ``1`` invents an ordering nobody wrote.
    """
    if facts.is_unresolved(value):
        return value
    if isinstance(value, bool):
        return _marker("unparsed", path, "int_or",
                       "a boolean is not a number; reading True as 1 would invent "
                       "a value nobody wrote")
    if isinstance(value, int):
        return value
    text = _scalar(value, path, "int_or")
    if facts.is_unresolved(text):
        return text
    digits = text[1:] if text[:1] in ("-", "+") else text
    if not digits.isdigit():
        return _marker("unparsed", path, "int_or", "not a decimal integer")
    return int(text)


def project_of(value: Any, *, path: str) -> str | facts.Unresolved:
    """WHICH PROJECT this value lives in, as a bare project id (or number).

    Accepts an already-bare id, ``projects/<id>``, and any project-scoped self
    link or relative name — a project-scoped resource name carries its own
    project (``projects/acme-prod/global/networks/vpc-main``), so reading it out
    is an extraction and not a guess. A value that names NO project (an
    organization node, a bare collection path) is ``ambiguous_key``: a qualifier
    that names nothing qualifies nothing.

    The NUMBER spelling is returned as the number, never resolved to an id here:
    only :func:`gcp_grounding.identity.alias_map` knows that mapping, and
    guessing it keys one project's facts onto another project's row. Building
    the KEY of a project-scoped category remains :mod:`gcp_grounding.identity`'s
    job; this only extracts the qualifier a key build needs.
    """
    text = strip_self_link(value, path=path)
    if facts.is_unresolved(text):
        return text
    segments = text.split("/")
    if segments[0] == "projects" and len(segments) > 1 and segments[1]:
        return segments[1]
    if len(segments) == 1 and segments[0]:
        return segments[0]
    return _marker("ambiguous_key", path, "project_of",
                   "this value names no project, so it cannot supply one")


def principal(value: Any, *, path: str) -> str | facts.Unresolved:
    """An IAM principal in its ``<type>:<identity>`` spelling.

    The type prefix is matched case-insensitively against the closed
    :data:`PRINCIPAL_PREFIXES` vocabulary and returned in IAM's own casing; the
    identity after the colon is never touched, because an email local part is
    case-sensitive in practice. ``allUsers`` and ``allAuthenticatedUsers`` carry
    no prefix and pass through as themselves.
    """
    text = _scalar(value, path, "principal")
    if facts.is_unresolved(text):
        return text
    for bare in UNPREFIXED_PRINCIPALS:
        if text.lower() == bare.lower():
            return bare
    prefix, separator, rest = text.partition(":")
    if not separator or not rest.strip():
        return _marker("unparsed", path, "principal",
                       "a principal is '<type>:<identity>'; 'user:a@x' and "
                       "'serviceAccount:a@x' are not one identity")
    for known in PRINCIPAL_PREFIXES:
        if prefix.strip().lower() == known.lower():
            return f"{known}:{rest.strip()}"
    return _marker("unparsed", path, "principal",
                   f"principal type is not one of {list(PRINCIPAL_PREFIXES)}")


def network_tag(value: Any, *, path: str) -> str | facts.Unresolved:
    """One bare network tag, case PRESERVED — the tag a rule names is the tag it
    names, and folding it would match a rule against traffic it does not
    match."""
    text = _scalar(value, path, "network_tag")
    if facts.is_unresolved(text):
        return text
    if (len(text) > MAX_TAG or "/" in text or ":" in text
            or any(character.isspace() for character in text)):
        return _marker("unparsed", path, "network_tag",
                       "a network tag is one bare token of at most "
                       f"{MAX_TAG} characters")
    return text


def restricted_service(value: Any, *, path: str) -> str | facts.Unresolved:
    """One VPC-SC restricted service hostname, lowercased.

    A hostname is case-insensitive by definition, and the estate stores the
    lowercase spelling the API returns, so folding here is the one direction
    that makes the two spellings converge instead of missing each other.
    """
    text = _scalar(value, path, "restricted_service")
    if facts.is_unresolved(text):
        return text
    if ("." not in text or "/" in text
            or any(character.isspace() for character in text)):
        return _marker("unparsed", path, "restricted_service",
                       "a restricted service is a bare service hostname "
                       "('storage.googleapis.com')")
    return text.lower()
