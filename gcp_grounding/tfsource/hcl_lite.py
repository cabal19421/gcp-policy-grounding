"""The one stdlib-only HCL2 subset lexer and parser, whose failure mode is
DOES-NOT-PARSE-THEREFORE-ABSTAINS.

THE DEPENDENCY DECISION. ``python-hcl2`` is rejected, for four specific
reasons. First, ``pyproject.toml`` declares ``dependencies = []`` and no task in
this design adds a runtime dependency, hard or optional. Second, it drags in
``lark``, a parser-generator runtime that exists in this venv only as a
``cel-python`` transitive and that nothing here uses. Third, it silently decodes
some expressions to STRINGS THAT LOOK LITERAL — an interpolation, a traversal or
a function call comes back as ordinary text, and a caller cannot tell that text
apart from a value terraform actually wrote. Fourth, and decisive: its failure
mode is PARSES-BUT-SUBTLY-MIS-DECODES, and a mis-decoded value MANUFACTURES A
CLAIM — the gate then answers ``ungrounded`` about a role name, a CIDR or a
network that terraform never intended to exist. This module's failure mode is
DOES-NOT-PARSE-THEREFORE-ABSTAINS: every value it cannot resolve becomes a
:class:`gcp_grounding.facts.Unresolved` naming why, and every file it cannot
read becomes an empty body plus a note. For a tool whose output BLOCKS AN AGENT,
abstaining is the only acceptable failure mode, because a false block costs one
retry while a false pass costs the whole point of the tool.

WHAT THIS MODULE IS NOT. It never calls ``eval``, never calls ``exec``, never
calls ``compile``, and never imports anything named by the input — no module
name, no file path and no template reference in a ``.tf`` file reaches an import
machinery. It also never EVALUATES a terraform expression: an evaluator is a
second implementation of terraform, and a second implementation of a
load-bearing rule is a second place for it to be wrong, silently. The
prohibition is asserted by a source scan over this module's own text in
``tests/test_gcp_tf_hcl_lite.py``, so it cannot be relaxed by accident.

WHAT IT DOES. :func:`tokenize` lexes the HCL2 subset terraform configuration
actually uses: comments in all three syntaxes (``#``, ``//`` and ``/* */``),
both heredoc forms as a SINGLE token, quoted strings with the escape set
including the four-hex ``\\uXXXX`` form, numbers, identifiers, significant
newlines and the full punctuation set. :func:`parse` turns that into a
:class:`Body` of attributes and blocks. Attribute values are kept as BALANCED
TOKEN SPANS and deliberately never as an expression tree — this module
CLASSIFIES an expression, it does not evaluate one — and :func:`classify_expr`
turns a span into either a plain Python literal or an ``Unresolved``.

THE SUBSET, stated so nobody is surprised by an abstention: identifiers are
ASCII, and any construct outside the subset raises :class:`HclSyntaxError`,
which :func:`parse_file` turns into an empty body plus a note. Refusing a file
this reader does not fully understand is the whole design; guessing at one is
the failure this module exists to avoid.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..core.log import get_logger
from ..facts import MAX_DEPTH, Unresolved, is_interpolated, truncate

logger = get_logger(__name__)

__all__ = [
    "MAX_DEPTH",
    "TOKEN_KINDS",
    "PUNCTUATION",
    "DEFAULT_PATH",
    "EMPTY_FILE_NOTE",
    "SYNTAX_NOTE_PREFIX",
    "DEPTH_NOTE_PREFIX",
    "ENCODING_NOTE_PREFIX",
    "READ_NOTE_PREFIX",
    "INTERNAL_NOTE_PREFIX",
    "HclSyntaxError",
    "HclDepthError",
    "Token",
    "Block",
    "Body",
    "ParsedFile",
    "tokenize",
    "parse",
    "parse_file",
    "classify_expr",
]

#: Every token kind the lexer emits. ``NEWLINE`` is a token rather than
#: whitespace because a newline TERMINATES an attribute in HCL, so throwing it
#: away would run two attributes together into one expression.
TOKEN_KINDS = ("IDENT", "STRING", "NUMBER", "HEREDOC", "PUNCT", "NEWLINE", "EOF")

#: The full punctuation set, LONGEST FIRST so the scan is maximal-munch and
#: ``==`` never lexes as two ``=``. Operators are lexed but never evaluated:
#: they exist so an expression can be spanned and classified, not computed.
PUNCTUATION = (
    "...", "==", "!=", "<=", ">=", "&&", "||", "=>",
    "{", "}", "[", "]", "(", ")",
    ".", ",", "=", ":", "?", "+", "-", "*", "/", "%", "!", "<", ">",
)

#: The path an :class:`~gcp_grounding.facts.Unresolved` carries when the caller
#: did not name one. ``Unresolved.path`` may not be empty — an unattributed
#: marker cannot be turned into a verdict — so there has to be a default.
DEFAULT_PATH = "<expression>"

#: Emitted when a file parses cleanly and declares NOTHING. It exists so
#: parsed-fine-nothing-here is distinguishable from parsed-fine-no-google-
#: resources: without it, an empty file and a file full of AWS resources are the
#: same answer, and only one of them means the reader was pointed somewhere
#: useless.
EMPTY_FILE_NOTE = ("parsed to an empty body: this file declares nothing at all, "
                   "which is not the same as declaring no google resources")

SYNTAX_NOTE_PREFIX = "hcl syntax this reader does not implement"
DEPTH_NOTE_PREFIX = "nesting past the depth cap"
ENCODING_NOTE_PREFIX = "not utf-8 text"
READ_NOTE_PREFIX = "cannot read"
INTERNAL_NOTE_PREFIX = "the hcl reader failed"

_OPENERS = ("(", "[", "{")
_CLOSERS = (")", "]", "}")
_DIGITS = frozenset("0123456789")
_IDENT_START = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_IDENT_CHARS = _IDENT_START | _DIGITS | {"-"}
_KEYWORDS = {"true": True, "false": False, "null": None}

#: Simple escapes the string lexer decodes. The unicode forms (``\\uXXXX`` and
#: ``\\UXXXXXXXX``) are handled separately because they carry a payload.
_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}

#: Returned by :func:`_decode` for a span that is not a literal at all.
_NOT_LITERAL = object()


# -- errors -------------------------------------------------------------------


class HclSyntaxError(Exception):
    """Syntax this reader does not implement, WITH WHERE IT IS.

    A line and a column are not decoration: an operator who is told a
    configuration file was refused needs to see the construct that was refused,
    or the honest abstention reads as the tool being broken.
    """

    def __init__(self, message: str, line: int, column: int) -> None:
        super().__init__(f"{message} (line {line}, column {column})")
        self.message = message
        self.line = line
        self.column = column


class HclDepthError(HclSyntaxError):
    """Blocks nested past :data:`MAX_DEPTH`.

    A subclass because it IS a refusal to parse, but a distinct one so
    :func:`parse_file` can say "too deep" rather than "malformed": a
    pathological file is a different operator problem from a typo. The cap is
    what stops a hand-crafted input from raising ``RecursionError`` inside a
    gate, and a crash inside a gate is a gate that decided nothing.
    """


# -- the tokens ---------------------------------------------------------------


@dataclass(frozen=True)
class Token:
    """One lexeme, with where it starts (both 1-based).

    ``text`` is the DECODED value for ``STRING`` and ``HEREDOC`` — escapes
    already applied, heredoc body already dedented for the ``<<-`` form — and
    the raw lexeme for everything else.
    """

    kind: str
    text: str
    line: int
    column: int


def _show(token: Token) -> str:
    """A token rendered for an ERROR MESSAGE, without its content.

    A ``STRING`` or ``HEREDOC`` token's text is an attribute value, and an
    attribute value is exactly where a token, a key or a customer identifier
    lives; an exception message reaches logs and tracebacks like any other
    rendering, so it gets the shape and not the bytes.
    """
    if token.kind in ("STRING", "HEREDOC"):
        return f"<{token.kind.lower()}>"
    if token.kind == "NEWLINE":
        return "<newline>"
    if token.kind == "EOF":
        return "<end of file>"
    return repr(token.text)


# -- the lexer ----------------------------------------------------------------


def tokenize(text: str) -> tuple[Token, ...]:
    """Lex ``text`` into tokens, or raise :class:`HclSyntaxError`.

    Comments in all three syntaxes are dropped; newlines are kept, because a
    newline terminates an attribute. Anything outside the implemented subset is
    an error rather than a guess.
    """
    tokens: list[Token] = []
    index = 0
    line = 1
    column = 1
    size = len(text)
    while index < size:
        char = text[index]
        if char in " \t\r":
            index += 1
            column += 1
            continue
        if char == "\n":
            tokens.append(Token("NEWLINE", "\n", line, column))
            index += 1
            line += 1
            column = 1
            continue
        # Three comment syntaxes: '#' and '//' to end of line, '/* */' inline
        # or across lines. The newline that ends a line comment is NOT eaten:
        # it still terminates the attribute the comment trailed.
        if char == "#" or text.startswith("//", index):
            stop = text.find("\n", index)
            stop = size if stop == -1 else stop
            column += stop - index
            index = stop
            continue
        if text.startswith("/*", index):
            stop = text.find("*/", index + 2)
            if stop == -1:
                raise HclSyntaxError("unterminated '/*' comment", line, column)
            chunk = text[index:stop + 2]
            breaks = chunk.count("\n")
            if breaks:
                line += breaks
                column = len(chunk) - chunk.rfind("\n")
            else:
                column += len(chunk)
            index = stop + 2
            continue
        if text.startswith("<<", index):
            token, index, line, column = _lex_heredoc(text, index, line, column)
            tokens.append(token)
            continue
        if char == '"':
            token, index, column = _lex_string(text, index, line, column)
            tokens.append(token)
            continue
        if char in _DIGITS:
            token, index, column = _lex_number(text, index, line, column)
            tokens.append(token)
            continue
        if char in _IDENT_START:
            stop = index
            while stop < size and text[stop] in _IDENT_CHARS:
                stop += 1
            tokens.append(Token("IDENT", text[index:stop], line, column))
            column += stop - index
            index = stop
            continue
        for mark in PUNCTUATION:
            if text.startswith(mark, index):
                tokens.append(Token("PUNCT", mark, line, column))
                index += len(mark)
                column += len(mark)
                break
        else:
            # Deliberately fatal. A character this reader does not know is a
            # construct it does not understand, and the whole contract is that
            # it says so rather than skipping ahead and decoding the remainder
            # of a file it has already lost its place in.
            raise HclSyntaxError(f"unexpected character {char!r}", line, column)
    tokens.append(Token("EOF", "", line, column))
    return tuple(tokens)


def _lex_string(text: str, index: int, line: int, column: int) -> tuple[Token, int, int]:
    """Lex one quoted string, applying the escape set."""
    start_column = column
    size = len(text)
    cursor = index + 1
    out: list[str] = []
    while True:
        if cursor >= size:
            raise HclSyntaxError("unterminated string", line, start_column)
        char = text[cursor]
        if char == '"':
            cursor += 1
            break
        if char == "\n":
            raise HclSyntaxError("newline inside a quoted string", line, start_column)
        if char != "\\":
            out.append(char)
            cursor += 1
            continue
        if cursor + 1 >= size:
            raise HclSyntaxError("unterminated escape in a string", line, start_column)
        marker = text[cursor + 1]
        if marker in _ESCAPES:
            out.append(_ESCAPES[marker])
            cursor += 2
            continue
        if marker in ("u", "U"):
            width = 4 if marker == "u" else 8
            digits = text[cursor + 2:cursor + 2 + width]
            if len(digits) != width or any(d not in "0123456789abcdefABCDEF" for d in digits):
                raise HclSyntaxError(f"a '\\{marker}' escape needs {width} hex digits",
                                     line, start_column)
            out.append(chr(int(digits, 16)))
            cursor += 2 + width
            continue
        raise HclSyntaxError(f"unknown string escape '\\{marker}'", line, start_column)
    # NOTE the deliberate omission: '$${' and '%%{' are NOT unescaped here. HCL
    # spells a literal '${' as '$${', so unescaping would produce a value that
    # LOOKS like a resolved literal; leaving the bytes alone keeps the '${'
    # substring present, classify_expr refuses the value, and the reader
    # abstains. That is conservative on purpose — see classify_expr.
    return Token("STRING", "".join(out), line, start_column), cursor, column + (cursor - index)


def _lex_number(text: str, index: int, line: int, column: int) -> tuple[Token, int, int]:
    """Lex one number: digits, an optional fraction and an optional exponent."""
    size = len(text)
    cursor = index
    while cursor < size and text[cursor] in _DIGITS:
        cursor += 1
    if cursor + 1 < size and text[cursor] == "." and text[cursor + 1] in _DIGITS:
        cursor += 1
        while cursor < size and text[cursor] in _DIGITS:
            cursor += 1
    if cursor < size and text[cursor] in "eE":
        ahead = cursor + 1
        if ahead < size and text[ahead] in "+-":
            ahead += 1
        if ahead < size and text[ahead] in _DIGITS:
            cursor = ahead
            while cursor < size and text[cursor] in _DIGITS:
                cursor += 1
    return (Token("NUMBER", text[index:cursor], line, column),
            cursor, column + (cursor - index))


def _lex_heredoc(text: str, index: int, line: int,
                 column: int) -> tuple[Token, int, int, int]:
    """Lex ``<<EOT`` or ``<<-EOT`` and its body as ONE token.

    Both forms are one token because a heredoc is a TEMPLATE, not a scalar:
    there is no partial answer to hand a caller, so there is nothing to be
    gained by lexing its interior. The token's text is the body, dedented for
    the ``<<-`` form, and the closing marker's newline is left in place so it
    still terminates the attribute.
    """
    size = len(text)
    cursor = index + 2
    indented = cursor < size and text[cursor] == "-"
    if indented:
        cursor += 1
    marker_start = cursor
    while cursor < size and text[cursor] in _IDENT_CHARS:
        cursor += 1
    marker = text[marker_start:cursor]
    if not marker or marker[0] not in _IDENT_START:
        raise HclSyntaxError("a heredoc needs an identifier marker after '<<'", line, column)
    end_of_opener = text.find("\n", cursor)
    if end_of_opener == -1:
        raise HclSyntaxError(f"heredoc <<{marker} is never closed", line, column)
    if text[cursor:end_of_opener].strip():
        raise HclSyntaxError("a heredoc opener must end its own line", line, column)
    body_lines: list[str] = []
    cursor = end_of_opener + 1
    while True:
        end_of_line = text.find("\n", cursor)
        raw = text[cursor:end_of_line] if end_of_line != -1 else text[cursor:]
        if raw.strip() == marker:
            body = _dedent(body_lines) if indented else "\n".join(body_lines)
            stop = end_of_line if end_of_line != -1 else size
            # The opener's line, then one line per body line, then the marker's.
            return (Token("HEREDOC", body, line, column),
                    stop, line + 1 + len(body_lines), len(raw) + 1)
        if end_of_line == -1:
            raise HclSyntaxError(f"heredoc <<{marker} is never closed", line, column)
        body_lines.append(raw)
        cursor = end_of_line + 1


def _dedent(lines: Sequence[str]) -> str:
    """Strip the common leading indentation, as ``<<-`` means."""
    widths = [len(one) - len(one.lstrip()) for one in lines if one.strip()]
    trim = min(widths) if widths else 0
    return "\n".join(one[trim:] if one.strip() else one.lstrip() for one in lines)


# -- the parsed shapes --------------------------------------------------------


@dataclass(frozen=True)
class Block:
    """One ``type "label" "label" { ... }`` block, with where it starts."""

    type: str
    labels: tuple[str, ...]
    body: "Body"
    line: int = 0
    column: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "labels", tuple(self.labels))


@dataclass(frozen=True)
class Body:
    """The contents of a file or of one block.

    ``attributes`` maps a name to its expression as a BALANCED TOKEN SPAN,
    never to a decoded value: decoding is :func:`classify_expr`'s job and the
    caller decides which path to attribute a marker to. ``blocks`` keeps
    repeated blocks in source order, because a provider spells each
    protocol/ports pair as its own block and keeping only the first (or the
    last) loses a port silently.

    ``dynamic`` is SEPARATE from ``blocks`` and keyed by the dynamic block's
    LABEL. A ``dynamic "rule"`` beside one static ``rule`` block would otherwise
    make a body look like it has exactly one rule, and a caller would conclude
    no permissive rule exists — a silent false negative on precisely the checks
    that matter. Keeping the two apart forces the caller to say something about
    the generated blocks it cannot see.
    """

    attributes: Mapping[str, tuple[Token, ...]] = field(default_factory=dict)
    blocks: tuple[Block, ...] = ()
    dynamic: Mapping[str, tuple[Block, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "attributes", dict(self.attributes))
        object.__setattr__(self, "blocks", tuple(self.blocks))
        object.__setattr__(self, "dynamic",
                           {key: tuple(value) for key, value in self.dynamic.items()})

    def is_empty(self) -> bool:
        """True if this body declares nothing at all."""
        return not (self.attributes or self.blocks or self.dynamic)


@dataclass(frozen=True)
class ParsedFile:
    """What :func:`parse_file` returns, ALWAYS: a body and the notes.

    On any failure the body is empty rather than partial. A half-parsed body is
    the same hazard as a mis-decoded value — it looks like a complete reading of
    a file and is not — so a refusal hands back nothing plus the reason.

    The empty body is built FRESH per result rather than shared from a module
    constant: ``Body`` is frozen but the mapping inside it is not, so one shared
    instance would let a caller's edit reach every later refusal.
    """

    path: str
    body: Body = field(default_factory=Body)
    notes: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "notes", tuple(self.notes))


# -- the parser ---------------------------------------------------------------


class _Parser:
    """A hand-written recursive-descent parser over the token stream.

    Recursion is bounded by :data:`MAX_DEPTH` block levels, which is what keeps
    a pathological input from reaching ``RecursionError``.
    """

    def __init__(self, tokens: Sequence[Token]) -> None:
        self._tokens = tuple(tokens)
        self._position = 0

    def _peek(self) -> Token:
        return self._tokens[self._position]

    def _next(self) -> Token:
        token = self._tokens[self._position]
        if token.kind != "EOF":
            self._position += 1
        return token

    def _skip_newlines(self) -> None:
        while self._peek().kind == "NEWLINE":
            self._position += 1

    def body(self, depth: int, closing: bool) -> Body:
        attributes: dict[str, tuple[Token, ...]] = {}
        blocks: list[Block] = []
        dynamic: dict[str, list[Block]] = {}
        while True:
            self._skip_newlines()
            token = self._peek()
            if token.kind == "EOF":
                if closing:
                    raise HclSyntaxError("unexpected end of file: a block is never closed",
                                         token.line, token.column)
                break
            if token.kind == "PUNCT" and token.text == "}":
                if not closing:
                    raise HclSyntaxError("unexpected '}': no block is open",
                                         token.line, token.column)
                self._next()
                break
            if token.kind != "IDENT":
                raise HclSyntaxError(
                    f"expected an attribute or block name, found {_show(token)}",
                    token.line, token.column)
            name = self._next()
            following = self._peek()
            if following.kind == "PUNCT" and following.text == "=":
                self._next()
                span = self.expression_span()
                if name.text in attributes:
                    # Real terraform rejects a body that sets one attribute
                    # twice, so accepting it here would mean this reader
                    # answers about a configuration terraform would never
                    # apply — and it would have to invent which one wins.
                    raise HclSyntaxError(
                        f"duplicate attribute {name.text!r}: terraform rejects a body "
                        f"that sets the same attribute twice",
                        name.line, name.column)
                attributes[name.text] = span
                continue
            labels: list[str] = []
            while self._peek().kind in ("STRING", "IDENT"):
                labels.append(self._next().text)
            opener = self._peek()
            if not (opener.kind == "PUNCT" and opener.text == "{"):
                raise HclSyntaxError(
                    f"expected '{{' to open the {name.text!r} block, "
                    f"found {_show(opener)}", opener.line, opener.column)
            self._next()
            if depth + 1 > MAX_DEPTH:
                raise HclDepthError(f"blocks nest deeper than MAX_DEPTH={MAX_DEPTH}",
                                    opener.line, opener.column)
            inner = self.body(depth + 1, closing=True)
            block = Block(name.text, tuple(labels), inner, name.line, name.column)
            if name.text == "dynamic":
                if len(labels) != 1:
                    raise HclSyntaxError(
                        "a dynamic block needs exactly one label naming the block "
                        "it generates", name.line, name.column)
                dynamic.setdefault(labels[0], []).append(block)
            else:
                # A REPEATED block is legal HCL and must not raise — unlike a
                # duplicate attribute. Two 'allow' blocks are two protocol/ports
                # pairs, and collapsing them would drop a port.
                blocks.append(block)
        return Body(attributes, tuple(blocks),
                    {label: tuple(found) for label, found in dynamic.items()})

    def expression_span(self) -> tuple[Token, ...]:
        """Consume one attribute value as a BALANCED TOKEN SPAN.

        Deliberately not an expression tree: this module classifies an
        expression, it does not evaluate one, and a tree is the first half of an
        evaluator. The span ends at a newline outside every bracket, or at the
        ``}`` that closes the enclosing block.
        """
        span: list[Token] = []
        start = self._peek()
        depth = 0
        while True:
            token = self._peek()
            if token.kind == "EOF":
                if depth:
                    raise HclSyntaxError("unexpected end of file inside an expression",
                                         token.line, token.column)
                break
            if token.kind == "NEWLINE" and depth == 0:
                break
            if token.kind == "PUNCT":
                if token.text in _OPENERS:
                    depth += 1
                elif token.text in _CLOSERS:
                    if depth == 0:
                        if token.text != "}":
                            raise HclSyntaxError(f"unbalanced {token.text!r} in an expression",
                                                 token.line, token.column)
                        break
                    depth -= 1
            span.append(self._next())
        if not span:
            raise HclSyntaxError("expected an expression after '='", start.line, start.column)
        return tuple(span)


def parse(text: str) -> Body:
    """Parse HCL text into a :class:`Body`, or raise :class:`HclSyntaxError`.

    Use :func:`parse_file` at any boundary that must not crash.
    """
    return _Parser(tokenize(text)).body(depth=0, closing=False)


def parse_file(path: Any) -> ParsedFile:
    """Read and parse a file. NEVER RAISES.

    A syntax error, a non-utf-8 file, an unreadable file, nesting past
    :data:`MAX_DEPTH` and an unforeseen internal failure each come back as an
    EMPTY body plus a note. A reader that raises inside a gate takes the gate
    down with it, and a gate that crashed decided nothing — which is strictly
    worse than a gate that abstained out loud.
    """
    target = Path(path)
    name = str(target)
    try:
        text = target.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        logger.debug("hcl read refused %s: not utf-8 (%s)", name, type(error).__name__)
        return ParsedFile(name, Body(),
                          (f"{ENCODING_NOTE_PREFIX}: {name} is not decodable as utf-8, "
                           f"so nothing in it was read",))
    except OSError as error:
        logger.debug("hcl read refused %s: %s", name, type(error).__name__)
        return ParsedFile(name, Body(),
                          (f"{READ_NOTE_PREFIX}: {name} ({type(error).__name__})",))
    try:
        body = parse(text)
    except HclDepthError as error:
        logger.debug("hcl parse refused %s: %s", name, error.message)
        return ParsedFile(name, Body(),
                          (f"{DEPTH_NOTE_PREFIX}: {name} nests blocks deeper than "
                           f"MAX_DEPTH={MAX_DEPTH} at line {error.line}, column "
                           f"{error.column}; nothing in it was read",))
    except HclSyntaxError as error:
        logger.debug("hcl parse refused %s: %s", name, error.message)
        return ParsedFile(name, Body(),
                          (f"{SYNTAX_NOTE_PREFIX}: {name} at line {error.line}, column "
                           f"{error.column}: {error.message}; nothing in it was read",))
    except Exception as error:                      # pragma: no cover - belt and braces
        # The three named failures above are the expected ones; this arm is what
        # makes "never raises" true rather than aspirational. It is logged, not
        # silent, because a swallowed surprise that nobody can grep for is how a
        # reader quietly stops reading.
        logger.debug("hcl parse failed on %s: %s", name, type(error).__name__, exc_info=True)
        return ParsedFile(name, Body(),
                          (f"{INTERNAL_NOTE_PREFIX}: {name} ({type(error).__name__}); "
                           f"nothing in it was read",))
    notes = (EMPTY_FILE_NOTE,) if body.is_empty() else ()
    return ParsedFile(name, body, notes)


# -- classification -----------------------------------------------------------


def _is_template(text: str) -> bool:
    """True if a decoded string is a TEMPLATE rather than a literal.

    ``facts.is_interpolated`` is the one spelling of the ``${`` rule and is
    reused rather than restated. ``%{`` — the template DIRECTIVE form, ``%{ for
    ... }`` — is refused for the same reason: it is a program, not a value.
    """
    return is_interpolated(text) or "%{" in text


def _safe_detail(tokens: Sequence[Token]) -> str:
    """A marker's ``detail`` for an expression, WITHOUT any value it carries.

    A span holding a ``STRING`` or a ``HEREDOC`` renders as its shape only: the
    literal halves of ``"secret-${var.x}"`` are attribute content, and a detail
    lands in the same places a value must not.
    """
    parts: list[str] = []
    for token in tokens:
        if token.kind in ("STRING", "HEREDOC"):
            return "an expression carrying a quoted value"
        parts.append(token.text)
    return truncate("".join(parts))


def classify_expr(span: Sequence[Token], path: str = DEFAULT_PATH,
                  _depth: int = 0) -> Any:
    """Classify one expression span: a plain Python literal, or an
    :class:`~gcp_grounding.facts.Unresolved` naming why it is not one.

    FIRST MATCH WINS, in this order — heredoc, interpolation, function_call,
    expression — and the order is the point. Every arm scans the WHOLE span, so
    a bracketed list with ANY non-literal element is WHOLLY unresolved rather
    than partially decoded: a list that silently shrinks is a firewall rule
    whose reach silently shrinks, and a check would then pass on a rule that
    does not exist.

    THE PARTIAL-INTERPOLATION RULE. The interpolation arm tests for the
    SUBSTRING ``"${"`` and never for a prefix. ``"roles/${var.tier}.admin"``
    starts with a literal and ends with one, so a prefix check would emit it as
    a literal role name and produce a guaranteed false ``ungrounded`` against a
    value terraform never intended to exist. The escaped literal form ``$${`` is
    ALSO refused, because it contains ``${`` — deliberately conservative, and
    said here so nobody later "fixes" it into a leak: mistaking an escaped
    literal for an interpolation costs one honest abstention, while mistaking an
    interpolation for a literal costs a false verdict about a name nobody wrote.

    The last arm — ``expression`` — is every bare traversal, splat, ternary and
    operator chain: ``local.net``, ``data.google_project.this.project_id``,
    ``google_compute_firewall.all[*].name``. It reports the reason
    ``interpolation``, which is the closed vocabulary's name for "the value is a
    program, not a literal"; ``facts.UNRESOLVED_REASONS`` is closed on purpose,
    so a free-text ``expression`` reason nobody can grep for is not an option.
    """
    tokens = tuple(token for token in span if token.kind != "NEWLINE")
    if not tokens:
        return Unresolved("unparsed", path, "an empty expression")

    # 1. heredoc — a template, and there is no partial answer to hand back.
    if any(token.kind == "HEREDOC" for token in tokens):
        return Unresolved("heredoc", path, "a heredoc body is a template, not a scalar")

    # 2. interpolation — anywhere in the span, and anywhere inside the string.
    for token in tokens:
        if token.kind == "STRING" and _is_template(token.text):
            return Unresolved("interpolation", path,
                              "a quoted string carrying '${' or '%{'")

    # 3. function_call — an identifier immediately applied. NEVER evaluated,
    #    not even when every argument is a literal: an evaluator is a second
    #    implementation of terraform.
    for index in range(len(tokens) - 1):
        after = tokens[index + 1]
        if (tokens[index].kind == "IDENT" and after.kind == "PUNCT" and after.text == "("):
            return Unresolved("function_call", path, truncate(f"{tokens[index].text}()"))

    # 4. a literal, or the catch-all expression arm.
    value = _decode(tokens, path, _depth)
    if value is _NOT_LITERAL:
        return Unresolved("interpolation", path, _safe_detail(tokens))
    return value


def _wraps(tokens: Sequence[Token], opener: str, closer: str) -> bool:
    """True if the span is exactly one bracketed group — ``[a] + [b]`` is not."""
    if len(tokens) < 2:
        return False
    if not (tokens[0].kind == "PUNCT" and tokens[0].text == opener):
        return False
    if not (tokens[-1].kind == "PUNCT" and tokens[-1].text == closer):
        return False
    depth = 0
    last = len(tokens) - 1
    for index, token in enumerate(tokens):
        if token.kind != "PUNCT":
            continue
        if token.text in _OPENERS:
            depth += 1
        elif token.text in _CLOSERS:
            depth -= 1
            if depth == 0 and index != last:
                return False
    return depth == 0


def _split_top(tokens: Sequence[Token]) -> list[tuple[Token, ...]]:
    """Split on ``,`` outside every bracket, dropping empty groups so a trailing
    comma in a list literal is not a phantom element."""
    groups: list[tuple[Token, ...]] = []
    current: list[Token] = []
    depth = 0
    for token in tokens:
        if token.kind == "PUNCT":
            if token.text in _OPENERS:
                depth += 1
            elif token.text in _CLOSERS:
                depth -= 1
            elif token.text == "," and depth == 0:
                if current:
                    groups.append(tuple(current))
                current = []
                continue
        current.append(token)
    if current:
        groups.append(tuple(current))
    return groups


def _number(text: str) -> Any:
    return float(text) if ("." in text or "e" in text or "E" in text) else int(text)


def _decode(tokens: Sequence[Token], path: str, depth: int) -> Any:
    """Decode a span as a literal, or return :data:`_NOT_LITERAL`.

    A nested element that is not a literal propagates ITS marker outward, which
    is what makes a list wholly unresolved rather than shortened.
    """
    if depth >= MAX_DEPTH:
        return Unresolved("depth_cap", path, f"nesting past MAX_DEPTH={MAX_DEPTH}")
    if len(tokens) == 1:
        token = tokens[0]
        if token.kind == "STRING":
            return token.text
        if token.kind == "NUMBER":
            return _number(token.text)
        if token.kind == "IDENT" and token.text in _KEYWORDS:
            return _KEYWORDS[token.text]
        return _NOT_LITERAL
    if (len(tokens) == 2 and tokens[0].kind == "PUNCT" and tokens[0].text in ("-", "+")
            and tokens[1].kind == "NUMBER"):
        value = _number(tokens[1].text)
        return -value if tokens[0].text == "-" else value
    if _wraps(tokens, "[", "]"):
        items: list[Any] = []
        for element in _split_top(tokens[1:-1]):
            value = classify_expr(element, path, _depth=depth + 1)
            if isinstance(value, Unresolved):
                return value                    # WHOLLY unresolved, never shortened
            items.append(value)
        return items
    if _wraps(tokens, "{", "}"):
        mapping: dict[str, Any] = {}
        for entry in _split_top(tokens[1:-1]):
            if len(entry) < 3 or entry[0].kind not in ("IDENT", "STRING"):
                return _NOT_LITERAL
            separator = entry[1]
            if not (separator.kind == "PUNCT" and separator.text in ("=", ":")):
                return _NOT_LITERAL
            value = classify_expr(entry[2:], path, _depth=depth + 1)
            if isinstance(value, Unresolved):
                return value
            mapping[entry[0].text] = value
        return mapping
    return _NOT_LITERAL
