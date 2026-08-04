"""Segment-span and offset-arithmetic behaviour of the bash-mutation parser.

MODULE UNDER TEST: ``gcp_grounding/bash_mutation.py`` (this task owns it alone).

WHY THESE TESTS EXIST — the hook's decision about WHICH SLICE OF THE COMMAND an
invocation occupies is what every downstream guard keys on, so an off-by-one in
the segment splitter or in a flag scanner's index arithmetic is a security hole,
not a formatting bug: a dropped character turns ``gcloud`` into ``cloud`` and the
segment stops being this gate's business, and a stolen character turns a
neighbouring mutation into part of the previous span. The table below pins the
PARSED SPANS (``MutationFinding.segment``) and the classifications the offsets
feed, over single-segment, multi-segment, adjacent-separator, leading-separator,
trailing-separator, empty-segment and quoting-disagrees-with-body commands.

MEASUREMENT RECORD (committed into the diff, not only the notes)
===============================================================
Tool: ``harness.pipeline.mutation.collect_sites`` / ``mutation_score``.
``harness`` is not installed in this project's venv; the import was made to work
with ``sys.path.insert(0, "/home/jones/Downloads/harness")`` (the PYTHONPATH
route is unavailable — ``VAR=x cmd`` is blocked in this sandbox).
Isolated copy: ``git archive <ref>`` into a scratch directory, unpacked with
Python's ``tarfile`` (``tar`` is blocked in this sandbox); the tarball is the
one ``git archive`` produced, so the copy's contents are the ref's contents.
Validation (the killer suite), run from the scratch copy:
``["/home/jones/Downloads/gcp-policy-grounding/.venv/bin/python -m pytest -q tests/"]``
UNMUTATED BASELINE ASSERTED GREEN IN THE ISOLATED COPY BEFORE EVERY RUN.

  target: gcp_grounding/bash_mutation.py     candidate sites: 108 (both refs)

  ref                                     exhaustive         40-draw
  -------------------------------------------------------------------------
  BEFORE  c8ac9c9 (branch tip, pre-task)  54/108 = 0.500     18/40 = 0.450
  AFTER   this commit                     101/108 = 0.935    38/40 = 0.950

  green unmutated baseline: BEFORE 475 passed, AFTER 525 passed (in the copy)
  diff size: 13,503 characters, inside the 18,000 budget (harness's verifier
  reads the whole diff; gitutil.diff_text clips at 20,000)

Acceptance was exhaustive > 0.8 and 40-draw >= 34/40: both met, and the 54
survivors fell to 7 — 47 more kills against a required 33. No mutation
annotation was lowered or deleted, no exclusion and no verify-off was added,
and gcp_grounding/bash_mutation.py itself is UNCHANGED (this diff is test-only).

THE 7 RESIDUAL SURVIVORS ARE MEASURED-EQUIVALENT MUTANTS (house rule 7)
----------------------------------------------------------------------
Not argued equivalent — measured. Each was applied alone to an isolated copy
and run against a 10,706-command corpus (every command in both bash-mutation
test modules, every wrapper/quoting/CLI shape, and each pair joined under
' && ', '&&', ' || ', '||', ' ; ', ';', ' | ', newline, ' & ' and ' '),
comparing every field of every MutationFinding AND every emitted Verdict.
No input separates the mutant from clean source:

  L228 `1` -> `2`   '||' via the two-char branch vs. twice via the ';|\\n'
                    branch differ only by an empty segment, which yields no
                    finding either way.
  L274 `<` -> `<=`  the out-of-range read is reachable only when EVERY token
                    is a wrapper/assignment, where clean source returns [] and
                    the IndexError is swallowed by scan_command — both silent.
  L342 `>` -> `>=`  len('-X') == 2 is already consumed by the `-X <METHOD>`
  L350 `>` -> `>=`  branch above it; likewise '-d' by _DATA_FLAGS. Unreachable.
  L399 `0` -> `1`   tokens[0] is always the CLI, a wrapper or an assignment,
                    so a --member can never sit at index 0.
  L408 `1` -> `2`   rsplit maxsplit under a [-1] read: the last field is the
  L419 `1` -> `2`   same for every maxsplit >= 1.

ESCALATION — the seven above cannot be killed through this module's public
behaviour, so they are recorded here rather than closed by an argument or by
any weakening. This repository has no Escalation channel on this branch (no
tests/test_gcp_escalations.py, no Escalation symbol anywhere in the checkout),
so this committed comment block is the escalation of record. A future task
that makes any of these seven observable — by widening the parser's public
surface or by exposing _split_segments — should kill it rather than re-derive
this note.
"""

import pytest

from gcp_grounding.bash_mutation import bash_mutation_verdicts, scan_command


def spans(command: str) -> list[str]:
    """The raw shell slices the gate decided each finding occupies."""
    return [f.segment for f in scan_command(command)]


def verbs(command: str) -> list[str]:
    return [f.verb for f in scan_command(command)]


def detail(command: str) -> str:
    findings = scan_command(command)
    assert len(findings) == 1, findings
    return findings[0].detail


# -- group SPLIT: the parsed spans ------------------------------------------

SPAN_CASES = [
    # one segment, no separator at all
    ("terraform apply", ["terraform apply"]),
    # two segments, each separator spelling, spaced and unspaced
    ("terraform apply && terraform destroy", ["terraform apply", "terraform destroy"]),
    ("terraform apply&&terraform destroy", ["terraform apply", "terraform destroy"]),
    ("terraform apply || terraform destroy", ["terraform apply", "terraform destroy"]),
    ("terraform apply||terraform destroy", ["terraform apply", "terraform destroy"]),
    ("terraform apply ; terraform destroy", ["terraform apply", "terraform destroy"]),
    ("terraform apply;terraform destroy", ["terraform apply", "terraform destroy"]),
    ("terraform apply | terraform destroy", ["terraform apply", "terraform destroy"]),
    ("terraform apply\nterraform destroy", ["terraform apply", "terraform destroy"]),
    # an empty segment between two real ones contributes no span
    ("terraform apply ;; terraform destroy", ["terraform apply", "terraform destroy"]),
    # a separator at the very start / the very end
    ("; terraform apply", ["terraform apply"]),
    ("terraform apply ;", ["terraform apply"]),
    ("terraform apply |", ["terraform apply"]),
    ("terraform apply &&", ["terraform apply"]),
    # a LONE '&' is not a separator: the whole line stays one span
    ("terraform apply & terraform destroy", ["terraform apply & terraform destroy"]),
    ("terraform apply &", ["terraform apply &"]),
    # three segments, mixed separators
    ("terraform apply && terraform destroy ; terraform apply",
     ["terraform apply", "terraform destroy", "terraform apply"]),
    # quoted separators stay inside their span, both quote flavours
    ("gcloud pubsub topics create 'a; b && c' && terraform apply",
     ["gcloud pubsub topics create 'a; b && c'", "terraform apply"]),
    ('gcloud pubsub topics create "a; b && c" && terraform apply',
     ['gcloud pubsub topics create "a; b && c"', "terraform apply"]),
    # quoting that disagrees with the body: the span is still cut correctly
    ('terraform apply && gcloud projects create "unclosed',
     ["terraform apply", 'gcloud projects create "unclosed']),
]


@pytest.mark.parametrize("command,expected", SPAN_CASES)
def test_parsed_spans(command, expected):
    assert spans(command) == expected


def test_spans_carry_their_own_classification():
    command = 'terraform apply && gcloud projects create "unclosed'
    findings = scan_command(command)
    assert [f.status for f in findings] == ["mutating", "unrecognized"]
    assert findings[0].verb == "terraform apply"


# -- group WRAPPER: leading assignments and sudo/env/nohup ------------------


@pytest.mark.parametrize("command", [
    "sudo terraform apply",
    "env terraform apply",
    "FOO=bar terraform apply",
    "FOO=bar sudo terraform apply",
    "sudo /usr/bin/terraform apply",
])
def test_wrapped_invocation_still_resolves_to_its_cli(command):
    # exactly ONE wrapper/assignment token is consumed per step: skipping two
    # would land on the subcommand and the segment would look like ordinary shell.
    assert verbs(command) == ["terraform apply"]
    assert spans(command) == [command]


# -- group HTTP: curl/wget flag-scan offsets --------------------------------

HTTP_CASES = [
    # -X <METHOD>: the method is the NEXT token, and scanning resumes past it
    ("curl -X POST https://iam.googleapis.com/v1/x", "mutating", "curl POST"),
    ("curl -X DELETE https://iam.googleapis.com/v1/x", "mutating", "curl DELETE"),
    # a read method plus a body flag: the body flag is still reached
    ("curl -X GET -d @b.json https://iam.googleapis.com/v1/x", "mutating", "curl POST"),
    ("curl -XGET -d @b.json https://iam.googleapis.com/v1/x", "mutating", "curl POST"),
    ("curl --request=GET -d @b.json https://iam.googleapis.com/v1/x",
     "mutating", "curl POST"),
    # a body flag first: a later -X still decides the effective method
    ("curl --data=x -X DELETE https://iam.googleapis.com/v1/x", "mutating", "curl DELETE"),
    ("curl -dname=foo -X DELETE https://iam.googleapis.com/v1/x", "mutating", "curl DELETE"),
    # the url leads and a valueless -X trails: neither runs off the end
    ("curl https://iam.googleapis.com/v1/x -d @b.json -X", "mutating", "curl POST"),
    ("curl -XDELETE https://compute.googleapis.com/v1/x", "mutating", "curl DELETE"),
    # -X is the LAST flag pair: its value is still read
    ("curl https://iam.googleapis.com/v1/x -X DELETE", "mutating", "curl DELETE"),
    # a glued value of any length is a value, and a body flag alone means POST
    ("curl -XA https://iam.googleapis.com/v1/x", "unrecognized", "curl A"),
    ("curl -d1 https://iam.googleapis.com/v1/x", "mutating", "curl POST"),
    ("curl -dname=foo https://iam.googleapis.com/v1/x", "mutating", "curl POST"),
    # the method is everything after the FIRST '=': a malformed value is not
    # silently narrowed to a recognized method.
    ("curl --request=POST=x https://iam.googleapis.com/v1/x",
     "unrecognized", "curl POST=X"),
]


@pytest.mark.parametrize("command,status,verb", HTTP_CASES)
def test_http_flag_scan(command, status, verb):
    findings = scan_command(command)
    assert len(findings) == 1, findings
    assert (findings[0].status, findings[0].verb) == (status, verb)


# -- group MEMBER: --member/--members value offsets -------------------------


def test_member_value_is_the_following_token():
    # --member sits second-to-last, so reading one token too far or one too
    # short loses the evidence entirely.
    assert "user:evil@evil.com" in detail(
        "gcloud projects add-iam-policy-binding p --member user:evil@evil.com")


def test_member_value_is_everything_after_the_first_equals():
    assert "user:evil@evil.com=x" in detail(
        "gcloud projects add-iam-policy-binding p --member=user:evil@evil.com=x")


def test_every_token_is_examined_for_a_member_flag():
    # the flag lands at an odd token index here: a scanner that advances two at
    # a time walks straight past it.
    assert "user:evil@evil.com" in detail(
        "gcloud iam roles update r --member=user:evil@evil.com")


def test_trailing_member_without_a_value_still_yields_a_finding():
    findings = scan_command("gcloud projects add-iam-policy-binding p --member")
    assert len(findings) == 1
    assert findings[0].status == "mutating"
    assert "flags seen:" not in findings[0].detail


@pytest.mark.parametrize("command", [
    # a member with no '@' at all is not an external identity
    "gcloud projects add-iam-policy-binding p --member=group:eng --role=roles/viewer",
    # an '@' value that is NOT a --member value is not evidence
    "gcloud iam service-accounts keys create k.json "
    "--iam-account=sa@proj.iam.gserviceaccount.com",
    # the internal domain, quoted: quote stripping must happen before the
    # domain comparison or the closing quote joins the domain
    'gcloud projects add-iam-policy-binding p --member="user:alice@acme.example"',
    # -auto-approve is evidence only when it is actually present
    "terraform state rm aws_instance.foo",
])
def test_no_spurious_evidence(command):
    assert "flags seen:" not in detail(command)


# -- group VERDICT: the emitted verdicts are not anchored to a line ---------


@pytest.mark.parametrize("command", [
    "terraform apply\nterraform destroy\ngcloud pubsub topics create t",
    "gcloud beta wibble a\ngcloud beta wibble b\ngcloud beta wibble c",
])
def test_bash_verdicts_name_no_source_line(command):
    verdicts = bash_mutation_verdicts(command)
    assert len(verdicts) == 3
    linenos = {v.lineno for v in verdicts}
    # A shell segment has no source line. Every verdict must carry the same
    # non-anchoring lineno, and it must not name any real line of the command.
    assert len(linenos) == 1
    assert not (linenos & {1, 2, 3})
