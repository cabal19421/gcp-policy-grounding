"""The ABSTAIN BUCKET: undecidable inputs stay ``unverified`` and stay visible.

Every case in this module hands the real ``gcp-ground verify-policy --hook``
process something it genuinely cannot judge — a raw HCL file, non-UTF-8 bytes,
a document shape no extractor recognizes, a document whose grants were never
read, a snapshot category that was never captured, a baseline that is not an
IAM allow policy — and asserts the same outcome: **exit 0, byte-empty stdout,
the hook ITSELF naming what it could not judge on stderr, and the ignorance on
the record as at least one ``unverified``, with nothing manufactured into
``ungrounded`` or ``contradicted``.** :func:`assert_abstain_bucket` is that
assertion, in one place, so a case added later cannot quietly forget a leg.

Two failure modes are being held apart here, and only one of them is loud.
A missed *block* at least leaves the bad name in the diff. A missed *abstain*
tells the reviewer the gate looked and was happy — the gate's silence is
indistinguishable from a clean pass. So "exit 0" alone is never the assertion;
exit 0 *plus* a named reason is.

WHERE THE EVIDENCE COMES FROM, and why this module was repinned. It used to
come exclusively from a SEPARATE non-hook subprocess: the only legs asserted
about the hook run were exit code 0 and byte-empty stdout, which are
byte-identical to the CLI's not-my-file early return and to a clean pass.
MEASURED against the module as it stood: a hook stub returning success as its
FIRST statement — never reading the event, never loading a snapshot, never
grounding anything — left 10 of its 14 tests passing, and a hook that ignores
the event's path and grounds a hardcoded name left 11 of 14 passing. It read as
end-to-end proof of honest abstention while proving only that the normal-mode
CLI abstains.

EVERY case now carries POSITIVE IN-HOOK EVIDENCE, through the channel
``sx-hook-abstain-notes`` landed: ``--abstain-notes`` prints the verdicts the
gate could not judge to stderr INSIDE the ``report.ok`` arm of
``cli._run_hook``, so an abstaining run is observable at exit 0 without changing
production behaviour to suit a test. Each case requires the ``NOT DECIDED``
header, its own reason substrings, and at least one token drawn from THE FILE'S
OWN CONTENT — or, where the document is unparsable and has no content the gate
ever read, its own path. Both mutants above die on that leg: the stub prints
nothing at all, the wrong-file hook prints a reason about a document nobody
edited. RE-MEASURED after the repin, the same two source edits applied to a copy
of this tree: each reddens 16 of the 20 cases here, and the four survivors are
the four that never drive the hook (the transport check, the render pin and the
two contract-registry assertions).

EACH CASE DRIVES THE HOOK TWICE: the real child (:func:`run_hook` — argv, stdin
decoding, the two streams, the exit code) and the same ``cli._run_hook`` IN THIS
PROCESS (:func:`in_process_hook`). The mirror costs no spawn, and it is the one
an in-process ``Removal`` can reach — a monkeypatch of ``gcp_grounding.cli`` in
the parent is invisible to a child interpreter, which is why the two removals
this module owns are witnessed against it.

THE REPORT IS A CONTROL, AND IS NAMED ONE. :func:`report_of` runs the same
``ground_policy`` the child runs, in this process, rendered through the same
``PolicyReport`` the CLI's ``--format json`` renders. It is deliberately NOT
spawned per case: the suite-wide ceiling measured 449 of 450 spawns before this
repin, the in-hook evidence had to be paid for, and a sidecar child was never
evidence about the hook — that confusion is the defect being removed. The
transport is still exercised once, by
:func:`test_the_in_process_control_is_the_report_the_cli_prints`, which requires
the spawned document and the control to be EQUAL, so the control cannot drift
from the instrument it stands in for. :data:`MODULE_SPAWN_CAP` pins this
module's share at module teardown.

Degenerate inputs are written into ``tmp_path`` inline rather than committed
as fixtures, following the suite's existing convention: a file whose only
purpose is to be unparsable has no business in a fixtures directory where the
next reader has to guess whether it is broken on purpose.

Imports are by FULL dotted path (``tests.agentic.…``) because ``tests/`` is a
regular Python package — see ``tests/__init__.py``, which must not be removed.
"""

from __future__ import annotations

import io
import json
import sys

import pytest

from gcp_grounding import cli, preflight
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.report import PolicyReport
from tests.agentic import env, hookrunner
from tests.agentic.asserts import (
    assert_abstained, assert_blocked, assert_no_verdictless_pass,
    assert_recorded)
from tests.agentic.hookrunner import (
    HookOutcome,
    bound_subprocess_budget,  # noqa: F401 — autouse: bind spawns to the budget
    ground_json,
    run_hook,
    run_hook_explain,
)

#: This module's share of the suite-wide spawn budget, MEASURED: one child per
#: hook run, plus C08's and C11's blocking controls, plus the ONE ``--format
#: json`` transport check. Checked at module teardown.
MODULE_SPAWN_CAP = 20

#: C09's deliberately ancient capture stamp. Old enough that nobody would
#: defend trusting it, and the gate trusts it anyway — that is the finding.
STALE_CAPTURED_AT = "2019-01-01T00:00:00Z"

#: A member the estate snapshot has never heard of, used by C08 and C01.
ATTACKER = "user:attacker@evil.example"

#: The abstain channel, ON. Opt-in in production (``cli._abstain_notes``), and
#: the whole reason an exit-0 hook run is observable here at all.
NOTES = ("--abstain-notes",)

#: The header ``cli._abstain_note_lines`` writes before the verdicts it could
#: not judge. Its PRESENCE proves the child reached the ``report.ok`` arm with a
#: real report in hand; its ABSENCE, on a run whose channel is on, proves the
#: gate produced no verdict at all (which is what C11 is about).
NOT_DECIDED = "gcp-ground --hook: NOT DECIDED"

#: A Kubernetes ConfigMap: parses perfectly, means nothing here. C04's document,
#: and the abstain-only report the render case is about.
_CONFIGMAP = {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {"name": "app-config", "namespace": "default"},
    "data": {"LOG_LEVEL": "debug"},
}


def hook_event(path) -> dict:
    """An editor-agent PostToolUse event naming *path* as the edited file."""
    return {
        "session_id": "abstain-bucket",
        "hook_event_name": "PostToolUse",
        "tool_name": "Write",
        "tool_input": {"file_path": str(path)},
    }


def write_json(path, document):
    """Write *document* to *path* as JSON and return the path."""
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path


@pytest.fixture(scope="module", autouse=True)
def _module_spawn_cap(subprocess_budget):
    """Pin this module's share of the suite-wide spawn budget.

    The session ceiling is shared, so it cannot notice one module growing at the
    others' expense; this one can. Checked at module teardown rather than
    per-test so a ``-k`` selection does not trip it.
    """
    before = subprocess_budget.total
    yield
    spent = subprocess_budget.total - before
    assert spent <= MODULE_SPAWN_CAP, (
        f"this module spawned {spent} children, over its cap of "
        f"{MODULE_SPAWN_CAP}; the oracle is the full test run and an unbounded "
        f"suite stops being run at all")


# -- THE TWO INSTRUMENTS ------------------------------------------------------


@pytest.fixture
def in_process_hook(monkeypatch, capsys):
    """Factory: drive ``cli._run_hook`` over *event* IN THIS PROCESS.

    The same entry point the child runs — ``cli.main(["verify-policy",
    "--hook", …])`` reading the event off ``sys.stdin`` — with the child's own
    determinism: every name in :data:`~tests.agentic.hookrunner.SCRUBBED_ENV` is
    removed first, so a developer's exported ``GCP_GROUNDING_SNAPSHOT`` or
    ``GCP_GROUNDING_REQUIREMENTS`` cannot change a verdict here either.

    Two jobs. It costs no subprocess, which is what lets every case carry the
    in-hook evidence leg under a ceiling that had one spawn of headroom left.
    And it is REACHABLE BY A MONKEYPATCH: a ``Removal`` takes a symbol away in
    the parent process, which a child re-importing ``gcp_grounding`` never sees
    — measured, all 14 cases of this module stayed GREEN under
    ``RM-HOOK-SUCCESS-BEFORE-THE-EVENT`` before this mirror existed.

    The result is a :class:`~tests.agentic.hookrunner.HookOutcome`, stderr
    scrubbed by the same :func:`~tests.agentic.hookrunner.scrub_stderr`, so the
    shared assertion helpers read it exactly as they read a child's.
    """

    def run(event, *, snapshot=None, extra_argv=()) -> HookOutcome:
        for name in hookrunner.SCRUBBED_ENV:
            monkeypatch.delenv(name, raising=False)
        argv = ["verify-policy", "--hook", *NOTES]
        if snapshot is not None:
            argv += ["--snapshot", str(snapshot)]
        argv += list(extra_argv)
        payload = json.dumps(event)
        monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
        capsys.readouterr()  # nothing an earlier call left may leak into this
        exit_code = cli.main(argv)
        captured = capsys.readouterr()
        return HookOutcome(
            exit_code=exit_code,
            stdout=captured.out,
            stderr=hookrunner.scrub_stderr(captured.err),
            argv=("<in process>", *argv),
            event=event,
            stdin_bytes=payload.encode("utf-8"),
            stderr_raw=captured.err,
        )

    return run


def report_of(path, *, snapshot, baseline=None) -> dict:
    """THE CONTROL: the ``gcp-grounding-report/1`` document for *path*.

    The same :func:`~gcp_grounding.preflight.ground_policy` the hook child runs,
    over the same document and snapshot, rendered through the same
    :class:`~gcp_grounding.report.PolicyReport` the CLI's ``--format json``
    renders — in this process, because it is a CONTROL and not evidence about
    the hook. Reading it as though a second subprocess made it evidence is the
    confusion this module was repinned to remove.
    """
    loaded = (snapshot if isinstance(snapshot, GcpSnapshot)
              else GcpSnapshot.load(snapshot))
    report = preflight.ground_policy(
        str(path), loaded, baseline=None if baseline is None else str(baseline))
    return PolicyReport(report, captured_at=loaded.captured_at,
                        source=str(path)).to_dict()


def test_the_in_process_control_is_the_report_the_cli_prints(
        tmp_path, estate_snapshot_path):
    """THE ONE SIDECAR SPAWN THIS MODULE STILL SPENDS.

    :func:`report_of` stands in for
    :func:`~tests.agentic.hookrunner.ground_json` everywhere else here, so the
    two must be the SAME DOCUMENT — schema, backend, capture stamp, summary and
    verdicts included. If the CLI's ``--format json`` path ever renders
    something the control does not, every bucket assertion here is read off the
    wrong instrument, and this is where that is found.
    """
    document = write_json(tmp_path / "configmap.json", _CONFIGMAP)
    spawned = ground_json(document, snapshot=estate_snapshot_path)
    assert spawned == report_of(document, snapshot=estate_snapshot_path), (
        "the spawned --format json report and the in-process control disagree; "
        "the control is not the instrument it stands in for")


# -- THE CROSS-CUTTING ASSERTION ----------------------------------------------


def assert_named_by_the_hook(outcome, *tokens) -> None:
    """POSITIVE IN-HOOK EVIDENCE: the abstaining run SAID SO, itself.

    Exit 0 with byte-empty stdout is byte-identical to the CLI's "this file is
    not mine to judge" early return, to its broken-setup fail-open and to a
    clean pass, so neither leg is evidence that anything was examined. This one
    is: with the abstain channel on, ``cli._run_hook`` prints
    :data:`NOT_DECIDED` and one line per verdict it could not judge INSIDE the
    ``report.ok`` arm, so the header can only appear on a run that loaded a
    snapshot, ground a document and got a report back.

    Every *token* must appear in that stderr — a case's own reason substrings
    plus at least one drawn from THE FILE'S OWN CONTENT (or its path, where the
    document is unparsable and has no content the gate ever read), which is what
    tells "the hook judged MY file" from "the hook judged something".
    """
    assert tokens, (
        "assert_named_by_the_hook needs at least one token: a hook that names "
        f"nothing has not shown it read anything\n{outcome}")
    assert outcome.exit_code == 0, (
        f"an undecidable input must not fail the gate — ignorance is exit 0, "
        f"not a block; got {outcome.exit_code}\n{outcome}")
    assert outcome.stdout == "", (
        f"an abstaining hook run must leave stdout byte-empty\n{outcome}")
    assert NOT_DECIDED in outcome.stderr, (
        f"the hook itself said nothing: with the abstain channel on, a run that "
        f"really ground this document prints {NOT_DECIDED!r}. A hook that "
        f"returns success before reading the event prints exactly this "
        f"much — nothing\n{outcome}")
    for token in tokens:
        assert token in outcome.stderr, (
            f"expected {token!r} in the hook's OWN stderr — without a token "
            f"from this file, an abstention about some other document reads "
            f"identically\n{outcome}")


def assert_abstain_bucket(outcome, mirror, report, *substrings, named) -> None:
    """Every leg of the abstain bucket, for one case, in one call.

    The five report legs are spelled out here rather than only delegated, on
    purpose: they are this module's contract, and naming them locally means a
    change to the shared :func:`~tests.agentic.asserts.assert_abstained` cannot
    silently drop one from every C-case at once. The delegation still happens —
    the shared helper owns ``report.ok``, the source cross-check and the "an
    abstain must name its reason" substring check, and its assertion messages
    are the ones a red run reads.

    THE SIXTH LEG is the one this repin added: :func:`assert_named_by_the_hook`,
    over BOTH the child (*outcome*) and the in-process mirror. *named* is
    required and may not be empty — a case that names no token of its own file
    is back to asserting an exit code the CLI's not-my-file early return
    produces just as well.
    """
    for run in (outcome, mirror):
        assert run.exit_code == 0, (
            f"an undecidable input must not fail the gate — ignorance is exit "
            f"0, not a block; got {run.exit_code}\n{run}")
        assert run.stdout == "", (
            f"an abstaining hook run must leave stdout byte-empty\n{run}")
    summary = report.get("summary") or {}
    assert summary.get("unverified", 0) >= 1, (
        f"an abstain must record at least one unverified verdict — exit 0 with "
        f"no verdict is a silent pass\nsummary={summary!r}\n{outcome}")
    assert summary.get("ungrounded", 0) == 0, (
        f"an abstain must not manufacture an ungrounded name out of ignorance\n"
        f"summary={summary!r}\n{outcome}")
    assert summary.get("contradicted", 0) == 0, (
        f"an abstain must not manufacture a contradiction out of ignorance\n"
        f"summary={summary!r}\n{outcome}")
    assert_abstained(outcome, report, *substrings)
    assert_abstained(mirror, report, *substrings)
    assert named, (
        "assert_abstain_bucket needs a `named` token from the file's own "
        "content or its own path: the abstain channel naming SOME reason is "
        f"not this file's abstention\n{outcome}")
    for run in (outcome, mirror):
        assert_named_by_the_hook(run, *substrings, *named)


def assert_fail_open_bucket(outcome, *substrings) -> None:
    """THE STDERR-ONLY ARM, for the run that produced NO REPORT AT ALL.

    ``cli._run_hook`` returns the moment the snapshot will not load, before any
    document is ground, so there is no report to hold against the four-bucket
    legs — and reaching for a report made under a DIFFERENT, working snapshot
    certifies a different world. The honest property is the one asserted here:
    exit 0, byte-empty stdout, the fail-open note naming what happened, and —
    with the abstain channel ON — NO :data:`NOT_DECIDED` header and no rendered
    report, which is exactly how ZERO verdicts is told apart from an abstention.
    """
    assert substrings, (
        "assert_fail_open_bucket needs at least one substring: a bare exit code "
        f"asserts nothing about what the operator was told\n{outcome}")
    assert outcome.exit_code == 0, (
        f"a broken gate must never block an edit; got {outcome.exit_code}\n"
        f"{outcome}")
    assert outcome.stdout == "", (
        f"a fail-open hook run must leave stdout byte-empty\n{outcome}")
    for substring in substrings:
        assert substring in outcome.stderr, (
            f"expected {substring!r} on stderr — fail-open is only survivable "
            f"if it says so\n{outcome}")
    assert NOT_DECIDED not in outcome.stderr, (
        f"the abstain channel was ON and printed a header, so this run DID "
        f"produce verdicts — then it is not the fail-open path and this "
        f"assertion is about the wrong run\n{outcome}")
    assert "GCP policy grounding" not in outcome.stderr, (
        f"a rendered grounding report means a document was ground; the "
        f"fail-open path grounds nothing\n{outcome}")


# -- C01: a raw HCL file is not `terraform show -json` ------------------------


def test_c01_raw_hcl_abstains_and_never_blocks(tmp_path, estate_snapshot_path,
                                               in_process_hook):
    """An edited ``main.tf`` is HCL, not plan JSON: the JSONDecodeError is an
    abstain, and the hallucinated role inside it gets SILENCE.

    ``.tf`` is in :data:`gcp_grounding.cli._HOOK_SUFFIXES`, so the hook does
    pick this file up and does run the gate over it — it just cannot parse it.
    Anyone wiring the hook expecting it to catch a hallucinated role in an
    edited ``main.tf`` gets exactly nothing back; only committed
    ``terraform show -json`` output is actually gated. That gap is the reason
    this case exists.

    The named token is the file's own PATH, not a token of its content: an
    unparsable document has no content the gate ever read, and the path is what
    separates "the hook opened the file this event named" from "the hook opened
    something".
    """
    document = tmp_path / "main.tf"
    document.write_text(
        'resource "google_project_iam_binding" "hallucinated" {\n'
        '  project = "acme-prod"\n'
        '  role    = "roles/bigquery.reader"\n'
        f'  members = ["{ATTACKER}"]\n'
        "}\n",
        encoding="utf-8")

    event = hook_event(document)
    outcome = run_hook(event, snapshot=estate_snapshot_path, extra_argv=NOTES)
    mirror = in_process_hook(event, snapshot=estate_snapshot_path)
    report = report_of(document, snapshot=estate_snapshot_path)
    assert_abstain_bucket(outcome, mirror, report,
                          "not valid JSON", "nothing was checked",
                          named=(str(document),))

    assert ".tf" in cli._HOOK_SUFFIXES, (
        "the premise of this case: the hook DOES select .tf files, so the "
        "silence below is the parser's, not the suffix filter's")
    assert outcome.exit_code != cli.EXIT_BLOCK, str(outcome)
    # The teeth: a fabricated role and a fabricated member sat in the edited
    # file and the hook said nothing about either.
    assert "roles/bigquery.reader" not in outcome.stderr, str(outcome)
    assert ATTACKER not in outcome.stderr, str(outcome)


# -- C02: bytes that are not text ---------------------------------------------


def test_c02_garbled_bytes_abstain(tmp_path, estate_snapshot_path,
                                   in_process_hook):
    """Non-UTF-8 bytes raise UnicodeDecodeError — a ValueError that is NOT a
    JSONDecodeError, which is why ``_load_document`` needs its own arm."""
    document = tmp_path / "garbled.json"
    document.write_bytes(b'{"bindings": [{"role": "roles/\xff\xfe\x00viewer"}]}')

    event = hook_event(document)
    outcome = run_hook(event, snapshot=estate_snapshot_path, extra_argv=NOTES)
    mirror = in_process_hook(event, snapshot=estate_snapshot_path)
    report = report_of(document, snapshot=estate_snapshot_path)
    assert_abstain_bucket(outcome, mirror, report,
                          "could not be parsed", "nothing was checked",
                          named=(str(document), "UnicodeDecodeError"))


# -- C03: nesting deep enough to blow the parser's stack ----------------------


def test_c03_deep_nesting_abstains_without_a_traceback(
        tmp_path, estate_snapshot_path, in_process_hook):
    """200000 nested brackets: deep enough to trip RecursionError in the JSON
    scanner, shallow enough that the child stays fast.

    The failure mode being excluded is a traceback escaping ``ground_policy``:
    a crash in the hook is an exit code the editor agent reads as *something*, and
    a gate that dies on a pathological file is a gate someone disables.
    """
    document = tmp_path / "deeply_nested.json"
    document.write_text("[" * 200000 + "]" * 200000, encoding="utf-8")

    event = hook_event(document)
    outcome = run_hook(event, snapshot=estate_snapshot_path, extra_argv=NOTES)
    mirror = in_process_hook(event, snapshot=estate_snapshot_path)
    report = report_of(document, snapshot=estate_snapshot_path)
    assert_abstain_bucket(outcome, mirror, report, "nothing was checked",
                          named=(str(document),))

    messages = " ".join(v["message"] for v in report["verdicts"])
    assert "RecursionError" in messages or "could not be parsed" in messages, (
        f"the abstain must name the parse failure, not just record one\n"
        f"{messages}")
    assert "Traceback" not in outcome.stderr, str(outcome)


# -- C04: a document from some other world ------------------------------------


def test_c04_unrecognized_kind_abstains_naming_the_keys(
        tmp_path, estate_snapshot_path, in_process_hook):
    """A Kubernetes ConfigMap parses perfectly and means nothing here.

    The abstain names the top-level keys it saw, which is what lets a reader
    tell "the gate does not know this shape" from "the gate found nothing
    wrong" — and those keys are the file's OWN content, so requiring one of
    them in the hook's stderr is the strongest in-hook evidence available to
    any case here.
    """
    document = write_json(tmp_path / "configmap.json", _CONFIGMAP)

    event = hook_event(document)
    outcome = run_hook(event, snapshot=estate_snapshot_path, extra_argv=NOTES)
    mirror = in_process_hook(event, snapshot=estate_snapshot_path)
    report = report_of(document, snapshot=estate_snapshot_path)
    assert_abstain_bucket(outcome, mirror, report,
                          "document kind was not recognized", "top-level keys",
                          named=(str(document), "apiVersion", "metadata"))


# -- C05: recognized, and still nothing to check ------------------------------


#: case → (detected kind, document). The kind is asserted IN THE HOOK'S OWN
#: stderr, so each case's in-hook token is what the gate says it recognized.
_UNEXTRACTABLE = {
    # `bindings` as an object: detect_kind says iam_policy (the key is there),
    # iam_policy_claims refuses to guess at a non-array (claims.py:108) and
    # returns nothing.
    "bindings_as_object": ("iam_policy", {
        "bindings": {"role": "roles/bigquery.dataViewer",
                     "members": ["user:alice@acme.example"]},
        "etag": "BwXtRfPolicy=",
        "version": 3,
    }),
    # v1 `constraint` and v2 `name` at once: _org_policy_constraint calls that
    # ambiguous (claims.py:180) and emits nothing, including no value claim.
    "hybrid_v1_plus_v2_org_policy": ("org_policy", {
        "constraint": "constraints/compute.vmExternalIpAccess",
        "name": "projects/acme-prod/policies/compute.vmExternalIpAccess",
        "spec": {"rules": [{"enforce": True}]},
    }),
}


@pytest.mark.parametrize("case", sorted(_UNEXTRACTABLE), ids=sorted(_UNEXTRACTABLE))
def test_c05_recognized_but_unextractable_abstains(case, tmp_path,
                                                   estate_snapshot_path,
                                                   in_process_hook):
    """The zero-claims honesty guard (``preflight.py:112``).

    Both documents are RECOGNIZED — a kind is detected — and both carry
    content the conservative extractors decline to interpret. Without the
    guard, zero claims means zero verdicts, and zero verdicts renders exactly
    like a clean pass. This is the case that turns "I skipped all of it" into
    a verdict.
    """
    kind, body = _UNEXTRACTABLE[case]
    document = write_json(tmp_path / f"{case}.json", body)

    event = hook_event(document)
    outcome = run_hook(event, snapshot=estate_snapshot_path, extra_argv=NOTES)
    mirror = in_process_hook(event, snapshot=estate_snapshot_path)
    report = report_of(document, snapshot=estate_snapshot_path)
    assert_abstain_bucket(outcome, mirror, report,
                          "detected", "nothing checkable could be extracted",
                          named=(str(document), f"detected {kind} content"))


# -- THE VERDICTLESS EXIT-0 PASS: a document whose grants were never read -----


#: case → document. Both are IAM allow policies by ``detect_kind`` and neither
#: carries a readable ``bindings``, so a gate that treated zero claims as
#: "grants nothing" would pass them in silence: the module's own stated worst
#: failure mode, and it had no case until this repin.
_NEVER_READ = {
    # A mis-cased key. `detect_kind` reaches iam_policy on `etag` + `version`
    # alone, `iam_policy_claims` never sees a `bindings`, and `Bindings` — with
    # a hallucinated member inside it — is read by nothing.
    "bindings_key_mis_cased": {
        "Bindings": [{"role": "roles/bigquery.dataViewer",
                      "members": [ATTACKER]}],
        "etag": "BwXtRfPolicy=",
        "version": 1,
    },
    # No `bindings` key at all, just the two identifying scalars: a wrapped
    # `setIamPolicy` body whose `policy` was dropped looks exactly like this.
    "identifying_scalars_only": {
        "etag": "BwXtRfPolicy=",
        "version": 3,
    },
}


@pytest.mark.parametrize("case", sorted(_NEVER_READ), ids=sorted(_NEVER_READ))
def test_a_document_whose_grants_were_never_read_is_not_a_verdictless_pass(
        case, tmp_path, estate_snapshot_path, in_process_hook):
    """GATE 0, end to end through the hook: an ABSENT ``bindings`` is not an
    empty one.

    ``preflight._legitimately_empty`` licenses zero claims for exactly one
    shape — an IAM allow policy carrying an explicit ``bindings: []``, which
    really does grant nothing. Neither document here has the key at all, so
    nothing was read from either, and the zero-claims honesty guard must record
    that. :func:`~tests.agentic.asserts.assert_no_verdictless_pass` is the
    whole-document form of the property and is asserted here in its own right:
    exit 0 with zero verdicts is indistinguishable from a document the gate
    deliberately passed, and the mis-cased case has a hallucinated member
    sitting inside the key nobody read.

    This test is NOT softened to the pre-Gate-0 behaviour: a report with no
    verdicts fails it, which is the point.
    """
    document = write_json(tmp_path / f"{case}.json", _NEVER_READ[case])

    event = hook_event(document)
    outcome = run_hook(event, snapshot=estate_snapshot_path, extra_argv=NOTES)
    mirror = in_process_hook(event, snapshot=estate_snapshot_path)
    report = report_of(document, snapshot=estate_snapshot_path)
    assert_abstain_bucket(outcome, mirror, report,
                          "detected", "nothing checkable could be extracted",
                          named=(str(document), "detected iam_policy content"))

    assert_no_verdictless_pass(outcome, report)
    assert_no_verdictless_pass(mirror, report)
    assert preflight.detect_kind(_NEVER_READ[case]) == "iam_policy", (
        "the premise: the gate DOES recognize this as an IAM allow policy, so "
        "the silence Gate 0 replaced was a recognized document producing no "
        "verdict at all")
    assert not preflight._legitimately_empty(_NEVER_READ[case], "iam_policy"), (
        "an absent `bindings` key must never be licensed as legitimately "
        "empty — that licence belongs to an explicit `bindings: []`")


# -- C08: THE UNKNOWN SENTINEL CONTRACT ---------------------------------------


def test_c08_uncaptured_category_is_unverified_never_ungrounded(
        tmp_path, snapshot_variant, estate_snapshot_path, in_process_hook):
    """A category the snapshot never captured can make NOTHING ungrounded.

    ``reasoner.existence_program`` guards the ungrounded rule with
    ``captured(<category>)``: absence from an enumeration only proves
    non-existence when the enumeration exists. Drop ``principals`` and the
    most obviously bogus member in the estate — ``user:attacker@evil.example``
    — must come back ``unverified``, not ``ungrounded``, because with no
    principal enumeration the gate has no evidence either way.

    Nothing exercises that guard end-to-end through the subprocess hook path
    today; this does. The contrast run at the bottom is the test: the SAME
    document against the full snapshot blocks, so the abstain above is the
    missing category talking, not a document the gate happens to like.
    """
    document = write_json(tmp_path / "attacker_binding.json", {
        "bindings": [{"role": "roles/bigquery.dataViewer", "members": [ATTACKER]}],
        "etag": "BwXtRfPolicy=",
        "version": 1,
    })
    blind = snapshot_variant(drop=["principals"])

    event = hook_event(document)
    outcome = run_hook(event, snapshot=blind, extra_argv=NOTES)
    mirror = in_process_hook(event, snapshot=blind)
    report = report_of(document, snapshot=blind)
    # The named tokens are the member the document grants to and the json-path
    # it sits at — both read out of THIS file, by the hook, on the exit-0 run.
    assert_abstain_bucket(outcome, mirror, report,
                          "snapshot did not capture principals",
                          named=(ATTACKER, "bindings[0].members[0]"))

    verdict = assert_recorded(report, status="unverified", kind="principal")
    assert verdict["target"] == ATTACKER, verdict
    assert "undecidable offline" in verdict["message"], verdict
    # Spelled out beside the helper because it is THE contract of this case.
    assert report["summary"]["ungrounded"] == 0, report["summary"]

    # The contrast: with principals captured, the same member blocks.
    seeing = run_hook(event, snapshot=estate_snapshot_path)
    assert_blocked(seeing, ATTACKER, "does not exist in the snapshot")


# -- C09: a snapshot old enough to be wrong, and nothing notices --------------


@pytest.fixture
def cel_policy(tmp_path):
    """A policy that grounds cleanly EXCEPT for one condition outside the
    supported CEL subset — so the report carries grounded lines and an
    unverified line at once, which is what C09's render assertion needs."""
    return write_json(tmp_path / "conditional_binding.json", {
        "bindings": [{
            "role": "roles/bigquery.dataViewer",
            "members": ["group:data-eng@acme.example"],
            "condition": {
                "title": "buckets only",
                "expression": 'resource.type == "storage.googleapis.com/Bucket"',
            },
        }],
        "etag": "BwXtRfPolicy=",
        "version": 3,
    })


def test_c09_stale_snapshot_is_stamped_but_never_gated(
        cel_policy, snapshot_variant, estate_snapshot_path, in_process_hook):
    """A 2019 snapshot silently blesses every name that has since been deleted.

    The stamp reaches the report (``captured_at``) and every grounded /
    unverified line of the human render carries it bracketed — so the
    information IS there. What is NOT there is any decision made from it: the
    verdicts under a seven-year-old snapshot are byte-identical to the
    verdicts under the current one. A max-age abstain is the design's own open
    question, and this is where it would land; until then this test pins the
    absence rather than pretending it is covered.
    """
    stale = snapshot_variant(captured_at=STALE_CAPTURED_AT)

    event = hook_event(cel_policy)
    outcome = run_hook(event, snapshot=stale, extra_argv=NOTES)
    mirror = in_process_hook(event, snapshot=stale)
    stale_report = report_of(cel_policy, snapshot=stale)
    # The condition's own operand and the json-path it sits at: the hook read
    # this document's CEL and said which part of it it could not decide.
    assert_abstain_bucket(outcome, mirror, stale_report, "was not decided",
                          named=("resource.type",
                                 "bindings[0].condition.expression"))

    assert stale_report["captured_at"] == STALE_CAPTURED_AT, \
        stale_report["captured_at"]
    assert f"[snapshot {STALE_CAPTURED_AT}]" in outcome.stderr, (
        f"the abstain note carries the stamp the decision is NOT made from\n"
        f"{outcome}")

    # Nothing gates on it: same document, same verdicts, seven years apart.
    fresh_report = report_of(cel_policy, snapshot=estate_snapshot_path)
    assert fresh_report["captured_at"] == env.ESTATE_CAPTURED_AT
    assert stale_report["verdicts"] == fresh_report["verdicts"], (
        "the stale snapshot changed a verdict — if a max-age rule has landed, "
        "this test is the one that has to be rewritten")
    assert stale_report["ok"] is True and fresh_report["ok"] is True
    messages = " ".join(v["message"] for v in stale_report["verdicts"]).casefold()
    for word in ("stale", "too old", "max-age", "expired"):
        assert word not in messages, (
            f"{word!r} appears in a verdict — a freshness rule exists after "
            f"all, and this test's premise is out of date\n{messages}")


def test_c09_stale_stamp_reaches_the_human_render(cel_policy, tmp_path,
                                                  snapshot_variant):
    """The bracketed ``[snapshot <captured_at>]`` suffix, in the rendered
    report the agent actually sees.

    The renderer only reaches stderr on a FAILED report (``cli.py:187-189``),
    so this run adds one hallucinated role to the C09 policy to force the
    render. The stamp lands on grounded and unverified lines and deliberately
    NOT on ungrounded ones — those already carry the capture time inside the
    reasoner's own message (``reasoner.py:164``), and double-stamping would
    read as two different facts.

    ``--max-age off`` is the explicit opt-out the run needs to JUDGE against a
    2019 snapshot at all: the default freshness ceiling now demotes a stale
    snapshot's categories on the snapshot-only hook path too, so without the
    opt-out this run abstains instead of blocking — which is its own, separate
    contract. This test is about the render's stamp, not the ceiling.
    """
    document = json.loads(cel_policy.read_text(encoding="utf-8"))
    document["bindings"].append(
        {"role": "roles/bigquery.reader", "members": ["user:alice@acme.example"]})
    rendered_source = write_json(tmp_path / "stale_render.json", document)
    stale = snapshot_variant(captured_at=STALE_CAPTURED_AT)

    outcome = run_hook(hook_event(rendered_source), snapshot=stale,
                       extra_argv=("--max-age", "off"))
    assert_blocked(outcome, "roles/bigquery.reader")

    stamp = f"[snapshot {STALE_CAPTURED_AT}]"
    lines = outcome.stderr.splitlines()
    grounded = [line for line in lines if "exists in the snapshot" in line]
    unverified = [line for line in lines if "was not decided" in line]
    ungrounded = [line for line in lines if "does not exist in the snapshot" in line]
    assert grounded and unverified and ungrounded, str(outcome)
    for line in grounded + unverified:
        assert stamp in line, f"unstamped: {line!r}\n{outcome}"
    for line in ungrounded:
        assert stamp not in line, f"double-stamped: {line!r}\n{outcome}"


def test_c09_explain_is_the_one_visible_channel_on_an_abstain(
        cel_policy, snapshot_variant, in_process_hook):
    """``--explain`` prints before the ``report.ok`` check, so it is observable
    on an exit-0 run — the channel that was this module's ONLY in-hook evidence
    before the repin, kept because it proves a different half: the abstain notes
    say what the gate could not judge, ``--explain`` says what it fed the
    solver, and the two arrive on the same exit-0 run without truncating each
    other."""
    stale = snapshot_variant(captured_at=STALE_CAPTURED_AT)
    event = hook_event(cel_policy)
    outcome = run_hook_explain(event, snapshot=stale, extra_argv=NOTES)

    assert outcome.exit_code == 0, str(outcome)
    assert outcome.stdout == "", str(outcome)
    assert "z3 constraints generated this run" in outcome.stderr, str(outcome)
    # The abstain channel survives beside the explain block, and still names
    # this document's own condition.
    assert_named_by_the_hook(outcome, "resource.type", "was not decided")
    if env.HAVE_Z3:
        # Without z3 the explain block short-circuits to "z3 is not available"
        # before it ever looks at the expression, so the per-claim line only
        # exists on the z3 backend.
        assert "CEL outside the supported subset" in outcome.stderr, str(outcome)
        assert "resource.type" in outcome.stderr, str(outcome)


# -- C10: a baseline the comparison is not defined over -----------------------


@pytest.fixture
def clean_policy(tmp_path):
    """A policy every claim of which grounds — so the ONLY unverified in C10
    is the subset verdict, and the bucket assertion is about the baseline."""
    return write_json(tmp_path / "new_policy.json", {
        "bindings": [{"role": "roles/bigquery.dataViewer",
                      "members": ["user:alice@acme.example"]}],
        "etag": "BwXtRfPolicy=",
        "version": 1,
    })


@pytest.mark.parametrize("baseline_case", [
    "org_policy_document", "nonexistent_path", "deny_shaped_document"])
def test_c10_bad_baseline_abstains_on_the_subset(
        baseline_case, clean_policy, tmp_path, estate_snapshot_path,
        in_process_hook):
    """``--baseline`` pointed at something that is not an IAM allow policy.

    All three land on the same not-decided message, and the reason they must
    is in ``preflight._subset_verdict``: a document without a ``bindings``
    array reads as "grants nothing", so comparing against it would report
    every new grant as a widening — a report full of confident, fabricated
    ``contradicted`` verdicts. Refusing to decide is the only honest answer.

    The named token here is the BASELINE's own path, because the subset
    abstention is about the baseline and the proposal itself ground cleanly:
    it is the leg that proves the hook received the flag, opened what it
    pointed at, and refused THAT pairing.
    """
    if baseline_case == "org_policy_document":
        baseline = write_json(tmp_path / "baseline_org_policy.json", {
            "constraint": "constraints/compute.vmExternalIpAccess",
            "booleanPolicy": {"enforced": True},
        })
    elif baseline_case == "nonexistent_path":
        baseline = tmp_path / "baseline_that_was_never_written.json"
        assert not baseline.exists()
    else:
        # A deny policy: `rules` + `denyRule`, no `bindings` anywhere.
        baseline = write_json(tmp_path / "baseline_deny_policy.json", {
            "name": "policies/deny-sa-key-creation",
            "rules": [{"denyRule": {
                "deniedPrincipals": ["principalSet://goog/public:all"],
                "deniedPermissions": ["iam.serviceAccountKeys.create"],
            }}],
            "etag": "BwYYDenyPolicy=",
        })

    event = hook_event(clean_policy)
    flag = ("--baseline", str(baseline))
    outcome = run_hook(event, snapshot=estate_snapshot_path,
                       extra_argv=NOTES + flag)
    # The hook child really was handed the baseline — without this the exit-0
    # assertion below would hold just as well for a flag that never arrived.
    assert outcome.argv[-2:] == flag, str(outcome)
    mirror = in_process_hook(event, snapshot=estate_snapshot_path,
                             extra_argv=flag)
    report = report_of(clean_policy, snapshot=estate_snapshot_path,
                       baseline=baseline)
    assert_abstain_bucket(outcome, mirror, report, "new⊆old was not decided",
                          named=(str(baseline),))

    subset = assert_recorded(report, status="unverified", kind="subset")
    assert subset["target"] == "iam-policy", subset


# -- C11: the misconfiguration that checks nothing, forever -------------------


def test_c11_unreadable_snapshot_fails_open_loudly_enough(
        tmp_path, estate_snapshot_path, in_process_hook):
    """A ``--snapshot`` path that does not exist: exit 0, "fail-open" on stderr.

    Fail-open is right — a broken gate must never block an edit — but this is
    the misconfiguration that makes the gate check NOTHING for as long as
    nobody rereads the stderr, while every run looks healthy from the exit
    code.

    WHAT THIS CASE IS ABOUT WAS CORRECTED IN THE REPIN. It used to hold the
    four-bucket legs against a sidecar report made under the WORKING snapshot,
    whose sole abstention is that the document is not valid JSON — a different
    world from the one being demonstrated, in which the CLI returns before
    grounding at all and the real outcome is exit 0 with ZERO verdicts, exactly
    the verdictless pass this module exists to exclude. Every run below is now
    asserted through :func:`assert_fail_open_bucket`, that property stated
    directly, which also closes the two bare exit codes this case used to carry.

    The last two spawns are the demonstration and its control: a policy with a
    hallucinated role and an unknown member sails through under the broken
    snapshot, and BLOCKS under a working one. Without the second, the
    demonstration would pass while demonstrating nothing.
    """
    missing = tmp_path / "snapshot_that_is_not_there.json"
    assert not missing.exists()
    undecidable = tmp_path / "main.tf"
    undecidable.write_text('resource "google_project_iam_binding" "x" {}\n',
                           encoding="utf-8")

    event = hook_event(undecidable)
    outcome = run_hook(event, snapshot=missing, extra_argv=NOTES)
    assert_fail_open_bucket(outcome, "fail-open", "nothing was checked")
    mirror = in_process_hook(event, snapshot=missing)
    assert_fail_open_bucket(mirror, "fail-open", "nothing was checked")

    hallucinated = write_json(tmp_path / "hallucinated.json", {
        "bindings": [{"role": "roles/bigquery.reader", "members": [ATTACKER]}],
        "etag": "BwXtRfPolicy=",
        "version": 1,
    })
    blind = run_hook(hook_event(hallucinated), snapshot=missing,
                     extra_argv=NOTES)
    assert_fail_open_bucket(blind, "fail-open", "nothing was checked")
    assert "roles/bigquery.reader" not in blind.stderr, (
        f"a policy with a hallucinated role AND an unknown member passed — "
        f"because the snapshot never loaded, not because it is clean\n{blind}")
    assert ATTACKER not in blind.stderr, str(blind)

    # THE POSITIVE CONTROL: the same bytes, a snapshot that loads, a block.
    seeing = run_hook(hook_event(hallucinated), snapshot=estate_snapshot_path)
    assert_blocked(seeing, "roles/bigquery.reader")


# -- THE RENDER: an abstain-only pass says NOTHING VERIFIED -------------------


def _abstain_only_render(document, snapshot) -> tuple[str, dict]:
    """(the human render's header line, the four-bucket counts) for a document
    nothing was checked in.

    The source path is replaced by a placeholder before the header is returned:
    it is the one part of the line the caller chose, and a ``tmp_path`` carrying
    the test's own name would otherwise answer a word-search about the RENDER
    with a word the test itself put there.
    """
    report = preflight.ground_policy(str(document), snapshot)
    rendered = PolicyReport(report, captured_at=snapshot.captured_at,
                            source=str(document)).render("human")
    header = rendered.splitlines()[0].replace(str(document), "<source>")
    return header, report.counts()


def test_an_abstain_only_report_is_headlined_nothing_verified(
        tmp_path, estate_snapshot):
    """THE QUALIFIER, landed, and this pins the wording — the INVERSE of the
    pin that used to sit here.

    Until ``ESC-GX-ABSTAIN-PASSED-HEADER`` was retired, this test (then named
    ``test_an_abstain_only_report_is_headlined_passed``) pinned the DEFECT: a
    document nothing was checked in was headlined with the same bare ``PASSED``
    a fully grounded one gets, and every qualifier spelling was refused so the
    day one landed it said so. That day came: ``PolicyReport._render_human``
    now qualifies an ok headline by what was actually checked, so an
    abstain-only report reads ``PASSED — NOTHING VERIFIED (<N> unchecked)``
    and only a fully decided report gets the bare word.

    This test now REFUSES the unqualified form: ``PASSED [`` — the exact
    header shape a fully grounded report renders, word then backend — must not
    appear, and the counts stay on the line exactly as before.
    """
    document = write_json(tmp_path / "configmap.json", _CONFIGMAP)
    header, counts = _abstain_only_render(document, estate_snapshot)

    assert counts == {"grounded": 0, "ungrounded": 0, "contradicted": 0,
                      "unverified": 1}, counts
    assert "PASSED — NOTHING VERIFIED (1 unchecked)" in header, header
    assert "unverified=1" in header, header
    assert "grounded=0" in header, header
    assert "PASSED [" not in header, (
        f"the bare unqualified headline is back — an abstain-only report is "
        f"rendering exactly like a fully grounded one, which is the approval-"
        f"from-ignorance defect ESC-GX-ABSTAIN-PASSED-HEADER was retired by "
        f"fixing\n{header}")
    assert "FAILED" not in header, header


def test_the_headline_of_a_report_that_checked_nothing_carries_a_qualifier(
        tmp_path, estate_snapshot):
    """THE SPEC LITERAL, now LIVE: a document nothing was checked in must not
    be headlined with the bare word a fully grounded one gets.

    This assertion was landed strict-xfailed under
    ``ESC-GX-ABSTAIN-PASSED-HEADER`` while the qualifier was a product change
    no test task could make; the qualifier landed (``NOTHING VERIFIED``, in
    ``PolicyReport._render_human``) and the xfail was deleted with the
    escalation's retirement — see the RETIRED comment in
    ``tests/escalations.py``. The word list stays a LIST: the property is that
    SOME qualifying word interrupts the header, and the exact spelling is
    pinned by the positive test above."""
    document = write_json(tmp_path / "configmap.json", _CONFIGMAP)
    header, _ = _abstain_only_render(document, estate_snapshot)

    assert any(word in header.upper()
               for word in ("NOT DECIDED", "ABSTAIN", "ABSTENTION",
                            "INCONCLUSIVE", "NOTHING VERIFIED",
                            "PASSED (")), header


# -- THE MUTATION CONTRACT: both removals, and the one the ceiling refuses ----


def _removal(removal_id):
    from tests.mutation_entries import REMOVALS

    return next(r for r in REMOVALS if r.id == removal_id)


def test_both_hook_removals_name_cases_this_module_owns():
    """The two removals this task owns are registered, name this family, and
    witness themselves against cases HERE.

    ``RM-HOOK-SUCCESS-BEFORE-THE-EVENT`` is the hook stub that returns success
    as its first statement; ``RM-HOOK-WRONG-FILE`` is the hook that ignores the
    event's path and grounds a hardcoded one. Both are the mutants whose 10-of-14
    and 11-of-14 survival rates this repin exists to close.
    """
    for removal_id in ("RM-HOOK-SUCCESS-BEFORE-THE-EVENT", "RM-HOOK-WRONG-FILE"):
        removal = _removal(removal_id)
        assert removal.family == "abstain", removal
        assert removal.owner == "gx-agentic-abstain-repin", removal
        assert removal.must_fail, removal
        assert all(node.startswith("tests/test_gcp_agentic_abstain.py::")
                   for node in removal.must_fail), removal


def test_the_wrong_file_removal_is_live_in_the_contract():
    """The new removal is EXECUTED by the frozen gate, not parked."""
    assert not _removal("RM-HOOK-WRONG-FILE").pending


@pytest.mark.xfail(strict=True, reason=(
    "ESC-GX-ABSTAIN-REMOVAL-CEILING: the removal DOES redden its named cases, "
    "measured, and contract_spawn_ceiling() still refuses the pending→live "
    "flip — a new live removal is net zero, flipping an already-counted one is "
    "+1 spawn and +0 slots"))
def test_the_hook_success_removal_is_live_in_the_contract():
    """THE SPEC LITERAL for the removal the ceiling will not let this task
    flip. Landed strict-xfailed so the day ``CONTRACT_CONTROL_SPAWNS`` is
    rescaled to the controls it really has, this XPASSes and says so."""
    assert not _removal("RM-HOOK-SUCCESS-BEFORE-THE-EVENT").pending
