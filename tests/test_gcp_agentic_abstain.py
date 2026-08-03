"""The ABSTAIN BUCKET: undecidable inputs stay ``unverified`` and stay visible.

Every case in this module hands the real ``gcp-ground verify-policy --hook``
process something it genuinely cannot judge — a raw HCL file, non-UTF-8 bytes,
a document shape no extractor recognizes, a snapshot category that was never
captured, a baseline that is not an IAM allow policy — and asserts the same
five-legged outcome: **exit 0, byte-empty stdout, and the ignorance on the
record as at least one ``unverified``, with nothing manufactured into
``ungrounded`` or ``contradicted``.** :func:`assert_abstain_bucket` is that
assertion, in one place, so a case added later cannot quietly forget a leg.

Two failure modes are being held apart here, and only one of them is loud.
A missed *block* at least leaves the bad name in the diff. A missed *abstain*
tells the reviewer the gate looked and was happy — the gate's silence is
indistinguishable from a clean pass. So "exit 0" alone is never the assertion;
exit 0 *plus* a named reason is.

VISIBILITY, honestly stated. An abstaining hook run is silent by design —
``cli._run_hook`` returns ``EXIT_OK`` the moment ``report.ok`` is true and
prints nothing — so for most of these cases the ONLY channel that carries the
reason today is the :func:`~tests.agentic.hookrunner.ground_json` sidecar,
which re-runs the same document through the same
:func:`~gcp_grounding.preflight.ground_policy` in normal mode and reads the
machine report. Until ``sx-hook-abstain-notes`` teaches the hook to say "I
could not judge this", a developer watching only the hook sees nothing. The
one exception is the CEL-bearing case (C09): ``cli.py:183-184`` prints the
``--explain`` lines BEFORE the ``report.ok`` check, so
:func:`~tests.agentic.hookrunner.run_hook_explain` is genuinely observable on
an exit-0 run, and C09 asserts on it.

Degenerate inputs are written into ``tmp_path`` inline rather than committed
as fixtures, following the suite's existing convention: a file whose only
purpose is to be unparsable has no business in a fixtures directory where the
next reader has to guess whether it is broken on purpose.

Imports are by FULL dotted path (``tests.agentic.…``) because ``tests/`` is a
regular Python package — see ``tests/__init__.py``, which must not be removed.
"""

from __future__ import annotations

import json

import pytest

from gcp_grounding import cli
from tests.agentic import env
from tests.agentic.asserts import assert_abstained, assert_blocked, assert_recorded
from tests.agentic.hookrunner import (
    bound_subprocess_budget,  # noqa: F401 — autouse: bind spawns to the budget
    ground_json,
    run_hook,
    run_hook_explain,
)

#: C09's deliberately ancient capture stamp. Old enough that nobody would
#: defend trusting it, and the gate trusts it anyway — that is the finding.
STALE_CAPTURED_AT = "2019-01-01T00:00:00Z"

#: A member the estate snapshot has never heard of, used by C08 and C01.
ATTACKER = "user:attacker@evil.example"


def hook_event(path) -> dict:
    """A Claude-Code PostToolUse event naming *path* as the edited file."""
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


# -- THE CROSS-CUTTING ASSERTION ----------------------------------------------


def assert_abstain_bucket(outcome, report, *substrings) -> None:
    """Every leg of the abstain bucket, for one case, in one call.

    The five legs are spelled out here rather than only delegated, on purpose:
    they are this module's contract, and naming them locally means a change to
    the shared :func:`~tests.agentic.asserts.assert_abstained` cannot silently
    drop one from every C-case at once. The delegation still happens — the
    shared helper owns ``report.ok`` and the "an abstain must name its reason"
    substring check, and its assertion messages are the ones a red run reads.
    """
    assert outcome.exit_code == 0, (
        f"an undecidable input must not fail the gate — ignorance is exit 0, "
        f"not a block; got {outcome.exit_code}\n{outcome}")
    assert outcome.stdout == "", (
        f"an abstaining hook run must leave stdout byte-empty\n{outcome}")
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


# -- C01: a raw HCL file is not `terraform show -json` ------------------------


def test_c01_raw_hcl_abstains_and_never_blocks(tmp_path, estate_snapshot_path):
    """An edited ``main.tf`` is HCL, not plan JSON: the JSONDecodeError is an
    abstain, and the hallucinated role inside it gets SILENCE.

    ``.tf`` is in :data:`gcp_grounding.cli._HOOK_SUFFIXES`, so the hook does
    pick this file up and does run the gate over it — it just cannot parse it.
    Anyone wiring the hook expecting it to catch a hallucinated role in an
    edited ``main.tf`` gets exactly nothing back; only committed
    ``terraform show -json`` output is actually gated. That gap is the reason
    this case exists.
    """
    document = tmp_path / "main.tf"
    document.write_text(
        'resource "google_project_iam_binding" "hallucinated" {\n'
        '  project = "acme-prod"\n'
        '  role    = "roles/bigquery.reader"\n'
        f'  members = ["{ATTACKER}"]\n'
        "}\n",
        encoding="utf-8")

    outcome = run_hook(hook_event(document), snapshot=estate_snapshot_path)
    report = ground_json(document, snapshot=estate_snapshot_path)
    assert_abstain_bucket(outcome, report, "not valid JSON", "nothing was checked")

    assert ".tf" in cli._HOOK_SUFFIXES, (
        "the premise of this case: the hook DOES select .tf files, so the "
        "silence below is the parser's, not the suffix filter's")
    assert outcome.exit_code != cli.EXIT_BLOCK, str(outcome)
    # The teeth: a fabricated role and a fabricated member sat in the edited
    # file and the hook said nothing about either.
    assert "roles/bigquery.reader" not in outcome.stderr, str(outcome)
    assert ATTACKER not in outcome.stderr, str(outcome)


# -- C02: bytes that are not text ---------------------------------------------


def test_c02_garbled_bytes_abstain(tmp_path, estate_snapshot_path):
    """Non-UTF-8 bytes raise UnicodeDecodeError — a ValueError that is NOT a
    JSONDecodeError, which is why ``_load_document`` needs its own arm."""
    document = tmp_path / "garbled.json"
    document.write_bytes(b'{"bindings": [{"role": "roles/\xff\xfe\x00viewer"}]}')

    outcome = run_hook(hook_event(document), snapshot=estate_snapshot_path)
    report = ground_json(document, snapshot=estate_snapshot_path)
    assert_abstain_bucket(outcome, report, "could not be parsed", "nothing was checked")


# -- C03: nesting deep enough to blow the parser's stack ----------------------


def test_c03_deep_nesting_abstains_without_a_traceback(tmp_path, estate_snapshot_path):
    """200000 nested brackets: deep enough to trip RecursionError in the JSON
    scanner, shallow enough that the child stays fast.

    The failure mode being excluded is a traceback escaping ``ground_policy``:
    a crash in the hook is an exit code Claude Code reads as *something*, and
    a gate that dies on a pathological file is a gate someone disables.
    """
    document = tmp_path / "deeply_nested.json"
    document.write_text("[" * 200000 + "]" * 200000, encoding="utf-8")

    outcome = run_hook(hook_event(document), snapshot=estate_snapshot_path)
    report = ground_json(document, snapshot=estate_snapshot_path)
    assert_abstain_bucket(outcome, report, "nothing was checked")

    messages = " ".join(v["message"] for v in report["verdicts"])
    assert "RecursionError" in messages or "could not be parsed" in messages, (
        f"the abstain must name the parse failure, not just record one\n"
        f"{messages}")
    assert "Traceback" not in outcome.stderr, str(outcome)


# -- C04: a document from some other world ------------------------------------


def test_c04_unrecognized_kind_abstains_naming_the_keys(tmp_path, estate_snapshot_path):
    """A Kubernetes ConfigMap parses perfectly and means nothing here.

    The abstain names the top-level keys it saw, which is what lets a reader
    tell "the gate does not know this shape" from "the gate found nothing
    wrong".
    """
    document = write_json(tmp_path / "configmap.json", {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "app-config", "namespace": "default"},
        "data": {"LOG_LEVEL": "debug"},
    })

    outcome = run_hook(hook_event(document), snapshot=estate_snapshot_path)
    report = ground_json(document, snapshot=estate_snapshot_path)
    assert_abstain_bucket(outcome, report,
                          "document kind was not recognized", "top-level keys")


# -- C05: recognized, and still nothing to check ------------------------------


_UNEXTRACTABLE = {
    # `bindings` as an object: detect_kind says iam_policy (the key is there),
    # iam_policy_claims refuses to guess at a non-array (claims.py:108) and
    # returns nothing.
    "bindings_as_object": {
        "bindings": {"role": "roles/bigquery.dataViewer",
                     "members": ["user:alice@acme.example"]},
        "etag": "BwXtRfPolicy=",
        "version": 3,
    },
    # v1 `constraint` and v2 `name` at once: _org_policy_constraint calls that
    # ambiguous (claims.py:180) and emits nothing, including no value claim.
    "hybrid_v1_plus_v2_org_policy": {
        "constraint": "constraints/compute.vmExternalIpAccess",
        "name": "projects/acme-prod/policies/compute.vmExternalIpAccess",
        "spec": {"rules": [{"enforce": True}]},
    },
}


@pytest.mark.parametrize("case", sorted(_UNEXTRACTABLE), ids=sorted(_UNEXTRACTABLE))
def test_c05_recognized_but_unextractable_abstains(case, tmp_path, estate_snapshot_path):
    """The zero-claims honesty guard (``preflight.py:112``).

    Both documents are RECOGNIZED — a kind is detected — and both carry
    content the conservative extractors decline to interpret. Without the
    guard, zero claims means zero verdicts, and zero verdicts renders exactly
    like a clean pass. This is the case that turns "I skipped all of it" into
    a verdict.
    """
    document = write_json(tmp_path / f"{case}.json", _UNEXTRACTABLE[case])

    outcome = run_hook(hook_event(document), snapshot=estate_snapshot_path)
    report = ground_json(document, snapshot=estate_snapshot_path)
    assert_abstain_bucket(outcome, report,
                          "detected", "nothing checkable could be extracted")


# -- C08: THE UNKNOWN SENTINEL CONTRACT ---------------------------------------


def test_c08_uncaptured_category_is_unverified_never_ungrounded(
        tmp_path, snapshot_variant, estate_snapshot_path):
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

    outcome = run_hook(hook_event(document), snapshot=blind)
    report = ground_json(document, snapshot=blind)
    assert_abstain_bucket(outcome, report, "snapshot did not capture principals")

    verdict = assert_recorded(report, status="unverified", kind="principal")
    assert verdict["target"] == ATTACKER, verdict
    assert "undecidable offline" in verdict["message"], verdict
    # Spelled out beside the helper because it is THE contract of this case.
    assert report["summary"]["ungrounded"] == 0, report["summary"]

    # The contrast: with principals captured, the same member blocks.
    seeing = run_hook(hook_event(document), snapshot=estate_snapshot_path)
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
        cel_policy, snapshot_variant, estate_snapshot_path):
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

    outcome = run_hook(hook_event(cel_policy), snapshot=stale)
    stale_report = ground_json(cel_policy, snapshot=stale)
    assert_abstain_bucket(outcome, stale_report, "was not decided")

    assert stale_report["captured_at"] == STALE_CAPTURED_AT, stale_report["captured_at"]

    # Nothing gates on it: same document, same verdicts, seven years apart.
    fresh_report = ground_json(cel_policy, snapshot=estate_snapshot_path)
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


def test_c09_stale_stamp_reaches_the_human_render(cel_policy, tmp_path, snapshot_variant):
    """The bracketed ``[snapshot <captured_at>]`` suffix, in the rendered
    report the agent actually sees.

    The renderer only reaches stderr on a FAILED report (``cli.py:187-189``),
    so this run adds one hallucinated role to the C09 policy to force the
    render. The stamp lands on grounded and unverified lines and deliberately
    NOT on ungrounded ones — those already carry the capture time inside the
    reasoner's own message (``reasoner.py:164``), and double-stamping would
    read as two different facts.
    """
    document = json.loads(cel_policy.read_text(encoding="utf-8"))
    document["bindings"].append(
        {"role": "roles/bigquery.reader", "members": ["user:alice@acme.example"]})
    rendered_source = write_json(tmp_path / "stale_render.json", document)
    stale = snapshot_variant(captured_at=STALE_CAPTURED_AT)

    outcome = run_hook(hook_event(rendered_source), snapshot=stale)
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
        cel_policy, snapshot_variant):
    """``--explain`` prints before the ``report.ok`` check, so it is observable
    on an exit-0 run — the only such channel this suite has today."""
    stale = snapshot_variant(captured_at=STALE_CAPTURED_AT)
    outcome = run_hook_explain(hook_event(cel_policy), snapshot=stale)

    assert outcome.exit_code == 0, str(outcome)
    assert outcome.stdout == "", str(outcome)
    assert "z3 constraints generated this run" in outcome.stderr, str(outcome)
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
        baseline_case, clean_policy, tmp_path, estate_snapshot_path):
    """``--baseline`` pointed at something that is not an IAM allow policy.

    All three land on the same not-decided message, and the reason they must
    is in ``preflight._subset_verdict``: a document without a ``bindings``
    array reads as "grants nothing", so comparing against it would report
    every new grant as a widening — a report full of confident, fabricated
    ``contradicted`` verdicts. Refusing to decide is the only honest answer.
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

    outcome = run_hook(hook_event(clean_policy), snapshot=estate_snapshot_path,
                       extra_argv=("--baseline", str(baseline)))
    # The hook child really was handed the baseline — without this the exit-0
    # assertion below would hold just as well for a flag that never arrived.
    assert outcome.argv[-2:] == ("--baseline", str(baseline)), str(outcome)
    report = ground_json(clean_policy, snapshot=estate_snapshot_path,
                         baseline=baseline)
    assert_abstain_bucket(outcome, report, "new⊆old was not decided")

    subset = assert_recorded(report, status="unverified", kind="subset")
    assert subset["target"] == "iam-policy", subset


# -- C11: the misconfiguration that checks nothing, forever -------------------


def test_c11_unreadable_snapshot_fails_open_loudly_enough(
        tmp_path, estate_snapshot_path):
    """A ``--snapshot`` path that does not exist: exit 0, "fail-open" on stderr.

    Fail-open is right — a broken gate must never block an edit — but this is
    the misconfiguration that makes the gate check NOTHING for as long as
    nobody rereads the stderr, while every run looks healthy from the exit
    code. The second spawn is the demonstration: a policy that blocks under a
    real snapshot sails through under this one.
    """
    missing = tmp_path / "snapshot_that_is_not_there.json"
    assert not missing.exists()
    undecidable = tmp_path / "main.tf"
    undecidable.write_text('resource "google_project_iam_binding" "x" {}\n',
                           encoding="utf-8")

    outcome = run_hook(hook_event(undecidable), snapshot=missing)
    assert "fail-open" in outcome.stderr, str(outcome)
    assert "nothing was checked" in outcome.stderr, str(outcome)
    # The bucket legs are asserted about the DOCUMENT, through a sidecar run
    # against a snapshot that loads — the broken snapshot produces a usage
    # error (exit 2), not a report, so there is no report to assert on.
    report = ground_json(undecidable, snapshot=estate_snapshot_path)
    assert_abstain_bucket(outcome, report, "nothing was checked")

    hallucinated = write_json(tmp_path / "hallucinated.json", {
        "bindings": [{"role": "roles/bigquery.reader", "members": [ATTACKER]}],
        "etag": "BwXtRfPolicy=",
        "version": 1,
    })
    blind = run_hook(hook_event(hallucinated), snapshot=missing)
    assert blind.exit_code == 0, (
        f"a policy with a hallucinated role AND an unknown member passed — "
        f"because the snapshot never loaded, not because it is clean\n{blind}")
    assert "roles/bigquery.reader" not in blind.stderr, str(blind)
