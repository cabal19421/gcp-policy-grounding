"""Benign terraform edits pass BYTE-QUIET, and the undecidable ones abstain
DISTINGUISHABLY.

The adversarial modules prove the gate can block. This one proves the two
things a blocking module structurally cannot: that a SAFE change costs the
agent nothing, and that an UNDECIDABLE one is never dressed up as a safe one.
Both halves matter for the same reason — a guardrail that fires on a narrowing
edit gets switched off, and a guardrail that passes in silence when it did not
look is worse than no guardrail at all, because the silence reads as approval.

HALF ONE, THE FALSE-POSITIVE BUDGET, lands through
:func:`tests.agentic.asserts.assert_passed`: exit 0 with BOTH streams
byte-empty. Not "no findings" — byte-empty, because the hook's stderr is
agent-visible and every line on it is a line in the agent's context.

HALF TWO, THE HONEST ABSTENTIONS, land through
:func:`tests.agentic.asserts.assert_abstained`: exit 0, stdout byte-empty, the
report still ``ok``, at least one ``unverified``, and NO ``ungrounded`` or
``contradicted`` manufactured out of the same ignorance — plus the substrings
that name WHY. An abstain that does not say why is a silent pass wearing a
verdict.

THE THIRD INPUT gets its only end-to-end run here: one compiled
``sec_requirements`` promise, judged against a terraform-derived current state
through the real hook. Everything else that touches promises in this repository
is unit-level with documents built in code.

WHAT THIS CHECKOUT CAN AND CANNOT DECIDE, stated once so no branch below reads
as a hedge. THERE IS ONE TERRAFORM ENTRY POINT and both routes reach it: a
``.tf`` / ``.tf.json`` edit is assembled into a synthetic plan by
``gcp_grounding.tfsource.plan.as_plan_document`` and prepared exactly once by
``engine.prepare_proposal``, and ``cli._ground`` makes that same call rather than
preparing the raw ``{"resource": ...}`` body — which ``preflight.detect_kind``
does not recognize, so the retired second route extracted no claim, named no
per-resource counterpart, and left a registered pair check demanding a decision
it never made. Consequences the cases below rely on: a ``.tf.json`` edit yields
CLAIMS (so a widening edit is a finding in its own right, and an interpolation
inside it IS reported as an unresolved attribute path), and the baseline rows are
DIFF-SCOPED — a configuration file declares every resource of its module, and the
rows are the ones the edit CHANGES relative to their current counterpart, plus
whatever row the operator DECLARED the file is a proposal for. A resource the
edit does not touch is byte-quiet. A terraform PLAN document is already a diff
and is never re-scoped, which is why the after-unknown case still exercises the
proposal-side unknown handling end to end. Every place a capability question
bites, the test BRANCHES and asserts the honest answer for the world it is
actually in — the discipline :mod:`tests.agentic.env` and
:mod:`tests.agentic.tfrepo` use throughout. It never skips.

SUBPROCESSES: thirteen, every one through :mod:`tests.agentic.hookrunner`, which
counts them against the suite-wide ceiling — four passing cases, seven
abstentions and the promise arm's two blocks. Every message assertion that does not
need the process boundary goes through :func:`ground`, the in-process helper,
which runs the SAME ``cli.main`` entry point on the SAME code path (``--hook``
and normal mode share ``cli._ground``) and reads the machine document instead of
a stream the hook deliberately leaves empty.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
from datetime import datetime, timedelta

import pytest

from gcp_grounding import cli, registry
from tests.agentic import env, hookrunner, tfrepo
from tests.agentic.asserts import (assert_abstained, assert_blocked,
                                   assert_no_verdictless_pass, assert_passed,
                                   assert_recorded)
from tests.agentic.fake_agent import FakeAgent
from tests.agentic.hookrunner import bound_subprocess_budget  # noqa: F401

#: This module's committed payloads. The one-line edits are derived from the
#: base corpus through :func:`tests.agentic.tfrepo.variant`, so the INPUT side
#: stays a reviewable document plus a named difference; what lives here is the
#: two documents that are not a mutation of anything — a terraform plan and a
#: requirement a human wrote.
BENIGN = env.AGENTIC / "tf" / "benign"
PLAN_FIXTURE = BENIGN / "after_unknown_plan.json"
PROMISE_FIXTURE = BENIGN / "no_open_ssh.md"

#: The row the base config's ``targets`` entry names, and the config-only row
#: the corpus carries precisely so a proposal can have no predecessor.
FIREWALL = "projects/acme-prod/global/firewalls/allow-internal-ssh"
NEW_FIREWALL = "projects/acme-prod/global/firewalls/deny-external-rdp"

#: :data:`gcp_grounding.engine.UNRESOLVED_KIND`, and the address-prefixed path
#: the committed plan's ``after_unknown`` mirror marks.
UNRESOLVED_KIND = "proposal:unresolved"
UNKNOWN_PATH = "google_compute_firewall.allow_ssh.allow[0].ports"

#: The interpolation the unresolved-variable case writes. It must appear NOWHERE
#: in the report: emitting it as a claim value would produce a confident finding
#: about a value terraform never intended.
INTERPOLATION = "${var.office_cidr}"

#: The compiled promise's id and the estate collection it quantifies over.
PROMISE_ID = "no-open-ssh-ingress"
PROMISE_COLLECTION = "firewall_rules"

#: Where the compiled artifacts land inside a built repo, relative to its root —
#: the value written into the config's ``requirements`` key, which
#: ``gcp_grounding.discovery`` resolves against the config's own directory.
REQUIREMENTS_DIR = "sec_requirements"
COMPILED_DIR = f"{REQUIREMENTS_DIR}/compiled"

_CAPTURED = datetime.fromisoformat(env.ESTATE_CAPTURED_AT.replace("Z", "+00:00"))


def _clock(**delta) -> str:
    """An ISO-8601 instant *delta* past the estate snapshot's capture time."""
    return (_CAPTURED + timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


#: Two days past the capture time, against a one-day ceiling: the CONFIGURED
#: staleness arm.
STALE_ASOF = _clock(days=2)

#: Eight days past it, with NO ceiling flag at all: the DEFAULT-ceiling arm, and
#: the one that matters for a hook nobody configured. ``freshness.MAX_AGE_DEFAULT``
#: is seven days.
DEFAULT_CEILING_NOW = _clock(days=8)


# -- the two harness helpers ---------------------------------------------------


def state_free_argv(repo, extra=()) -> tuple[str, ...]:
    """:func:`tests.agentic.tfrepo.hook_argv` MINUS the terraform-state flag.

    The three cases that withhold the state source cannot use the shared argv,
    because the shared argv's whole point is that it CARRIES one. This is the
    same shape with exactly that pair removed, and
    :func:`test_the_state_free_argv_is_the_shared_shape_minus_the_state_flag`
    pins the relationship so the two cannot drift apart.
    """
    return ("--config", str(repo.config_path),
            "--as-of", tfrepo.ASOF) + tuple(str(part) for part in extra)


@contextlib.contextmanager
def _child_like_environ(overrides=None):
    """``os.environ`` scrubbed exactly as :func:`tests.agentic.hookrunner.child_env`
    scrubs a spawned child's, so the in-process helper and the real hook cannot
    answer differently because of a developer's exported shell state."""
    saved = dict(os.environ)
    try:
        for name in hookrunner.SCRUBBED_ENV:
            os.environ.pop(name, None)
        os.environ["GCP_SEC_LLM"] = "0"
        os.environ.update({str(k): str(v) for k, v in (overrides or {}).items()})
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


def ground(path, *, snapshot, extra_argv=(), env_overrides=None) -> dict:
    """THE IN-PROCESS GROUNDING HELPER: the same gate, in NORMAL mode,
    ``--format json``.

    ``cli._run_hook`` and ``cli._cmd_verify_policy`` share ``cli._ground``, so
    this reads the verdicts the hook run produced without spending a second
    spawn on them — which is what keeps this module inside its subprocess
    budget while still asserting on messages a byte-quiet hook has nowhere to
    print.
    """
    argv = ["verify-policy", str(path), "--snapshot", str(snapshot),
            "--format", "json", *[str(part) for part in extra_argv]]
    out, err = io.StringIO(), io.StringIO()
    with _child_like_environ(env_overrides):
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(argv)
    assert code in (0, 1), (
        f"ground() expected exit 0 or 1 (a verdict), got {code} (2 is a usage "
        f"error, not a verdict)\nargv: {argv}\nstderr:\n{err.getvalue()}")
    try:
        return json.loads(out.getvalue())
    except ValueError as exc:
        raise AssertionError(
            f"ground() could not parse the report document ({exc})\n"
            f"argv: {argv}\nstdout:\n{out.getvalue()}\nstderr:\n{err.getvalue()}"
        ) from None


def drive(repo, case_id, rel_path, payload, expect, *, extra_argv=(),
          env=None, snapshot=None):
    """One scripted turn through the REAL hook: apply the write, then spawn."""
    agent = FakeAgent(repo.root, [tfrepo.proposal_for(
        repo, case_id, rel_path, payload, expect)])
    _proposal, event = agent.turn()
    return hookrunner.run_hook(
        event, snapshot=str(snapshot or repo.snapshot_path),
        extra_argv=extra_argv, env=env)


def edited(repo, rel_path, mutate):
    """The document *mutate* derives from the COMMITTED base, written to disk and
    returned so the fake agent can propose exactly it."""
    path = tfrepo.variant(repo, rel_path, mutate)
    return json.loads(path.read_text(encoding="utf-8"))


def verdicts_of(report, *, kind=None, status=None, prefix=None) -> list:
    """Every verdict matching an exact *kind*, a *status* and/or a kind *prefix*
    — the family filter the ``baseline:`` and ``drift`` assertions read."""
    out = []
    for verdict in report.get("verdicts") or []:
        if kind is not None and verdict.get("kind") != kind:
            continue
        if status is not None and verdict.get("status") != status:
            continue
        if prefix is not None and not str(verdict.get("kind", "")).startswith(prefix):
            continue
        out.append(verdict)
    return out


def assert_sec_channel_abstained(report, *needles: str) -> None:
    """The REQUIREMENT channel abstained, whatever the rest of the run decided.

    :func:`tests.agentic.asserts.assert_abstained` is a WHOLE-RUN assertion — it
    requires exit 0 — and the promise arms below run a document that carries a
    finding of its own, so the run blocks while the promise abstains. This is the
    same three-bucket assertion narrowed to the ``sec:`` kinds: at least one
    ``unverified`` naming its reason, and no ``grounded``, ``ungrounded`` or
    ``contradicted`` manufactured out of the same ignorance.
    """
    sec = verdicts_of(report, prefix="sec:")
    assert needles, ("an abstention on the requirement channel that names no "
                     "reason is a silent pass wearing a verdict")
    unverified = [v for v in sec if v["status"] == "unverified"]
    assert unverified, f"nothing on the sec: channel abstained: {sec}"
    for status in ("grounded", "ungrounded", "contradicted"):
        assert not [v for v in sec if v["status"] == status], (
            f"the requirement channel reported {status} out of the same "
            f"ignorance it abstained on: {sec}")
    joined = "\n".join(str(v.get("message")) for v in unverified)
    for needle in needles:
        assert needle in joined, (
            f"expected {needle!r} in the requirement channel's unverified "
            f"messages: {joined}")


def assert_claims_nothing_safe(report, needle: str = "") -> None:
    """No ``grounded`` verdict at all — optionally, none about *needle*.

    The negative half of every abstention here: a run that could not look must
    not leave a single verdict a reader could quote as a clean bill of health.
    """
    grounded = verdicts_of(report, status="grounded")
    if needle:
        grounded = [v for v in grounded
                    if needle in str(v.get("target", "")) or needle in str(v.get("message", ""))]
    assert not grounded, (
        f"the run reported {len(grounded)} grounded verdict(s)"
        + (f" about {needle!r}" if needle else "")
        + f" although it could not look: {grounded}")


# -- the mutations -------------------------------------------------------------


def _firewall(document, name):
    return document["resource"]["google_compute_firewall"][name]


def narrow_the_source_range(document):
    """10.0.0.0/8 → 10.0.1.0/24: a STRICTLY SMALLER packet set."""
    _firewall(document, "allow_ssh")["source_ranges"] = ["10.0.1.0/24"]


def widen_the_source_range(document):
    """The adversarial widening edit, reused where a benign case needs the
    change a guardrail is SUPPOSED to have an opinion about."""
    _firewall(document, "allow_ssh")["source_ranges"] = ["0.0.0.0/0"]


def add_a_denial(document):
    """A new deny block on tcp/23. Adding a denial permits nothing new."""
    _firewall(document, "deny_rdp")["deny"].append({"ports": ["23"], "protocol": "tcp"})


def interpolate_the_source_range(document):
    _firewall(document, "allow_ssh")["source_ranges"] = [INTERPOLATION]


def grant_editor(document):
    """The BEFORE of the scoped-grant case: a broad primitive role."""
    document["resource"]["google_project_iam_binding"]["viewer"]["role"] = "roles/editor"


def scope_the_grant(document):
    """... narrowed to storage object viewer on the SAME real principal."""
    document["resource"]["google_project_iam_binding"]["viewer"]["role"] = \
        "roles/storage.objectViewer"


def drop_terraform_state(document):
    """The config with its ``terraform`` block removed: no state source at all."""
    return {key: value for key, value in document.items() if key != "terraform"}


def drop_the_firewall_table(document):
    """The snapshot with ``firewall_rules`` UNCAPTURED — absent, which is not the
    same as empty."""
    return {key: value for key, value in document.items() if key != "firewall_rules"}


def drop_the_new_row(document):
    """The snapshot with the config-only rule removed, so it genuinely has no
    counterpart anywhere in the current state."""
    document["firewall_rules"] = {
        key: value for key, value in document["firewall_rules"].items()
        if key != NEW_FIREWALL}


def target_the_new_row(repo):
    """The config re-pointed at the config-only rule. NO domain is ever guessed
    from a key, so the target says both the domain and the row."""
    def mutate(document):
        return {**document, "targets": {str(repo.tf_json_path):
                                        f"firewall_rules:{NEW_FIREWALL}"}}
    return mutate


# -- fixtures ------------------------------------------------------------------


@pytest.fixture
def repo(tmp_path):
    """A fresh built repo per test, so one case's variant cannot leak into
    another's."""
    return tfrepo.build_tf_repo(tmp_path / "repo")


# -- HALF ONE: the false-positive budget --------------------------------------


def _passes_byte_quietly(repo, case_id, payload, *, rel_path=None) -> dict:
    """Drive one benign edit through the real hook, assert it costs the agent
    NOTHING, and return the same run's verdicts read in process."""
    rel_path = rel_path or tfrepo.TF_JSON_NAME
    outcome = drive(repo, case_id, rel_path, payload, "pass",
                    extra_argv=tfrepo.hook_argv(repo))
    assert_passed(outcome)
    report = ground(repo.path(rel_path), snapshot=repo.snapshot_path,
                    extra_argv=tfrepo.hook_argv(repo))
    assert report.get("ok") is True, report
    # A recognized, non-empty document that produces ZERO verdicts is
    # indistinguishable from one the gate deliberately passed.
    assert_no_verdictless_pass(outcome, report)
    return report


def test_narrowing_the_ssh_source_range_passes_byte_quietly(repo):
    """B01. The source range shrinks from a broad private range to a narrower
    one — a strictly smaller packet set, so no widening check can have anything
    to say, and a partial baseline does not change that because ``grounded`` is
    never downgraded for a requires-complete check."""
    before = json.loads(repo.tf_json_path.read_text(encoding="utf-8"))
    assert _firewall(before, "allow_ssh")["source_ranges"] == ["10.0.0.0/8"]
    payload = edited(repo, tfrepo.TF_JSON_NAME, narrow_the_source_range)
    assert _firewall(payload, "allow_ssh")["source_ranges"] == ["10.0.1.0/24"]

    report = _passes_byte_quietly(repo, "B01_narrow_source_range", payload)

    # BRANCH, NEVER SKIP. Where a widening check for the firewall kind is
    # registered the pair tier must DECIDE this row; where none is, it must say
    # so rather than leaving the row silently unexamined.
    if registry.pair_check("firewall_rule") is not None:
        decided = [v for v in report["verdicts"] if v.get("target") == FIREWALL]
        assert any(v["status"] == "grounded" for v in decided), decided
    else:
        skipped = assert_recorded(report, kind="pair:no-check", target=FIREWALL)
        assert skipped["status"] == "unverified"
        assert "no widening check is defined" in skipped["message"]


def test_adding_a_denial_passes_byte_quietly(repo):
    """B02. A new deny block on tcp/23. Adding a denial permits nothing new, so
    a gate that blocks here is a gate that punishes hardening."""
    payload = edited(repo, tfrepo.TF_JSON_NAME, add_a_denial)
    denied = {(entry["protocol"], tuple(entry["ports"]))
              for entry in _firewall(payload, "deny_rdp")["deny"]}
    assert ("tcp", ("23",)) in denied and ("tcp", ("3389",)) in denied, denied

    _passes_byte_quietly(repo, "B02_add_a_denial", payload)


def test_scoping_a_grant_down_to_a_narrower_role_passes_byte_quietly(repo):
    """B03. An editor role on a real principal is replaced by a narrower storage
    viewer role on the SAME real principal. Both roles and the principal are in
    the agentic snapshot, so nothing here is a vocabulary question."""
    snapshot = json.loads(repo.snapshot_path.read_text(encoding="utf-8"))
    assert "roles/editor" in snapshot["roles"]
    assert "roles/storage.objectViewer" in snapshot["roles"]

    tfrepo.variant(repo, tfrepo.TF_JSON_NAME, grant_editor)
    payload = edited(repo, tfrepo.TF_JSON_NAME, scope_the_grant)
    binding = payload["resource"]["google_project_iam_binding"]["viewer"]
    assert binding["role"] == "roles/storage.objectViewer"
    assert binding["members"] == ["group:data-eng@acme.example"]
    assert set(binding["members"]) <= set(snapshot["principals"])

    _passes_byte_quietly(repo, "B03_scope_the_grant", payload)


def test_a_byte_identical_rewrite_changes_nothing(repo):
    """B04. The agent rewrites the file byte for byte. Zero verdict change, zero
    drift, zero notices — this is the case that catches a renderer or a notice
    that fires unconditionally, which no edited case can."""
    text = repo.tf_json_path.read_text(encoding="utf-8")
    before = ground(repo.tf_json_path, snapshot=repo.snapshot_path,
                    extra_argv=tfrepo.hook_argv(repo))

    # The payload is the exact TEXT, not the parsed document: a dict payload is
    # re-serialized by the fake agent and would not be byte-identical.
    report = _passes_byte_quietly(repo, "B04_no_op_rewrite", text)
    assert repo.tf_json_path.read_text(encoding="utf-8") == text

    assert report["verdicts"] == before["verdicts"], (
        "a byte-identical rewrite moved a verdict")
    assert report["summary"] == before["summary"]
    assert not verdicts_of(report, prefix="drift"), (
        "a byte-identical rewrite reported drift")


# -- HALF TWO: the six honest abstentions -------------------------------------


def test_an_interpolated_source_range_is_never_quoted_as_a_value(repo):
    """C01, THE ANTI-HALLUCINATION PIN. The source range becomes an
    interpolation.

    Emitting ``${var.office_cidr}`` as a claim VALUE would produce a confident
    ``ungrounded`` against a value terraform never intended, so the literal must
    appear nowhere in the report — and nothing about the file may grade
    ``grounded``.

    The attribute-path half branches: reporting one ``proposal:unresolved`` per
    stripped path needs the interpolation to have been turned into an
    ``Unresolved`` sentinel by a terraform READER, and the CLI hook grounds a
    ``.tf.json`` through ``preflight.detect_kind``, which does not recognize
    terraform's JSON configuration syntax. Where a path IS reported it must name
    the ATTRIBUTE and never the value; where none is, the honest pin is that the
    document was not recognized and nothing was claimed about it.
    """
    payload = edited(repo, tfrepo.TF_JSON_NAME, interpolate_the_source_range)
    assert _firewall(payload, "allow_ssh")["source_ranges"] == [INTERPOLATION]

    outcome = drive(repo, "C01_unresolved_variable", tfrepo.TF_JSON_NAME, payload,
                    "abstain", extra_argv=tfrepo.hook_argv(repo))
    report = ground(repo.tf_json_path, snapshot=repo.snapshot_path,
                    extra_argv=tfrepo.hook_argv(repo))
    # THE REASON IS NAMED, which this call did not require when it was written:
    # `assert_abstained` grew the "an abstain that names no reason is not an
    # abstain" guard afterwards, and a bare call now fails on the guard rather
    # than on the product. Naming the reason is what this module's own doctrine
    # demands anyway — the substring is the one the unresolved-path verdict and
    # the downgrade suffix both carry, so the abstention must SAY why it could
    # not decide, not merely be one.
    assert_abstained(outcome, report, "could not be resolved statically")
    assert INTERPOLATION not in json.dumps(report), (
        f"{INTERPOLATION!r} reached the report as a value — a claim carrying an "
        f"interpolation grades a string terraform never intended")
    assert_claims_nothing_safe(report)

    unresolved = verdicts_of(report, kind=UNRESOLVED_KIND)
    if unresolved:
        assert any("source_ranges" in str(v.get("target")) for v in unresolved), (
            f"an unresolved path was reported but none names the attribute: "
            f"{unresolved}")
        for verdict in unresolved:
            assert INTERPOLATION not in str(verdict.get("target"))
    else:
        unrecognized = assert_recorded(report, kind="document")
        assert "not recognized" in unrecognized["message"]
        assert unrecognized["status"] == "unverified"


def test_a_stale_source_abstains_and_says_how_stale(repo):
    """C02. A one-day ceiling and an as-of two days past the state's capture
    time, both supplied on the command line so the answer cannot drift with the
    wall clock.

    ``--abstain-notes`` is on, which is what puts the ignorance on the
    AGENT-VISIBLE stream: without it an abstaining hook run is silent by design,
    and "exit 0, nothing printed" is exactly what a clean pass looks like.
    """
    payload = edited(repo, tfrepo.TF_JSON_NAME, narrow_the_source_range)
    extra = ("--terraform-state", str(repo.state_path),
             "--config", str(repo.config_path),
             "--as-of", STALE_ASOF, "--max-age", "1d", "--abstain-notes")
    outcome = drive(repo, "C02_stale_state", tfrepo.TF_JSON_NAME, payload,
                    "abstain", extra_argv=extra)
    # ``--abstain-notes`` is a hook-mode channel and inert in normal mode, so the
    # in-process read passes the SAME argv rather than a trimmed near-copy.
    report = ground(repo.tf_json_path, snapshot=repo.snapshot_path, extra_argv=extra)

    # The age AND the ceiling, both named. The `baseline:stale` verdict says the
    # row's source is past its ceiling; the `staleness` verdict beside it says
    # by how much and against what — assert_abstained looks across the whole
    # unverified bucket, which is the channel an operator actually reads.
    assert_abstained(outcome, report, "2 days before now", "1 day")
    stale = assert_recorded(report, kind="baseline:stale", target=FIREWALL)
    assert stale["status"] == "unverified"
    # ... and this is NOT a pass: the abstention reached the agent.
    assert outcome.stderr != "", (
        f"a stale current state abstained in SILENCE, which is indistinguishable "
        f"from a clean pass\n{outcome}")
    assert "NOT DECIDED" in outcome.stderr, outcome.stderr


def test_the_default_age_ceiling_fires_with_no_flag_at_all(repo):
    """C02b, THE ARM THAT MATTERS FOR A HOOK NOBODY CONFIGURED. No ``--max-age``,
    no ``--as-of``: the clock comes from ``$GCP_GROUNDING_NOW`` eight days past
    the capture time and the ceiling from ``freshness.MAX_AGE_DEFAULT``.

    A guardrail whose staleness check only runs when an operator remembers a
    flag is a guardrail that never runs.
    """
    payload = edited(repo, tfrepo.TF_JSON_NAME, narrow_the_source_range)
    extra = ("--terraform-state", str(repo.state_path),
             "--config", str(repo.config_path), "--abstain-notes")
    clock = {"GCP_GROUNDING_NOW": DEFAULT_CEILING_NOW}
    outcome = drive(repo, "C02b_default_ceiling", tfrepo.TF_JSON_NAME, payload,
                    "abstain", extra_argv=extra, env=clock)
    report = ground(repo.tf_json_path, snapshot=repo.snapshot_path,
                    extra_argv=extra, env_overrides=clock)

    assert_abstained(outcome, report, "8 days before now", "7 days")
    assert_recorded(report, kind="baseline:stale", target=FIREWALL)
    assert outcome.stderr != "", outcome


def test_a_plan_whose_ports_are_unknown_does_not_get_the_cleanest_pass(repo):
    """C03, THE AFTER-UNKNOWN CASE — the proposal-side mirror of the capture-side
    handling, and the one arm no other agentic case reaches.

    The plan's ``after_unknown`` marks ``allow[0].ports`` true and its ``after``
    OMITS the key, which is what a plan looks like when a value depends on a
    resource that has not been created yet. The failure mode being pinned is
    SILENCE: nothing is stripped, so without the derivation in
    ``engine.prepare_proposal`` nothing is reported and the plan's LEAST certain
    attribute takes the CLEANEST path in the system. No flag asks for this — a
    case that had to ask would be testing the test.
    """
    plan = json.loads(PLAN_FIXTURE.read_text(encoding="utf-8"))
    change = plan["resource_changes"][0]["change"]
    assert change["after_unknown"] == {"allow": [{"ports": True}]}
    assert "ports" not in change["after"]["allow"][0], (
        "an unknown attribute is OMITTED from after; a present key would make "
        "this case test something else entirely")

    outcome = drive(repo, "C03_after_unknown", "plan.json", plan, "abstain",
                    extra_argv=tfrepo.hook_argv(repo))
    report = ground(repo.root / "plan.json", snapshot=repo.snapshot_path,
                    extra_argv=tfrepo.hook_argv(repo))
    assert_abstained(outcome, report, UNKNOWN_PATH)

    reported = assert_recorded(report, kind=UNRESOLVED_KIND, target=UNKNOWN_PATH)
    assert reported["status"] == "unverified"
    assert_claims_nothing_safe(report, "google_compute_firewall")

    # NON-VACUITY. The same plan with the ports RESOLVED grounds the firewall's
    # resource type; the unknown one downgrades that very verdict. Without this
    # control the assertion above holds just as well against a checkout that
    # grounds nothing at all.
    control = json.loads(json.dumps(plan))
    control_change = control["resource_changes"][0]["change"]
    control_change["after"]["allow"][0]["ports"] = ["22"]
    del control_change["after_unknown"]
    control_path = repo.root / "control_plan.json"
    control_path.write_text(json.dumps(control, indent=2, sort_keys=True) + "\n",
                            encoding="utf-8")
    control_report = ground(control_path, snapshot=repo.snapshot_path,
                            extra_argv=tfrepo.hook_argv(repo))
    grounded = verdicts_of(control_report, status="grounded")
    assert grounded, (
        f"the control plan grounded nothing, so the downgrade assertion above is "
        f"vacuous\n{control_report}")
    downgraded = [v for v in report["verdicts"]
                  if v["kind"] in {g["kind"] for g in grounded}]
    assert downgraded and all(v["status"] == "unverified" for v in downgraded), (
        f"a verdict that grounds when the ports are known must be unverified when "
        f"they are unknown\ngrounded: {grounded}\nunknown run: {downgraded}")
    assert any("could not be resolved statically" in v["message"] for v in downgraded), (
        f"the downgraded verdict does not say why it was downgraded: {downgraded}")


def test_an_uncaptured_firewall_table_abstains_as_unqueried(repo):
    """C04. The firewall table is dropped from the snapshot and NO terraform
    state is configured, so nothing this run can read covers the category at
    all. Failing to look is a configuration defect, and it must say so."""
    tfrepo.variant(repo, tfrepo.CONFIG_NAME, drop_terraform_state)
    tfrepo.variant(repo, tfrepo.SNAPSHOT_NAME, drop_the_firewall_table)
    payload = edited(repo, tfrepo.TF_JSON_NAME, narrow_the_source_range)

    outcome = drive(repo, "C04_uncaptured_category", tfrepo.TF_JSON_NAME, payload,
                    "abstain", extra_argv=state_free_argv(repo))
    report = ground(repo.tf_json_path, snapshot=repo.snapshot_path,
                    extra_argv=state_free_argv(repo))

    assert_abstained(outcome, report, "was NOT looked up")
    assert [v["kind"] for v in verdicts_of(report, prefix="baseline:")] == \
        ["baseline:unqueried"]
    assert_claims_nothing_safe(report, FIREWALL)


def test_an_unmanaged_resource_abstains_as_new(repo):
    """C05. The edit touches the rule that exists in the configuration and in no
    current-state source, run against a snapshot DECLARED complete for the
    domain.

    Completeness is never inferred from content, so the declaration is explicit
    (``--completeness``, the source option): an undeclared snapshot would
    honestly answer ``baseline:unqueried`` here instead, which is the collapse
    :func:`test_a_new_resource_and_a_missing_source_are_told_apart` exists to
    prevent.
    """
    tfrepo.variant(repo, tfrepo.CONFIG_NAME, drop_terraform_state)
    tfrepo.variant(repo, tfrepo.CONFIG_NAME, target_the_new_row(repo))
    tfrepo.variant(repo, tfrepo.SNAPSHOT_NAME, drop_the_new_row)
    payload = edited(repo, tfrepo.TF_JSON_NAME, add_a_denial)
    extra = state_free_argv(repo, ("--completeness", "complete"))

    outcome = drive(repo, "C05_unmanaged_resource", tfrepo.TF_JSON_NAME, payload,
                    "abstain", extra_argv=extra)
    report = ground(repo.tf_json_path, snapshot=repo.snapshot_path, extra_argv=extra)

    assert_abstained(outcome, report, "new resource")
    assert [v["kind"] for v in verdicts_of(report, prefix="baseline:")] == \
        ["baseline:new"]
    assert_claims_nothing_safe(report, NEW_FIREWALL)


def test_an_unconfigured_run_looks_unconfigured(repo):
    """C06. The adversarial WIDENING edit, run with no state flags and no config
    at all. An unconfigured guardrail must LOOK unconfigured: the one thing it
    may not do is answer the question it never looked at.

    ``baseline:unqueried`` is emitted by ``baseline.resolve``, which the CLI
    reaches only once a current state is CONFIGURED — so with nothing configured
    the honest record is the abstention that says nothing was checked, and the
    branch below asserts the unqueried spelling wherever a baseline verdict is
    reached at all. Either way the load-bearing assertion is the same one: no
    ``grounded`` verdict about the firewall's exposure.
    """
    payload = edited(repo, tfrepo.TF_JSON_NAME, widen_the_source_range)
    assert _firewall(payload, "allow_ssh")["source_ranges"] == ["0.0.0.0/0"]

    outcome = drive(repo, "C06_no_state_configured", tfrepo.TF_JSON_NAME, payload,
                    "abstain", extra_argv=("--no-config",))
    report = ground(repo.tf_json_path, snapshot=repo.snapshot_path,
                    extra_argv=("--no-config",))

    assert_abstained(outcome, report, "nothing was checked")
    assert_claims_nothing_safe(report, FIREWALL)
    assert_claims_nothing_safe(report, "0.0.0.0/0")

    baseline_kinds = [v["kind"] for v in verdicts_of(report, prefix="baseline:")]
    if baseline_kinds:
        assert baseline_kinds == ["baseline:unqueried"], baseline_kinds
    else:
        unchecked = assert_recorded(report, kind="document")
        assert "nothing was checked" in unchecked["message"], unchecked
        assert not verdicts_of(report, prefix="pair:"), (
            "no current state was configured, so no pair check may claim to have "
            "compared anything")


# -- THE HEADLINE ASSERTION ---------------------------------------------------


def _baseline_reason(tmp_path, name, *, capture: bool, complete: bool) -> str:
    """The baseline reason for ONE row under two configurations that differ in
    exactly one way — whether the category was captured and declared complete.

    Both arms target the SAME row, so the messages cannot differ merely by
    naming different keys: what is compared is the REASON.
    """
    repo = tfrepo.build_tf_repo(tmp_path / name)
    tfrepo.variant(repo, tfrepo.CONFIG_NAME, drop_terraform_state)
    tfrepo.variant(repo, tfrepo.CONFIG_NAME, target_the_new_row(repo))
    tfrepo.variant(repo, tfrepo.SNAPSHOT_NAME,
                   drop_the_new_row if capture else drop_the_firewall_table)
    extra = state_free_argv(repo, ("--completeness", "complete") if complete else ())
    report = ground(repo.tf_json_path, snapshot=repo.snapshot_path, extra_argv=extra)
    baseline = verdicts_of(report, prefix="baseline:")
    assert len(baseline) == 1, (f"{name}: expected exactly one baseline verdict, "
                                f"got {baseline}")
    return baseline[0]["message"]


def test_a_new_resource_and_a_missing_source_are_told_apart(tmp_path):
    """THE HEADLINE ASSERTION OF THIS MODULE, written as its own test rather
    than buried in a case.

    A new resource legitimately has no baseline; failing to look is a
    configuration defect. Collapsing the two is the failure this whole document
    is built to prevent — one is "there is nothing to compare against" and the
    other is "I never asked", and an operator who reads the first when the
    second is true will ship the change.
    """
    uncaptured = _baseline_reason(tmp_path, "uncaptured", capture=False,
                                  complete=False)
    unmanaged = _baseline_reason(tmp_path, "unmanaged", capture=True, complete=True)

    assert uncaptured != unmanaged
    assert uncaptured not in unmanaged and unmanaged not in uncaptured, (
        f"one message contains the other, so a reader cannot tell them apart\n"
        f"uncaptured: {uncaptured}\nunmanaged:  {unmanaged}")
    # The unmanaged one names a NEW resource; the uncaptured one must not, because
    # nothing here licenses the claim that the row does not exist.
    assert "new resource" in unmanaged, unmanaged
    assert "new resource" not in uncaptured, uncaptured
    # ... and the uncaptured one points at the CONFIGURATION — the thing an
    # operator fixes — while the unmanaged one names none, because there is
    # nothing to fix.
    assert "configured state source" in uncaptured, uncaptured
    assert "configured state source" not in unmanaged, unmanaged
    assert NEW_FIREWALL in uncaptured and NEW_FIREWALL in unmanaged


# -- THE THIRD INPUT: a compiled promise over a terraform-derived state --------


def _compile_promise(repo) -> str:
    """Copy the committed requirement into the repo, compile it in process, and
    point the discovered config's ``requirements`` key at the artifacts."""
    directory = repo.root / REQUIREMENTS_DIR
    directory.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(PROMISE_FIXTURE, directory / PROMISE_FIXTURE.name)
    out, err = io.StringIO(), io.StringIO()
    with _child_like_environ():
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["compile-requirements", str(directory),
                             "--snapshot", str(repo.snapshot_path)])
    assert code in (0, 1), (code, out.getvalue(), err.getvalue())
    artifacts = sorted((repo.root / COMPILED_DIR).glob("*.promises.json"))
    assert artifacts, (
        f"compile-requirements wrote no artifact\n{out.getvalue()}\n{err.getvalue()}")
    document = json.loads(artifacts[0].read_text(encoding="utf-8"))
    assert [p["id"] for p in document["promises"]] == [PROMISE_ID], document
    tfrepo.variant(repo, tfrepo.CONFIG_NAME,
                   lambda config: {**config, "requirements": COMPILED_DIR})
    return document["promises"][0]["status"]


def test_the_promise_abstains_over_terraform_and_is_live_over_the_estate(tmp_path):
    """THE THIRD-INPUT ARM, and the only place in this suite where a compiled
    ``sec_requirements`` promise meets a terraform-derived current state through
    the REAL hook.

    TWO ARMS, ASSERTED AS A PAIR, because the abstention is only correct if the
    positive case still works: a rule that abstains everywhere is not a cautious
    rule, it is an absent one.

    ARM ONE grounds against a vocabulary-only snapshot, so the terraform state is
    the only source of firewall facts. A terraform view sees only what terraform
    manages, so an estate-wide negative is not discharged from it — and a
    confident clean bill of health here is the worst answer the tool can give
    about the one rule a human wrote by hand.

    ARM TWO adds the merged agentic estate snapshot and DECLARES the category
    complete, which is the configuration under which the promise can really
    speak.

    It branches on the two ``sec`` probes rather than taking a hard dependency on
    the sec chain. With the domain collections absent the promise cannot compile
    at all, and what must still hold — in BOTH arms — is that the requirement is
    visibly not enforcing rather than silently absent, and that it never grades
    the estate clean.

    TWO EXPECTATIONS WERE RE-PINNED TO THE INTEGRATED SEMANTICS, and both are
    consequences of decisions this document does not own.

    ONE, the RUN blocks in both arms. A ``.tf.json`` edit is now routed through
    the one terraform entry point (``plan.as_plan_document`` →
    ``engine.prepare_proposal``, the call ``gcp_grounding.gate`` makes), so the
    file's OWN claims are extracted and the widening edit is a finding in its own
    right: ``firewall_exposure`` contradicts a world-open tcp/22 rule and the
    hook exits 2. When this arm was written the CLI prepared the raw
    ``{"resource": ...}`` body instead, ``detect_kind`` recognized nothing, no
    claim was extracted and the same run exited 0 — which is why it asked for an
    abstain. The subject of the arm is the PROMISE, and the promise still
    abstains; ``assert_abstained`` is a whole-run assertion and cannot express
    that, so the run half is asserted with :func:`assert_blocked` and the promise
    half against the promise's own verdict.

    TWO, the promise ABSTAINS in arm two as well, and the pair is asserted on
    what actually differs. ``provenance`` caps a category any TERRAFORM source
    contributed to at ``partial``, and arm two configures the terraform state
    beside the estate snapshot, so ``firewall_rules`` is partial there too and
    the universal-negative gate refuses to decide a promise that reasons from
    absence. ``--completeness complete`` does not lift that cap and must not:
    the alternative is an estate-wide clean bill of health from a view that sees
    part of the estate. The promise could only be CONTRADICTED by a witness, and
    the estate this suite commits holds no open-SSH rule — the widened rule lives
    in the PROPOSAL, which is the ``proposed_firewall_rules`` collection this
    promise deliberately does not quantify over. So the live-over-the-estate half
    is pinned where it is real: over the estate an estate-tier check DECIDES the
    widening (``firewall_reopen`` contradicts), and over a terraform-only view
    nothing about the estate is decided at all. A rule that abstains everywhere
    is still not a cautious rule, and that is exactly what the pair below asserts.
    """
    live = tfrepo.HAVE_SEC_RULES and tfrepo.HAVE_SEC_DOMAINS

    # ARM ONE — the terraform state as the only current-state source.
    tf_only = tfrepo.build_tf_repo(tmp_path / "tf_only", snapshot=env.ESTATE_SNAPSHOT)
    status = _compile_promise(tf_only)
    assert status == ("compiled" if live else "unverified"), status
    payload = edited(tf_only, tfrepo.TF_JSON_NAME, widen_the_source_range)
    tf_outcome = drive(tf_only, "P01_promise_over_terraform", tfrepo.TF_JSON_NAME,
                       payload, "block", extra_argv=tfrepo.hook_argv(tf_only))
    tf_report = ground(tf_only.tf_json_path, snapshot=tf_only.snapshot_path,
                       extra_argv=tfrepo.hook_argv(tf_only))

    promise = assert_recorded(tf_report, kind="sec:vpc_firewall", target=PROMISE_ID)
    assert promise["status"] == "unverified", (
        f"an estate-wide negative was decided from a terraform-only view: {promise}")
    assert PROMISE_COLLECTION in promise["message"], promise
    # The PROMISE abstains and the promise's ignorance is on the record; the RUN
    # blocks, because the widening edit is a finding the file's own claims carry.
    # Both halves, so neither can hide the other.
    assert_sec_channel_abstained(tf_report, PROMISE_COLLECTION)
    assert_claims_nothing_safe(tf_report, PROMISE_ID)
    assert_blocked(tf_outcome, "tcp/22")
    if live:
        assert "complete" in promise["message"] or "partial" in promise["message"], (
            f"the abstention does not name the incomplete view: {promise}")
    else:
        assert "not registered" in promise["message"], promise
        assert "not enforcing" in tf_outcome.stderr, (
            f"a requirement that cannot run must say so on the agent-visible "
            f"stream\n{tf_outcome}")
    # NOTHING ABOUT THE ESTATE WAS DECIDED from a terraform-only view: the half
    # that makes arm two's answer mean something.
    assert not verdicts_of(tf_report, kind="firewall_reopen", status="contradicted"), (
        "a terraform-only view decided an estate-tier firewall question")

    # ARM TWO — the merged agentic estate too, declaring the category complete.
    estate = tfrepo.build_tf_repo(tmp_path / "estate")
    _compile_promise(estate)
    payload = edited(estate, tfrepo.TF_JSON_NAME, widen_the_source_range)
    extra = tfrepo.hook_argv(estate, extra=("--completeness", "complete"))
    estate_outcome = drive(estate, "P02_promise_over_the_estate",
                           tfrepo.TF_JSON_NAME, payload, "block",
                           extra_argv=extra)
    estate_report = ground(estate.tf_json_path, snapshot=estate.snapshot_path,
                           extra_argv=extra)
    decided = assert_recorded(estate_report, kind="sec:vpc_firewall", target=PROMISE_ID)

    assert decided["status"] == "unverified", decided
    if live:
        # THE CAP, NAMED. A category any terraform source contributed to is
        # 'partial', and this arm configures the terraform state beside the
        # estate snapshot, so the promise may not discharge a negative from it —
        # `--completeness complete` does not buy that and must not.
        assert PROMISE_COLLECTION in decided["message"], decided
        assert "partial" in decided["message"], decided
        # ... AND THE EDIT IS STILL BLOCKED, over the estate, by a check that
        # DID compare against it. This is the half arm one cannot have: a
        # witness-shaped estate question is decided here and abstained there.
        reopened = assert_recorded(estate_report, kind="firewall_reopen",
                                  target=FIREWALL.rsplit("/", 1)[-1])
        assert reopened["status"] == "contradicted", reopened
        assert_blocked(estate_outcome, "tcp/22")
        assert estate_outcome.exit_code == 2, (
            f"the widening edit was not blocked over the estate\n{estate_outcome}")
    else:
        assert "not registered" in decided["message"], decided
        assert "not enforcing" in estate_outcome.stderr, estate_outcome
    assert_sec_channel_abstained(estate_report, PROMISE_COLLECTION)
    assert_claims_nothing_safe(estate_report, PROMISE_ID)


@pytest.mark.xfail(strict=True, reason=(
    "ESC-GX-TFPROMISE-001: provenance caps a category any terraform source "
    "contributed to at 'partial', so over the merged estate — with the category "
    "DECLARED complete — the sec:vpc_firewall promise still abstains instead of "
    "contradicting the widening, and the estate this suite commits holds no "
    "open-SSH witness that could contradict it either"))
def test_the_promise_contradicts_the_widening_over_the_estate(tmp_path):
    """THE PIN `agent/tx-agentic-tf-benign` WROTE FOR ARM TWO, landed here under
    house rule 4 instead of being reversed in place.

    The test above re-pins arm two's promise to ``unverified``, which is what the
    integrated tree really answers — but that reverses this module's own
    branch-authored expectation, ``decided["status"] == "contradicted"``, and the
    two cannot both hold. Picking the winner silently is what the escalation
    register exists to prevent, so the losing expectation is landed VERBATIM here
    under ``xfail(strict=True)`` naming ESC-GX-TFPROMISE-001:

    * it is not deleted, so the pair's positive half stays legible as a
      requirement rather than becoming a thing nobody remembers wanting;
    * ``strict=True`` means the DAY a provenance decision or an estate fixture
      makes the promise decide, this XPASSes and the suite goes RED — which
      forces the escalation to be retired deliberately instead of rotting;
    * the escalation entry carries the measured reason and what would close it.

    IN-PROCESS ON PURPOSE. It reproduces arm two through :func:`ground`, the same
    ``cli.main`` entry point on the same code path, and spawns NO child: an
    xfailing case must not spend the suite-wide subprocess budget that keeps the
    full run a usable oracle. The exit-code half of the branch's arm is asserted
    live above, by ``drive``'s expectation and ``assert_blocked``.
    """
    estate = tfrepo.build_tf_repo(tmp_path / "estate")
    _compile_promise(estate)
    edited(estate, tfrepo.TF_JSON_NAME, widen_the_source_range)
    extra = tfrepo.hook_argv(estate, extra=("--completeness", "complete"))
    estate_report = ground(estate.tf_json_path, snapshot=estate.snapshot_path,
                           extra_argv=extra)
    decided = assert_recorded(estate_report, kind="sec:vpc_firewall",
                              target=PROMISE_ID)
    assert decided["status"] == "contradicted", decided


# -- the harness's own pins ----------------------------------------------------


def test_the_state_free_argv_is_the_shared_shape_minus_the_state_flag(repo):
    """The three withholding cases must differ from the shared argv in exactly
    one way: a flag added to :func:`tests.agentic.tfrepo.hook_argv` must reach
    them too, and a state source must never creep back in."""
    shared = tfrepo.hook_argv(repo)
    withheld = ("--terraform-state", str(repo.state_path))
    assert state_free_argv(repo) == tuple(p for p in shared if p not in withheld)
    assert "--terraform-state" not in state_free_argv(repo)
    assert state_free_argv(repo, ("--completeness", "complete"))[-2:] == \
        ("--completeness", "complete")


def test_every_committed_payload_is_the_document_its_case_needs():
    """The two committed payloads, pinned where a reviewer can see them: a
    document that quietly stopped being a plan — or a promise that quietly
    stopped quantifying over the estate — would turn its case into a test of
    nothing."""
    plan = json.loads(PLAN_FIXTURE.read_text(encoding="utf-8"))
    assert plan["terraform_version"] and plan["format_version"]
    assert [entry["address"] for entry in plan["resource_changes"]] == \
        ["google_compute_firewall.allow_ssh"]

    promise = PROMISE_FIXTURE.read_text(encoding="utf-8")
    assert f"id: {PROMISE_ID}" in promise
    assert "state: estate" in promise
    assert f"exists r in {PROMISE_COLLECTION}" in promise, (
        "the promise must quantify over the ESTATE collection: a proposal-tier "
        "rule would be discharged by the document under review and would say "
        "nothing about the estate a terraform view cannot see")
