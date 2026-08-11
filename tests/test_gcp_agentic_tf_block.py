"""Six adversarial terraform edits, driven through the REAL hook against a
current state the gate DERIVED FOR ITSELF from a v4 tfstate on disk.

THE PROPERTY UNDER TEST IS THE THIRD INPUT, not the six domains. Every case
below is an edit to a terraform configuration whose counterpart lives in the
current state the run assembled from ``--terraform-state`` plus the merged
agentic snapshot — and NOT ONE of them passes ``--baseline``. That is the whole
point: ``constraints.check_policy_subset`` and the registered pair checks are
the only things in this repository that can say "this change grants something
the old configuration did not", and before this document they were reachable
only when a human typed a flag the PostToolUse hook never types. Cross-cutting
assertion 2 pins exactly that, per case, on the recorded argv.

THE PAYLOADS ARE COMMITTED DOCUMENTS, one reviewable ``.tf.json`` per case id
under ``tests/fixtures/gcp/agentic/tf/block/``, loaded and handed to the
proposal — never Python literals, so what an agent is scripted to write is a
file a reviewer can read. :func:`test_every_payload_is_the_base_corpus_plus_its_named_edit`
pins each one against the committed base corpus so a payload cannot quietly
become a different document. That directory is named here in prose and
deliberately NOT in a ``(paths:)`` entry: ``target_paths`` is compared as an
exact string wherever it is consumed, an entry ending in a slash can never match
a git-reported file, so a directory entry would convey nothing while hiding
these files from any who-else-writes-here collision check.

BRANCH-HONEST TRI-STATE. Each case decides ONE of two branches and no third
outcome is possible:

* it is DECIDED — exit 2, byte-empty stdout, the rendered report's ``FAILED``
  header and case-specific substrings on stderr, and a ``contradicted`` verdict
  on the family's OWN channel; or
* it is RECORDED — exit 0, the changed thing left a trace, and the report
  carries the BASELINE PLUMBING evidence: a verdict whose target is the
  resource's CANONICAL KEY in the current state, carrying the per-verdict
  attribution suffix that names the source it was compared against. That is
  this document's contribution — the counterpart was found and handed to the
  pair tier — and it holds whether or not the domain check that would consume
  it exists yet.

WHICH BRANCH A CASE TAKES IS COMPUTED, NEVER ASSUMED, and the predicate is
NOT the bare domain probe the design named. The domain probes in
:mod:`tests.agentic.env` are behavioural over a POLICY-shaped document; they
answer "can this domain block at all", which is a strictly weaker question than
"can this domain decide a terraform proposal whose counterpart came from a
state file". Three of the six cases have a live domain probe and still do not
block, each for a different and separately named reason, so a predicate that
read the probe alone would assert a block this tree cannot produce. Each case
therefore carries the design's domain probe AND the one further conjunct its
route actually needs, and every RECORDED branch names its gap in a comment.

THE SOLVER IS A SECOND AXIS, and it BRANCHES rather than skipping — the
``HAVE_Z3`` idiom the suite uses everywhere. Every check these cases turn on
except the VPC-SC one is solver-backed, so in a checkout where ``get_solver()``
falls back to the builtin backend the packet-set, priority and subset
comparisons do not run at all: the domain probes read False, the cases take the
RECORDED branch, and the abstentions must say the SOLVER is missing rather than
naming a partial baseline. Those are different facts about the world and an
operator has to be able to tell them apart — a checkout that cannot compare
anything must not read like a checkout being careful. :data:`HAVE_SOLVER` is
the switch, and the run is green on both sides of it.

THE RAW-HCL ARM is the only place in the whole agentic suite where a ``.tf``
file drives an outcome through the real hook. ``tx-gate-tf-routing``'s reader
assertion is in-process only and ``tx-agentic-tf-plumbing`` merely writes an
equivalent ``main.tf``, so without the arm below the one surface an agent
actually edits — the surface whose reader is resolved lazily and could silently
be absent — has zero end-to-end coverage.

THE PARTIAL-BASELINE ASYMMETRY is the most important assertion in the module and
gets one parametrised test per widening case. A counterpart that came from
terraform caps its category at ``partial``, and a check that reasons from what
the baseline does NOT contain may not turn a partial view into a block; the same
edit over a view an API source covered completely MUST block. Asserting only
half of that would pass against a gate that never blocks, or against one that
blocks on ignorance.

SUBPROCESSES: EIGHT, and the number is NOT this task's own budget of fourteen.
The suite-wide ceiling, ``budget.SubprocessBudget.MAX_SUBPROCESS_SPAWNS``, is
450 and the integrated tree measured 442 before this module — so eight is the
whole of the headroom, and :data:`MODULE_SPAWN_CAP` pins it at module teardown.
Raising the ceiling was available and was NOT taken: it is asserted as a
literal in ``tests/test_gcp_agentic_plumbing.py`` and named as a measured
number in four other modules' docstrings, and a module that lifts a shared
ceiling to fit itself has moved the cost onto everyone rather than paid it.

WHERE THE EIGHT GO, and what each one buys that no in-process read can:

* SIX case runs, one per adversarial edit. The design requires each write to be
  driven through the REAL hook and nothing else observes argv assembly, stdin
  decoding and the exit-code-plus-stderr contract an editor agent consumes.
  They carry ``--abstain-notes``, so a case the gate could not decide reaches
  the agent-visible stream instead of being byte-silent — which is what lets
  the softened half of the partial-baseline pair be asserted on a real stream.
* ONE for the unconditional existence arm, because "at least one adversarial
  case is a hard block from day one" means exit 2, and an exit code is the one
  thing an in-process call cannot honestly produce.
* ONE for the raw ``.tf``, which is this arm's entire justification.

EVERYTHING ELSE reads the same ``cli.main`` code path in process through
:func:`ground` — ``--hook`` and normal mode share ``cli._ground`` — which is
what the task's own budget note asks for: a second spawn wherever only verdict
text is needed buys nothing. The partial-baseline pair is therefore split by
what each half can witness: the SOFTENED verdict and its visibility on stderr
are asserted on the case run that produced them, and the pair of verdicts —
softened over a partial view, ``contradicted`` over a complete one — is
asserted in process, where a second and third spawn would have added no
evidence.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
from dataclasses import dataclass
from pathlib import Path

import pytest

from gcp_grounding import cli, registry
from tests.agentic import env, hookrunner, tfrepo
from tests.agentic.asserts import (assert_blocked, assert_decided_on_channel,
                                   assert_not_silently_dropped, assert_recorded)
from tests.agentic.fake_agent import FakeAgent
from tests.agentic.hookrunner import bound_subprocess_budget  # noqa: F401

#: This module's committed payloads: one reviewable ``<case id>.tf.json`` per
#: case, each the base corpus plus exactly one named edit.
BLOCK = env.AGENTIC / "tf" / "block"

#: This module's share of the suite-wide spawn ceiling — SIX case runs, ONE
#: unconditional-block run and ONE raw-``.tf`` run.
#:
#: Not this task's own budget of fourteen. ``MAX_SUBPROCESS_SPAWNS`` is 450 and
#: the integrated tree measures 442 without this module, so eight is the whole
#: of the remaining headroom. The session ceiling is shared and cannot notice
#: one module growing at the others' expense; this cap can, and it is checked at
#: module teardown rather than per test so a ``-k`` selection does not trip it.
MODULE_SPAWN_CAP = 8

#: The flag that must appear NOWHERE in any recorded argv. The counterpart came
#: off the disk the agent is editing, not from a human who remembered to name a
#: baseline — and this string is the regression pin for the whole document.
BASELINE_FLAG = "--baseline"

#: A dollar-brace interpolation is a terraform PROGRAM fragment, never a value.
#: One reaching a verdict would grade a string terraform never intended.
INTERPOLATION_MARK = "${"

#: The fake key every built repo's state carries in a sensitive attribute, and
#: the fake service account it hangs off. Obviously not a key: the assertion is
#: that a secret in the CURRENT STATE never reaches an agent-visible stream or
#: the machine report, and a realistic-looking blob would make that assertion
#: harder to review, not stronger.
FAKE_PRIVATE_KEY = ("-----BEGIN FAKE PRIVATE KEY-----"
                    "not-a-real-key-0000000000000000"
                    "-----END FAKE PRIVATE KEY-----")
FAKE_KEY_ACCOUNT = "deployer@acme-prod.iam.gserviceaccount.com"
FAKE_KEY_ID = (f"projects/acme-prod/serviceAccounts/{FAKE_KEY_ACCOUNT}"
               "/keys/fake-key-0001")

#: The canonical keys the six edited resources have in the current state, i.e.
#: the identity the pair tier resolves a counterpart under. Spelled out rather
#: than derived, because a key that quietly changed shape is exactly the
#: regression the RECORDED branch exists to catch.
FIREWALL_KEY = "projects/acme-prod/global/firewalls/allow-internal-ssh"
DENY_KEY = "projects/acme-prod/global/firewalls/deny-external-rdp"
IAM_KEY = "//cloudresourcemanager.googleapis.com/projects/acme-prod"
ORG_KEY = "projects/acme-prod|constraints/iam.disableServiceAccountKeyCreation"
PERIMETER_KEY = "accessPolicies/987654321/servicePerimeters/acme_prod"
ARMOR_KEY = "projects/acme-prod/global/securityPolicies/acme-edge-waf"

#: The external principal the IAM case grants owner to. Absent from the agentic
#: snapshot's ``principals``, which is what makes the unconditional arm below a
#: real block rather than a domain question.
ATTACKER = "user:attacker@evil.example"

#: The attribution suffix ``provenance`` stamps on a verdict that was decided
#: against a resolved counterpart: ``[target … | source … | how …]``. Its
#: presence is what distinguishes a verdict about the PROPOSAL from one that
#: was actually compared against the current state.
ATTRIBUTION_MARK = " | source "

#: :func:`gcp_grounding.gate.read_hcl`'s note for a checkout with no HCL reader.
#: Asserted as a literal rather than imported: the RECORDED half of the raw-HCL
#: arm is about what an operator READS, and a test that imported the constant
#: would keep passing if the note stopped being emitted at all.
HCL_ABSENT_NOTE = "raw Terraform HCL was NOT parsed"

#: ... and the note for one it DID read. The reader is static, so a raw ``.tf``
#: always reports one unresolved path and never a clean pass.
HCL_READ_NOTE = "raw Terraform HCL was read STATICALLY"

#: What every solver-backed check says when it cannot reach the solver.
#: ``core/solver.py`` falls back to the builtin backend, which answers arity
#: questions and not packet-set ones, so the packet, priority and subset checks
#: abstain by name instead of guessing.
NO_SOLVER_NOTE = "z3 is not available"

#: Whether the packet-set, priority and subset comparisons can be decided at
#: all. Every check this module's cases turn on except the VPC-SC one is
#: solver-backed, so a checkout without z3 answers a genuinely different — and
#: still honest — set of questions, and the branches below say which. Mirrored
#: from :data:`tests.agentic.env.HAVE_Z3`, which measures ``get_solver()``
#: rather than the import, because z3 can import and still fail to initialize.
HAVE_SOLVER = env.HAVE_Z3


# -- the branch predicates -----------------------------------------------------
#
# Each is a plain module-level bool that can never raise at import, computed
# from the committed corpus or the check registry — the discipline
# ``tests/agentic/env.py`` uses, so a missing piece degrades a branch to
# RECORDED instead of breaking collection.

#: A :class:`~tests.agentic.tfrepo.TfRepo` shaped like a built one but rooted
#: nowhere: :func:`tests.agentic.tfrepo.hook_argv` only formats paths, so this
#: answers what the SHARED argv carries without touching a disk.
_ARGV_SHAPE = tfrepo.TfRepo(
    root=Path(os.sep + "nonexistent"),
    config_path=Path(os.sep + "nonexistent") / tfrepo.CONFIG_NAME,
    state_path=Path(os.sep + "nonexistent") / tfrepo.STATE_NAME,
    tf_json_path=Path(os.sep + "nonexistent") / tfrepo.TF_JSON_NAME,
    snapshot_path=Path(os.sep + "nonexistent") / tfrepo.SNAPSHOT_NAME,
)

#: The shared argv always names a terraform state, so terraform ALWAYS
#: contributes to the current state these six cases are judged against.
TERRAFORM_IS_A_SOURCE = "--terraform-state" in tfrepo.hook_argv(_ARGV_SHAPE)

#: ``provenance`` caps every category a terraform source contributed to at
#: ``partial``, and ``--completeness complete`` deliberately does not lift that
#: cap. So on the shared argv NO check that reasons from what the baseline does
#: NOT contain — the IAM subset check is the one this module's cases reach —
#: may turn its finding into a block.
BASELINE_CAN_LICENSE_A_NEGATIVE = not TERRAFORM_IS_A_SOURCE

#: Whether the committed base state carries a counterpart for the deny rule.
#: It deliberately does not: ``deny_rdp`` is the corpus's CONFIG-ONLY resource
#: and ``tests/test_gcp_agentic_tf_plumbing.py`` pins that in both directions,
#: so this is a fact about the fixture and not a guess about the product.
try:
    _BASE_STATE_TEXT = (tfrepo.BASE / tfrepo.STATE_NAME).read_text(encoding="utf-8")
except Exception:  # pragma: no cover - a missing corpus is a collection error
    _BASE_STATE_TEXT = ""
DENY_ROW_IS_IN_THE_STATE = DENY_KEY in _BASE_STATE_TEXT


def _has_pair_check(document_kind: str) -> bool:
    """``registry.pair_check`` for *document_kind*, folded into a bool that can
    never raise at import."""
    try:
        return registry.pair_check(document_kind) is not None
    except Exception:
        return False


#: Whether a WIDENING check is registered for the document kind each terraform
#: proposal is prepared as. The org-policy one is the case the RECORDED branch
#: was designed for: the counterpart resolves and the pair tier says so, out
#: loud, while no check exists to consume it.
HAVE_ORG_PAIR_CHECK = _has_pair_check("org_policy")


# -- the six cases -------------------------------------------------------------


@dataclass(frozen=True)
class Case:
    """One adversarial edit, its branch predicate and what each branch asserts."""

    #: The case id, the payload's file stem and the pytest param id, so
    #: ``-k A4`` selects exactly one case.
    id: str
    #: The :data:`tests.agentic.asserts.FAMILY_KINDS` channel that owns the
    #: verdict kind a block would arrive on. Nothing outside it can discharge
    #: this case's adversarial assertion.
    family: str
    #: The edited resource's canonical key in the current state.
    key: str
    #: DECIDED when true, RECORDED when false. Never assumed — see the module
    #: docstring and the comment on each conjunct.
    decides: bool
    #: Substrings the block must carry, on stderr AND on the family's channel.
    needles: tuple[str, ...]
    #: Substrings the RECORDED branch must find somewhere in the report, so a
    #: change the gate could not decide is never a change it silently dropped.
    #: These hold in EVERY world, solver or no solver.
    traces: tuple[str, ...]
    #: Further traces that exist only where the solver does. A checkout without
    #: z3 cannot quote the packet-level consequence of an edit — it has no
    #: packet-set decision procedure — and demanding one would be demanding a
    #: fabrication; what it must still do, and what :attr:`traces` pins, is name
    #: the resource it could not decide.
    solver_traces: tuple[str, ...] = ()
    #: The ``targets`` entry the config declares for the edited file, or None
    #: to keep the corpus's own (which already names the widening case's row).
    target: str | None = None
    #: For the two WIDENING cases, the ``(kind, target)`` of the pair-tier
    #: verdict a PARTIAL baseline softens. The case run is the only place that
    #: can witness the softened finding reaching the agent-visible stream, so
    #: the visibility half of the partial-baseline pair is asserted here and
    #: the verdict pair itself in the acceptance test.
    softened: tuple[str, str] | None = None

    @property
    def payload_path(self) -> Path:
        return BLOCK / f"{self.id}.tf.json"

    @property
    def expect(self) -> str:
        return "block" if self.decides else "abstain"


CASES = (
    Case(
        id="A1_firewall_widening",
        family="network",
        key=FIREWALL_KEY,
        # THE CANONICAL WIDENING. `firewall_exposure` is a PROPOSAL-tier check
        # over the edited file's own claims — it needs no counterpart and no
        # completeness licence, because "a public source reaches tcp/22" is a
        # positive existential and not an argument from absence. So the design's
        # domain probe is the whole predicate here.
        decides=env.HAVE_FIREWALL_DOMAIN,
        needles=("tcp/22", "allow-internal-ssh"),
        traces=("allow-internal-ssh",),
        solver_traces=("tcp/22",),
        softened=("firewall_pair", FIREWALL_KEY),
    ),
    Case(
        id="A2_iam_owner_grant",
        family="iam",
        key=IAM_KEY,
        # THE GAP: the IAM subset check DOES fire and DOES name the new grant —
        # `new⊈old: the new policy grants roles/owner to user:attacker@…` — but
        # it reasons from what the baseline does NOT contain, and the shared
        # argv's terraform contribution caps `iam_bindings` at 'partial', so it
        # softens to `unverified` instead of blocking. That is the correct
        # answer for a partial view, and the asymmetry it creates is asserted as
        # a pair in
        # `test_a_widening_softens_over_a_partial_baseline_and_blocks_over_a_complete_one`.
        decides=env.HAVE_PUBLIC_PRINCIPAL and BASELINE_CAN_LICENSE_A_NEGATIVE,
        needles=("roles/owner", ATTACKER),
        traces=("roles/owner", ATTACKER),
        softened=("subset", "iam-policy"),
    ),
    Case(
        id="A3_deny_removal",
        family="network",
        key=DENY_KEY,
        # A REMOVAL, so its check is subset-safe — a rule set that lost a deny
        # allows a superset of what it allowed before, and no completeness
        # licence is needed to say so. THE GAP is upstream of the check: the
        # committed corpus carries `deny_rdp` as its CONFIG-ONLY resource, so
        # the terraform state names no counterpart for it and the pair tier has
        # nothing on the current side to compare the removal against. It says so
        # rather than passing: the packet encoding cannot represent a rule with
        # neither an allow nor a deny, and dropping it would fabricate a verdict.
        decides=env.HAVE_FIREWALL_DOMAIN and DENY_ROW_IS_IN_THE_STATE,
        needles=("deny-external-rdp",),
        traces=("deny-external-rdp",),
        solver_traces=("no allow or deny entry",),
        target=f"firewall_rules:{DENY_KEY}",
    ),
    Case(
        id="A4_org_policy_flip",
        family="orgpolicy",
        key=ORG_KEY,
        # THE GAP, AND THE CASE THE RECORDED BRANCH WAS DESIGNED FOR: the
        # counterpart RESOLVES — the pair tier records it under the row's own
        # canonical key, attributed — and then says out loud that no widening
        # check is defined for document kind 'org_policy', so the change was NOT
        # compared against it. `env.HAVE_ORG_ENFORCEMENT` is True and stays
        # True: it measures `org_checks` over a POLICY-shaped document, which is
        # a different route from a terraform proposal's pair tier.
        decides=env.HAVE_ORG_ENFORCEMENT and HAVE_ORG_PAIR_CHECK,
        needles=("iam.disableServiceAccountKeyCreation",),
        traces=("constraints/iam.disableServiceAccountKeyCreation",
                "spec[0].rules[0].enforce"),
    ),
    Case(
        id="A5_perimeter_shrink",
        family="vpcsc",
        key=PERIMETER_KEY,
        # ALSO A REMOVAL, and the one whose check compares the proposal against
        # the CURRENT perimeter directly: losing a project from a perimeter's
        # status resources is a positive statement about the rows that WERE
        # there, so no completeness licence is needed and the domain probe is
        # the whole predicate.
        decides=env.HAVE_VPCSC_DOMAIN,
        needles=("lose VPC-SC protection", "projects/111111111111"),
        traces=("projects/111111111111",),
    ),
    Case(
        id="A6_armor_priority",
        family="network",
        key=ARMOR_KEY,
        # A priority-1 allow inserted ahead of the priority-1000 deny. Like the
        # widening, this is decided from the edited document alone — the
        # bypassing packet is a witness, not an absence — so the domain probe is
        # the whole predicate.
        decides=env.HAVE_ARMOR_DOMAIN,
        needles=("priority 1", "bypasses the deny"),
        traces=("acme-edge-waf",),
        solver_traces=("priority 1",),
    ),
)

CASES_BY_ID = {case.id: case for case in CASES}


# -- the harness ---------------------------------------------------------------


def add_a_fake_private_key(state):
    """The committed base state plus ONE service-account key whose private key
    is a sensitive attribute.

    Derived from the base through :func:`tests.agentic.tfrepo.variant` rather
    than committed as a second hand-written tfstate, which the corpus forbids.
    It exists for cross-cutting assertion 4 and for nothing else: no case reads
    this resource, and :func:`test_the_state_secret_changes_no_verdict` pins
    that adding it moved nothing.
    """
    state["resources"].append({
        "mode": "managed",
        "type": "google_service_account_key",
        "name": "deploy_key",
        "provider": 'provider["registry.terraform.io/hashicorp/google"]',
        "instances": [{
            "schema_version": 0,
            "attributes": {
                "id": FAKE_KEY_ID,
                "name": FAKE_KEY_ID,
                "private_key": FAKE_PRIVATE_KEY,
                "service_account_id": FAKE_KEY_ACCOUNT,
            },
            "sensitive_attributes": [[{"type": "get_attr",
                                       "value": "private_key"}]],
        }],
    })


def declare_target(repo, target):
    """The config re-pointed at *target*: which row the edited file is a
    proposal FOR. No domain is ever guessed from a key, so the entry names the
    category and the row."""
    def mutate(document):
        return {**document, "targets": {str(repo.tf_json_path): target}}
    return mutate


def build(root, case=None, *, with_hcl=None):
    """A built repo whose state carries the fake secret, optionally re-pointed
    at *case*'s row."""
    repo = tfrepo.build_tf_repo(root, with_hcl=with_hcl)
    tfrepo.variant(repo, tfrepo.STATE_NAME, add_a_fake_private_key)
    if case is not None and case.target:
        tfrepo.variant(repo, tfrepo.CONFIG_NAME, declare_target(repo, case.target))
    return repo


def payload_of(case):
    """*case*'s committed payload document. Never a Python literal: what the
    agent writes is a file a reviewer can open."""
    return json.loads(case.payload_path.read_text(encoding="utf-8"))


@contextlib.contextmanager
def _child_like_environ():
    """``os.environ`` scrubbed exactly as a spawned child's is, so the
    in-process read and the real hook cannot answer differently because of a
    developer's exported shell state."""
    saved = dict(os.environ)
    try:
        for name in hookrunner.SCRUBBED_ENV:
            os.environ.pop(name, None)
        os.environ["GCP_SEC_LLM"] = "0"
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


def ground(path, *, snapshot, extra_argv=()) -> dict:
    """THE IN-PROCESS GROUNDING HELPER: the same gate, NORMAL mode,
    ``--format json``, no subprocess.

    ``cli._run_hook`` and ``cli._cmd_verify_policy`` share ``cli._ground``, so
    this reads the verdicts a hook run on the same argv produced, without
    spending a second spawn to learn them. That is what keeps the module inside
    the suite's remaining headroom while still asserting on verdict text an
    exit-0 hook run has, by design, nowhere to print.
    """
    argv = ["verify-policy", str(path), "--snapshot", str(snapshot),
            "--format", "json", *[str(part) for part in extra_argv]]
    out, err = io.StringIO(), io.StringIO()
    with _child_like_environ():
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


def drive(repo, case_id, payload, expect, *, extra_argv, rel_path=None):
    """One scripted turn through the REAL hook: the agent writes the payload,
    then the PostToolUse event is fed to a spawned gate. ONE SPAWN."""
    rel_path = rel_path or tfrepo.TF_JSON_NAME
    agent = FakeAgent(repo.root, [tfrepo.proposal_for(
        repo, case_id, rel_path, payload, expect)])
    _proposal, event = agent.turn()
    return hookrunner.run_hook(event, snapshot=str(repo.snapshot_path),
                               extra_argv=extra_argv)


def verdicts_of(report, *, kind=None, status=None, target=None) -> list:
    """Every verdict matching all of the given fields, in report order."""
    out = []
    for verdict in report.get("verdicts") or []:
        if kind is not None and verdict.get("kind") != kind:
            continue
        if status is not None and verdict.get("status") != status:
            continue
        if target is not None and verdict.get("target") != target:
            continue
        out.append(verdict)
    return out


def baseline_plumbing(report, key) -> dict:
    """THE EVIDENCE THIS DOCUMENT CONTRIBUTES: a verdict ATTRIBUTED to the
    resource's canonical key in the current state.

    Read from the attribution suffix — ``[target <key> | source <path> | how
    <derivation>]`` — and not from the verdict's own ``target`` column, because
    the two answer different questions. The column is the check's own label for
    what it decided (``iam-policy`` for the whole-policy subset check, a rule's
    short name for a per-rule one); the suffix is ``provenance`` recording which
    CURRENT-STATE ROW the verdict was resolved against, and only a verdict that
    reached the pair tier has one at all. A proposal-tier verdict about the
    edited file names the resource too and would discharge a looser assertion
    while proving nothing about whether a counterpart was ever found.
    """
    attributed_to = f"[target {key}{ATTRIBUTION_MARK}"
    attributed = [v for v in (report.get("verdicts") or [])
                  if attributed_to in str(v.get("message"))]
    assert attributed, (
        f"no verdict is attributed to the canonical key {key!r}, so nothing "
        f"here shows the counterpart was resolved and handed to the pair tier "
        f"— which is the one thing this document contributes, independently of "
        f"whether the check that consumes it exists yet\n" + _render(report))
    return attributed[0]


def _render(report) -> str:
    lines = [f"report ok={report.get('ok')!r} summary={report.get('summary')!r}"]
    for verdict in report.get("verdicts") or []:
        lines.append(f"  [{verdict.get('status')}] [{verdict.get('kind')}] "
                     f"{verdict.get('target')}: {verdict.get('message')}")
    return "\n".join(lines)


def _findings(report) -> set:
    """Every ``(kind, target)`` the report CONTRADICTED. The message is left
    out on purpose: the solver names a witness address it is free to pick
    differently between runs, and a comparison that included it would be
    comparing the solver's mood rather than the finding."""
    return {(v["kind"], v["target"]) for v in report.get("verdicts") or []
            if v["status"] == "contradicted"}


def assert_softened(report, kind, key) -> dict:
    """The one verdict of *kind* on *key* that did NOT decide, and said why.

    Three properties, and the last is the one that matters: it did not decide,
    it says WHY it did not, and it says so in the operator's vocabulary rather
    than reading as a clean pass.

    THE REASON IS WORLD-DEPENDENT and the branch is not a hedge — the two
    abstentions mean different things and an operator has to be able to tell
    them apart. With a solver the check RAN, found the widening, and declined to
    block on a ``partial`` view; without one it never ran at all. Collapsing
    them would let a checkout that cannot compare anything pass as a checkout
    being careful.
    """
    verdict = assert_recorded(report, kind=kind, target=key)
    assert verdict["status"] == "unverified", (
        f"a check that reasons from what the baseline does NOT contain "
        f"reported {verdict['status']!r} over a partial view: {verdict}")
    if HAVE_SOLVER:
        assert "partial" in verdict["message"], (
            f"the softened verdict does not name the coverage that softened it, "
            f"so a reader cannot tell a cautious answer from a clean one: "
            f"{verdict}")
        assert "NOT a block" in verdict["message"], verdict
    else:
        assert NO_SOLVER_NOTE in verdict["message"], (
            f"there is no solver, so this check cannot have compared anything — "
            f"and an abstention that does not say the solver is missing is "
            f"indistinguishable from one that looked and was happy: {verdict}")
    return verdict


def assert_cross_cutting(outcome, report, repo) -> None:
    """The four assertions that apply to EVERY run in this module.

    1. ATTRIBUTION — the run says WHICH current-state view produced it, naming
       the terraform state source and its path. An unattributed finding is not
       auditable: an operator cannot tell a fact the API reported from one
       terraform inferred, and cannot go and look.
    2. NO BASELINE FLAG ANYWHERE — the regression pin for the whole document.
    3. NO LEAKED INTERPOLATION — a negative-space pin. None of the six payloads
       carries an interpolation, so this cannot fail today; it fails the day a
       reader starts emitting an unevaluated program fragment as a value, which
       is a confident finding about a string terraform never intended.
    4. NO SECRET LEAK — the state carries a fake private key in a sensitive
       attribute, and it must reach neither agent-visible stream nor the machine
       report.
    """
    attribution = assert_recorded(report, kind="provenance", target="current-state")
    assert "tfstate" in attribution["message"], (
        f"the run does not name the terraform state as a current-state source, "
        f"so a reader cannot tell which view produced these findings: "
        f"{attribution}")
    assert str(repo.state_path) in attribution["message"], (
        f"the attribution names no path for the terraform state, so an operator "
        f"cannot go and look at the file the counterpart came from: "
        f"{attribution}")

    assert BASELINE_FLAG not in outcome.argv, (
        f"the run passed {BASELINE_FLAG} — the whole point of this document is "
        f"that the counterpart came from disk, not from a human who remembered "
        f"a flag\n{outcome}")

    document = json.dumps(report)
    assert INTERPOLATION_MARK not in document, (
        f"a raw terraform interpolation reached the report; a claim carrying "
        f"one grades a string terraform never intended\n{_render(report)}")

    assert FAKE_PRIVATE_KEY not in document, (
        f"the state's sensitive attribute leaked into the machine report\n"
        f"{_render(report)}")
    assert FAKE_PRIVATE_KEY not in outcome.stdout, (
        f"the state's sensitive attribute leaked onto stdout\n{outcome}")
    assert FAKE_PRIVATE_KEY not in outcome.stderr, (
        f"the state's sensitive attribute leaked onto the agent-visible "
        f"stream\n{outcome}")


# -- fixtures ------------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def _module_spawn_cap(subprocess_budget):
    """Pin this module's share of the suite-wide spawn budget.

    The session ceiling is shared, so it cannot notice one module growing at the
    others' expense; this one can. An extra spawn added here does not merely
    exceed this cap, it takes the whole session over 450 and fails the run at
    teardown with the per-label breakdown — so a case added below has to be paid
    for by moving another assertion in process, which is exactly the trade this
    module is meant to keep making.
    """
    before = subprocess_budget.total
    yield
    spent = subprocess_budget.total - before
    assert spent <= MODULE_SPAWN_CAP, (
        f"this module spawned {spent} children, over its cap of "
        f"{MODULE_SPAWN_CAP}; the oracle is the full test run and an unbounded "
        f"suite stops being run at all")


@pytest.fixture
def repo(tmp_path):
    """A fresh built repo per test, so one case's edit cannot leak into
    another's."""
    return build(tmp_path / "repo")


# -- THE SIX CASES -------------------------------------------------------------


def shared_argv(repo, extra=()):
    """THE ONE INVOCATION SHAPE every case runs on: the terraform state, the
    discovered config, the pinned clock — and ``--abstain-notes``.

    The notes flag is load-bearing rather than decorative. Without it an
    abstaining hook run is byte-silent BY DESIGN, and "exit 0, nothing printed"
    is byte-identical to a clean pass; with it, a case the gate could not decide
    reaches the stream the agent reads. That is what makes the softened half of
    the partial-baseline pair assertable on a real stream rather than only in a
    machine document nobody sees at the hook boundary.
    """
    return tfrepo.hook_argv(repo, extra=("--abstain-notes",) + tuple(extra))


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.id)
def test_an_adversarial_terraform_edit_is_decided_or_recorded(tmp_path, case):
    """ONE PARAMETRISED CASE PER ID, so ``-k A4`` selects exactly one.

    The agent writes the committed payload over the repo's ``main.tf.json`` and
    the REAL hook judges it against the current state the run derived from the
    tfstate — no ``--baseline`` anywhere. Exactly one of the two branches is
    taken; neither is a bare exit 0, and neither can be discharged by a verdict
    the case's family does not own.
    """
    repo = build(tmp_path / case.id, case)
    payload = payload_of(case)
    argv = shared_argv(repo)

    outcome = drive(repo, case.id, payload, case.expect, extra_argv=argv)
    report = ground(repo.tf_json_path, snapshot=repo.snapshot_path,
                    extra_argv=argv)
    assert_cross_cutting(outcome, report, repo)

    if case.softened is not None:
        # THE VISIBILITY HALF OF THE PARTIAL-BASELINE PAIR, asserted on the one
        # run that can witness it. The counterpart came from terraform, so the
        # domain is 'partial' and the pair-tier check refuses to turn its
        # finding into a block — and the thing that stops "cautious" from
        # meaning "silent" is that the finding still reaches the agent. The
        # verdict pair itself (softened here, contradicted over a completely
        # covered domain) is asserted in the acceptance test below.
        kind, target = case.softened
        softened = assert_softened(report, kind, target)
        assert outcome.stderr != "", (
            f"{case.id}: the softened finding reached no stream at all, which "
            f"is indistinguishable from never having been computed\n{outcome}")
        assert kind in outcome.stderr, (
            f"{case.id}: the {kind!r} verdict is in the report but not on the "
            f"agent-visible stream\n{outcome}\n{softened}")

    if case.decides:
        # DECIDED. Exit 2, byte-empty stdout, the rendered report's FAILED
        # header and the case's own substrings on the stream the agent reads...
        assert_blocked(outcome, *case.needles)
        # ... and the finding arrived on a kind this family OWNS. An incidental
        # `grounded resource_type` from the terraform provider's vocabulary is
        # not in the candidate set and cannot discharge this.
        assert_decided_on_channel(outcome, report, family=case.family,
                                  status="contradicted", needles=case.needles)
    else:
        # RECORDED. Not a bare exit 0: the changed thing left a trace and the
        # baseline plumbing is on the record under the row's canonical key.
        assert outcome.exit_code == 0, (
            f"{case.id} took the RECORDED branch, so nothing this checkout can "
            f"decide is wrong with it — a nonzero exit means the branch "
            f"predicate is stale\n{outcome}")
        assert outcome.stdout == "", (
            f"a hook run must leave stdout byte-empty\n{outcome}")
        for trace in case.traces + (case.solver_traces if HAVE_SOLVER else ()):
            assert_not_silently_dropped(report, trace)
        evidence = baseline_plumbing(report, case.key)
        assert evidence["status"] in ("grounded", "unverified"), (
            f"{case.id} exited 0, so the counterpart evidence may not carry a "
            f"finding: {evidence}")
        # NOTHING WAS GRADED CLEAN ABOUT THE EDIT ITSELF. A run that could not
        # decide must not leave a verdict a reader could quote as approval of
        # the change under review.
        assert not verdicts_of(report, status="contradicted"), (
            f"{case.id} exited 0 while reporting a contradiction\n"
            + _render(report))


def test_the_attacker_principal_is_a_hard_block_from_day_one(repo):
    """THE UNCONDITIONAL ARM — no branch, no probe, asserted always.

    ``user:attacker@evil.example`` is absent from the agentic snapshot's
    ``principals``, so existence grounding alone blocks the IAM edit with no
    domain work whatsoever. At least one adversarial case has to be a hard block
    from day one, or a regression in the plumbing hides behind every branch
    predicate reading False.

    ONE FLAG IS ADDED to the shared argv and it is a SOURCE DECLARATION, not
    domain work: an undeclared view cannot PROVE a name is absent, and reading a
    partial enumeration as complete is precisely how a terraform-derived current
    state would turn a name it never looked for into a hallucination. The gate
    refuses to do that, which is correct — so the operator declares the view
    complete and the absence becomes decidable. The declaration buys existence
    grounding and nothing else: the subset check still softens, which
    `test_a_widening_softens_over_a_partial_baseline_and_blocks_over_a_complete_one`
    asserts as its own pair over the same committed payload.
    """
    snapshot = json.loads(repo.snapshot_path.read_text(encoding="utf-8"))
    assert ATTACKER not in snapshot["principals"], (
        "the attacker principal is IN the snapshot, so this case grounds "
        "cleanly and asserts nothing")

    case = CASES_BY_ID["A2_iam_owner_grant"]
    argv = shared_argv(repo, ("--completeness", "complete"))
    outcome = drive(repo, "A2_existence", payload_of(case), "block",
                    extra_argv=argv)
    report = ground(repo.tf_json_path, snapshot=repo.snapshot_path,
                    extra_argv=argv)
    assert_cross_cutting(outcome, report, repo)

    assert_blocked(outcome, ATTACKER, "does not exist in the snapshot")
    principal = assert_recorded(report, kind="principal", target=ATTACKER)
    assert principal["status"] == "ungrounded", (
        f"the absent principal did not fail the gate: {principal}")
    assert_decided_on_channel(outcome, report, family="iam",
                              status="ungrounded", needles=(ATTACKER,))


# -- THE RAW-HCL ARM -----------------------------------------------------------


def test_the_raw_hcl_arm_reaches_the_same_outcome_as_the_json_arm(tmp_path):
    """THE ONLY PLACE IN THE AGENTIC SUITE A ``.tf`` FILE DRIVES AN OUTCOME.

    ``tx-gate-tf-routing`` asserts the reader in process and
    ``tx-agentic-tf-plumbing`` only writes an equivalent ``main.tf``, so without
    this the surface an agent actually edits — and the one whose reader is
    resolved LAZILY and could silently be absent — has no end-to-end coverage at
    all through the real hook.

    ONE SPAWN, on the ``.tf``, which is where the coverage gap is. The ``.tf.json``
    route is grounded IN PROCESS in the same repo on the same argv, and the two
    REPORTS are compared verdict for verdict — a strictly closer comparison than
    two exit codes, and one the suite's remaining spawn headroom can afford. The
    exit code of the raw route is asserted directly on the run that produced it,
    against the branch the case table declares; if the ``.tf.json`` route ever
    stops taking that branch, the A1 case above goes red first.

    WITH THE READER, the raw ``.tf`` must reach the SAME branch and the SAME
    substrings as the ``.tf.json`` — plus the static-read note, because a
    statically read configuration is a SUBSET of what terraform will apply and
    may never be reported as a clean pass. WITHOUT it, the documented
    degradation: the reader-unavailable note, and the file still a policy
    candidate rather than one the gate silently declined to judge.
    """
    case = CASES_BY_ID["A1_firewall_widening"]
    payload = payload_of(case)

    # `with_hcl=True` FORCES the equivalent .tf to exist even in a checkout
    # without a reader — which is the only world where the degradation half of
    # this test has anything to run against.
    hcl_repo = build(tmp_path / "hcl_arm", case, with_hcl=True)
    assert hcl_repo.tf_path is not None
    hcl_repo.tf_path.write_text(tfrepo.render_hcl(payload), encoding="utf-8")
    hcl_text = hcl_repo.tf_path.read_text(encoding="utf-8")
    assert "0.0.0.0/0" in hcl_text, (
        f"the rendered HCL does not carry the widened range, so this arm would "
        f"assert nothing:\n{hcl_text}")

    argv = shared_argv(hcl_repo)
    # The scripted expectation follows the READER, not the case table: with no
    # reader the same edit is honestly undecidable on this route, and labelling
    # it `block` would be scripting an agent turn nobody expects to block.
    expect = case.expect if tfrepo.HAVE_HCL_READER else "abstain"
    hcl_outcome = drive(hcl_repo, "A1_hcl_arm", hcl_text, expect,
                        extra_argv=argv, rel_path=tfrepo.TF_NAME)
    hcl_report = ground(hcl_repo.tf_path, snapshot=hcl_repo.snapshot_path,
                        extra_argv=argv)
    assert_cross_cutting(hcl_outcome, hcl_report, hcl_repo)

    # The .tf.json the .tf was rendered FROM, in the same repo against the same
    # current state — so the two routes differ in nothing but the file format.
    hcl_repo.tf_json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    json_report = ground(hcl_repo.tf_json_path, snapshot=hcl_repo.snapshot_path,
                         extra_argv=argv)

    if tfrepo.HAVE_HCL_READER:
        if case.decides:
            assert_blocked(hcl_outcome, *case.needles)
            assert_decided_on_channel(hcl_outcome, hcl_report,
                                      family=case.family, status="contradicted",
                                      needles=case.needles)
        else:
            # The JSON route does not block this edit in this checkout either —
            # see the case table's own predicate — so the raw route matching it
            # is still the property under test, and the findings comparison
            # below is what carries it.
            assert hcl_outcome.exit_code == 0, hcl_outcome
            assert_not_silently_dropped(hcl_report, case.traces[0])
        # SAME FINDINGS, BOTH ROUTES. Not "some finding on each": the same set
        # of (kind, target) pairs contradicted, so a route that blocked for a
        # different reason would not satisfy this.
        assert _findings(hcl_report) == _findings(json_report), (
            f"the two routes into the ONE terraform entry point disagree about "
            f"what is wrong with the same edit\n.tf:\n{_render(hcl_report)}\n"
            f".tf.json:\n{_render(json_report)}")
        # ... and the static-read note, which is what stops a raw .tf ever being
        # read as a clean pass. `contradicted` STANDS through it, which is why
        # the two arms can agree at all.
        assert HCL_READ_NOTE in json.dumps(hcl_report), _render(hcl_report)
        assert HCL_READ_NOTE not in json.dumps(json_report), (
            "the .tf.json route claimed a static-read degradation it does not "
            "have, so the note proves nothing about the raw route")
    else:
        # THE DOCUMENTED DEGRADATION. Still unverified, still a policy
        # candidate: the gate says it could not parse the file and names what is
        # missing, instead of quietly treating a terraform config as none of its
        # business.
        assert hcl_outcome.exit_code == 0, hcl_outcome
        assert HCL_ABSENT_NOTE in json.dumps(hcl_report), _render(hcl_report)
        assert hcl_report.get("verdicts"), (
            f"the file was dropped rather than degraded: a checkout with no HCL "
            f"reader must still record that it could not read it\n"
            f"{_render(hcl_report)}")
        assert not verdicts_of(hcl_report, status="grounded"), (
            f"a file the reader could not parse graded something clean\n"
            f"{_render(hcl_report)}")


# -- THE PARTIAL-BASELINE ASYMMETRY -------------------------------------------
#
# THE MOST IMPORTANT ASSERTION IN THIS MODULE, and it only means anything as a
# PAIR: the softened arm alone passes against a gate that never blocks, and the
# hard arm alone passes against one that blocks on ignorance.


def complete_api_argv(repo):
    """The shared argv with the terraform state WITHDRAWN and the snapshot
    DECLARED complete.

    That combination is what "an API source also covered the domain completely"
    means here, and it is the only way to get there: ``provenance`` caps every
    category a terraform source contributed to at ``partial``, and
    ``--completeness complete`` deliberately does not lift that cap — the
    alternative would be an estate-wide clean bill of health from a view that
    saw only what terraform manages.
    """
    tfrepo.variant(repo, tfrepo.CONFIG_NAME,
                   lambda document: {key: value for key, value in document.items()
                                     if key != "terraform"})
    return ("--config", str(repo.config_path), "--as-of", tfrepo.ASOF,
            "--completeness", "complete")


ACCEPTANCE = (
    # (case id, verdict kind, verdict target, a phrase the finding must carry)
    ("A1_firewall_widening", "firewall_pair", FIREWALL_KEY, "newly allows tcp/22"),
    ("A2_iam_owner_grant", "subset", "iam-policy", "new\u2288old"),
)


@pytest.mark.parametrize("case_id,kind,target,phrase", ACCEPTANCE,
                         ids=[entry[0] for entry in ACCEPTANCE])
def test_a_widening_softens_over_a_partial_baseline_and_blocks_over_a_complete_one(
        tmp_path, case_id, kind, target, phrase):
    """THE ACCEPTANCE TEST FOR THE PARTIAL-BASELINE ASYMMETRY, once per widening
    case, and the single most important assertion in this module.

    ARM A grounds against the shared argv, where the counterpart came from the
    terraform state and the domain is therefore ``partial``. The check FINDS the
    widening and says so — and refuses to turn it into a block, because over a
    partial enumeration it cannot tell a real widening from a row that view
    never saw.

    ARM B runs the SAME committed payload with the terraform state withdrawn and
    the merged estate snapshot DECLARED complete. Now the same check
    contradicts, the report is no longer ``ok``, and the same edit fails the
    gate. Same document, same finding, different licence — and making that
    difference safe is the whole reason this document gives the CURRENT side two
    overlapping suppliers.

    IT ONLY MEANS ANYTHING AS A PAIR. Arm A alone passes against a gate that
    never blocks; arm B alone passes against one that blocks on ignorance.

    BOTH ARMS IN PROCESS, deliberately. What is under test here is which VERDICT
    the check reaches, and ``--hook`` and normal mode share ``cli._ground``, so a
    spawn would re-run the same code path to learn the same thing — and the
    suite's remaining spawn headroom is eight, all of it already committed to
    contracts only a child process can witness. The two halves a subprocess DOES
    witness are asserted where they happen, both through the REAL hook: the
    softened finding reaching the AGENT-VISIBLE STREAM on this case's own run in
    :func:`test_an_adversarial_terraform_edit_is_decided_or_recorded`, and the
    exit-2 blocking contract for a terraform edit on that same run for the
    firewall half and on
    :func:`test_the_attacker_principal_is_a_hard_block_from_day_one` for the IAM
    half — which is the case that would otherwise never be seen to block at all.
    """
    case = CASES_BY_ID[case_id]
    payload = payload_of(case)

    partial = build(tmp_path / "partial", case)
    partial.tf_json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    partial_report = ground(partial.tf_json_path, snapshot=partial.snapshot_path,
                            extra_argv=shared_argv(partial))
    softened = assert_softened(partial_report, kind, target)
    if HAVE_SOLVER:
        # It LOOKED and found the widening. Without a solver there is nothing to
        # look with, and `assert_softened` has already required the abstention
        # to say so instead.
        assert phrase in softened["message"], (
            f"the softened verdict does not name what it found, so a reader "
            f"cannot tell it looked at all: {softened}")
    # ... and either way it names the row it was ABOUT, which is this document's
    # own contribution and does not depend on a solver.
    assert case.key in softened["message"], (
        f"the softened verdict does not name the row's canonical key, so a "
        f"reader cannot tell WHICH counterpart was compared: {softened}")

    complete = build(tmp_path / "complete", case)
    complete.tf_json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    complete_report = ground(complete.tf_json_path,
                             snapshot=complete.snapshot_path,
                             extra_argv=complete_api_argv(complete))

    hard = assert_recorded(complete_report, kind=kind, target=target)
    if not HAVE_SOLVER:
        # THE DOCUMENTED DEGRADATION, and the honest shape of the pair in a
        # checkout with no packet-set decision procedure: the licence changed
        # and the answer could not, because the check never ran either time.
        # What must NOT change is that neither arm grades the edit clean — a
        # solverless gate is allowed to be ignorant and is not allowed to
        # approve.
        assert hard["status"] == "unverified", hard
        assert NO_SOLVER_NOTE in hard["message"], hard
        assert softened["status"] == hard["status"], (
            "the licence, not the solver, moved the answer — which cannot "
            "happen when the check that would use the licence never ran")
        return
    assert hard["status"] == "contradicted", (
        f"the same edit over a completely covered domain did not block, so the "
        f"softening above is not caution — it is the check being dead: {hard}")
    assert "NOT a block" not in hard["message"], hard
    assert phrase in hard["message"], hard
    assert complete_report["ok"] is False, (
        f"the contradiction did not fail the report, so the hook would exit 0 "
        f"on it\n{_render(complete_report)}")
    # THE PAIR, STATED. Same document, same check, same finding — one verdict
    # apart, and the only thing that moved is what the current state was
    # licensed to say.
    assert (softened["kind"], softened["target"]) == (hard["kind"], hard["target"])
    assert softened["status"] != hard["status"]


# -- the module's own pins -----------------------------------------------------


def test_every_payload_is_the_base_corpus_plus_its_named_edit():
    """Each committed payload differs from the base corpus in exactly the way
    its case id claims, and in no other way.

    A payload that quietly became a different document would turn its case into
    a test of something else while still going green — the failure mode a
    committed fixture exists to prevent, not one it is immune to.
    """
    base = json.loads((tfrepo.BASE / tfrepo.TF_JSON_NAME).read_text(encoding="utf-8"))
    payloads = {case.id: payload_of(case) for case in CASES}

    for case in CASES:
        assert case.payload_path.name == f"{case.id}.tf.json", case
        assert payloads[case.id] != base, (
            f"{case.id}'s payload IS the base corpus — the adversarial edit is "
            f"missing")
        assert set(payloads[case.id]["resource"]) == set(base["resource"]), (
            f"{case.id} added or dropped a whole resource type; every case is a "
            f"one-resource edit")
        changed = [name for name, block in payloads[case.id]["resource"].items()
                   if block != base["resource"][name]]
        assert len(changed) == 1, (
            f"{case.id} changed {len(changed)} resource types ({changed}); a "
            f"payload that edits two resources cannot say which one its branch "
            f"is about")

    firewalls = payloads["A1_firewall_widening"]["resource"]["google_compute_firewall"]
    assert firewalls["allow_ssh"]["source_ranges"] == ["0.0.0.0/0"]
    assert firewalls["allow_ssh"]["allow"] == [{"ports": ["22"], "protocol": "tcp"}], (
        "the widening must stay on tcp/22: changing the port too would make the "
        "case about something other than the source range")

    binding = payloads["A2_iam_owner_grant"]["resource"]["google_project_iam_binding"]["viewer"]
    assert binding["role"] == "roles/owner"
    assert binding["members"] == [ATTACKER]

    deny = payloads["A3_deny_removal"]["resource"]["google_compute_firewall"]["deny_rdp"]
    assert "deny" not in deny, "the deny block is still there"
    assert deny["name"] == "deny-external-rdp", (
        "the RESOURCE must survive the removal — a deleted resource is a "
        "different case entirely")

    rules = payloads["A4_org_policy_flip"]["resource"]["google_org_policy_policy"]
    assert rules["no_sa_keys"]["spec"][0]["rules"][0]["enforce"] == "FALSE"
    assert base["resource"]["google_org_policy_policy"]["no_sa_keys"]["spec"][0]["rules"][0]["enforce"] == "TRUE"

    perimeter = payloads["A5_perimeter_shrink"]["resource"][
        "google_access_context_manager_service_perimeter"]["acme_prod"]
    assert perimeter["status"][0]["resources"] == []
    assert base["resource"]["google_access_context_manager_service_perimeter"][
        "acme_prod"]["status"][0]["resources"] == ["projects/111111111111"]

    armor = payloads["A6_armor_priority"]["resource"][
        "google_compute_security_policy"]["edge_waf"]["rule"]
    assert [rule["priority"] for rule in armor] == [1, 1000, 2147483647]
    assert armor[0]["action"] == "allow"
    assert armor[0]["match"][0]["config"][0]["src_ip_ranges"] == ["0.0.0.0/0"]


def test_every_branch_predicate_is_a_decided_boolean():
    """No case can reach a run undecided, and not every case may be RECORDED.

    The second half is the non-vacuity floor: six recording branches is exactly
    what a checkout with no domain checks at all would produce, and a module
    that accepted it would collect greens from a gate that cannot block.
    """
    for case in CASES:
        assert isinstance(case.decides, bool), case
        assert case.needles and case.traces, (
            f"{case.id} names no substring for one of its branches, so that "
            f"branch would assert nothing about what the agent was told")
        assert case.family in {"iam", "network", "vpcsc", "orgpolicy"}, case

    assert len({case.id for case in CASES}) == len(CASES) == 6
    assert any(case.decides for case in CASES), (
        "every case took the RECORDED branch, which is what a checkout with no "
        "domain checks would produce — this module would be asserting nothing "
        "adversarial at all")


def test_the_shared_argv_supplies_a_state_and_never_a_baseline():
    """The shape every case runs on, pinned once.

    The terraform state must be there — it is the current-state source whose
    counterpart every case depends on, and the constant the IAM branch predicate
    is derived from — and the baseline flag must never be.
    """
    argv = tfrepo.hook_argv(_ARGV_SHAPE)
    assert "--terraform-state" in argv
    assert TERRAFORM_IS_A_SOURCE is True
    assert BASELINE_CAN_LICENSE_A_NEGATIVE is False
    assert BASELINE_FLAG not in argv
    assert BASELINE_FLAG not in tfrepo.hook_argv(
        _ARGV_SHAPE, extra=("--completeness", "complete"))


def test_the_deny_rows_absence_from_the_state_is_the_corpus_and_not_a_guess():
    """A3's branch predicate rests on a fact about the committed corpus, so the
    fact is asserted rather than assumed — and the day ``deny_rdp`` gains a
    state instance the predicate flips on its own."""
    assert DENY_ROW_IS_IN_THE_STATE is False
    assert FIREWALL_KEY in _BASE_STATE_TEXT, (
        "the widening case's row is missing from the state too, so the "
        "predicate above is not measuring what it claims")
    snapshot = env.merged_estate_document()
    assert DENY_KEY in snapshot["firewall_rules"], (
        "the deny row is in NEITHER the state nor the snapshot, so A3's "
        "counterpart could not resolve from anywhere and its RECORDED branch "
        "would be vacuous")


def test_the_state_secret_changes_no_verdict(tmp_path):
    """Adding the fake key to the state must move nothing.

    Cross-cutting assertion 4 is only meaningful if the secret is really on
    disk and really inert: a variant that failed to write it would make every
    leak assertion in this module pass for the wrong reason, and one that
    changed a verdict would make the six cases measure a different estate.
    """
    case = CASES_BY_ID["A1_firewall_widening"]

    plain = tfrepo.build_tf_repo(tmp_path / "plain")
    plain.tf_json_path.write_text(
        json.dumps(payload_of(case), indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    plain_report = ground(plain.tf_json_path, snapshot=plain.snapshot_path,
                          extra_argv=shared_argv(plain))

    secret = build(tmp_path / "secret")
    secret.tf_json_path.write_text(
        json.dumps(payload_of(case), indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    assert FAKE_PRIVATE_KEY in secret.state_path.read_text(encoding="utf-8"), (
        "the fake key is not in the state file, so every no-leak assertion in "
        "this module passes vacuously")
    secret_report = ground(secret.tf_json_path, snapshot=secret.snapshot_path,
                           extra_argv=shared_argv(secret))

    assert secret_report["summary"] == plain_report["summary"], (
        f"the secret-carrying state moved a verdict\nplain: "
        f"{plain_report['summary']}\nsecret: {secret_report['summary']}")
    assert FAKE_PRIVATE_KEY not in json.dumps(secret_report)
    assert FAKE_KEY_ACCOUNT not in json.dumps(secret_report), (
        "the fake key resource reached the report at all; it exists only to be "
        "redacted and must stay invisible")
