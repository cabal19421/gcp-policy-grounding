"""The APPEND-ONLY register of INTEGRATOR re-pins and frozen-path edits.

WHY THIS FILE EXISTS. Merging 135 task branches into one tree turns some
branch-authored expectations false: a branch asserts "no checker decides this
kind", a later branch lands the checker; a branch asserts "the run abstains", a
routing decision makes the same run carry a real finding. House rule 2 says an
integrator may not resolve that by picking a winner in silence, and house rule 4
gives the escape hatch a NAME — but the hatch in `tests/escalations.py` is
xfail-governed: it fits an expectation that must survive as a requirement, not
one that a landed capability has genuinely SUPERSEDED.

Three integration commits re-pinned expectations and their messages claimed each
was "recorded as an escalation". That record did not exist: `ESCALATIONS` carried
no such entry, and a claim of a record is worse than no record, because it stops
the next reader looking. This register is that record, made real and testable:

* every entry names the NODE, the branch whose text lost, both texts VERBATIM,
  and the MEASUREMENT that decided it — never an opinion, never "it seemed";
* `tests/test_gcp_integration_repins.py` (this file's self-test) asserts the
  ``integrated`` text really is in the module today, so an entry cannot describe
  a tree that no longer exists;
* an entry whose ``escalation_id`` is set must have its branch text LANDED in
  that module under ``xfail(strict=True)``, and the id must be registered in
  `tests/escalations.py`. An entry with no ``escalation_id`` must have branch
  text that is ABSENT — a superseded expectation, not a parked one — and must say
  in ``superseded_by`` what landed to supersede it.

WHAT AN ENTRY IS NOT. It is not permission. Nothing here relaxes an assertion,
and no entry may be added for a case where BOTH sides still hold: that is a
union, and a union needs no record. The test of a good entry is that a reader who
disagrees with it can run the measurement and say so.

:data:`FROZEN_PATH_EDITS` is the second register, for the sharper case: an edit to
a path that is FROZEN for every task. That is not a re-pin and it is not
excusable by one, so its entries carry the blob the branches carry, the blob the
tree carries, and what would close the divergence — and the self-test recomputes
the tree's blob on every run, so the frozen path cannot drift one byte further
without this record being updated or the edit reverted.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Repin:
    """One branch-authored expectation an integrator changed, and the proof.

    ``id``            stable handle for review to cite.
    ``node_id``       the pytest node whose expectation changed.
    ``branch``        the ref that authored the text that lost.
    ``branch_text``   that text, VERBATIM.
    ``integrated``    the text standing in the tree today, VERBATIM.
    ``measurement``   what was RUN, and what it answered.
    ``kept``          the assertions carrying the branch's intent afterwards —
                      an integrator who changes a pin and adds nothing has
                      deleted coverage, whatever the commit message says.
    ``escalation_id`` the `tests/escalations.py` id under which ``branch_text``
                      is landed strict-xfailed; empty when the expectation is
                      genuinely superseded rather than parked.
    ``superseded_by`` what landed that makes ``branch_text`` false. Required
                      when ``escalation_id`` is empty.
    """

    id: str
    node_id: str
    branch: str
    branch_text: str
    integrated: str
    measurement: str
    kept: str
    escalation_id: str = ""
    superseded_by: str = ""


@dataclass(frozen=True)
class FrozenPathEdit:
    """One edit to a path that is frozen for every task.

    ``path``          repo-relative frozen path.
    ``branch_blob``   the blob every branch carrying this path has.
    ``head_blob``     the blob this tree has. Recomputed by the self-test.
    ``commit``        the commit that made the edit.
    ``what_changed``  the diff, in words a reviewer can check against it.
    ``why_open``      why neither available resolution is takeable here.
    ``what_closes``   the change that would end the divergence, and whose it is.
    """

    path: str
    branch_blob: str
    head_blob: str
    commit: str
    what_changed: str
    why_open: str
    what_closes: str


REPINS: tuple[Repin, ...] = (
    Repin(
        id="RP-TFBENIGN-PROMISE-ESTATE",
        node_id=("tests/test_gcp_agentic_tf_benign.py::"
                 "test_the_promise_abstains_over_terraform_and_is_live_over_the_estate"),
        branch="agent/tx-agentic-tf-benign",
        branch_text='assert decided["status"] == "contradicted", decided',
        integrated='assert decided["status"] == "unverified", decided',
        measurement=(
            "Arm two rebuilt in-process through the module's own `ground` helper "
            "(cli.main, --completeness complete, estate snapshot beside the "
            "terraform state): the sec:vpc_firewall verdict for the promise comes "
            "back `unverified` naming the collection and the word 'partial', "
            "because `provenance` caps a category any TERRAFORM source "
            "contributed to at 'partial' and the universal-negative gate will not "
            "discharge a promise that reasons from absence over a partial view. "
            "The commit that changed the pin (a72bf27) is also the commit that "
            "routed .tf.json through one terraform entry point, which is what put "
            "a terraform contribution into this arm's firewall_rules category."
        ),
        kept=(
            "The pair's positive half is asserted on the channel where it is real "
            "— `firewall_reopen` contradicts the widening over the estate and is "
            "asserted ABSENT over the terraform-only view — plus "
            "assert_sec_channel_abstained (the promise's own ignorance is on the "
            "record, and nothing on the sec: channel reports grounded/ungrounded/"
            "contradicted out of that same ignorance) and assert_claims_nothing_safe."
        ),
        escalation_id="ESC-GX-TFPROMISE-001",
    ),
    Repin(
        id="RP-TFBENIGN-PROMISE-RUN-BUCKET",
        node_id=("tests/test_gcp_agentic_tf_benign.py::"
                 "test_the_promise_abstains_over_terraform_and_is_live_over_the_estate"),
        branch="agent/tx-agentic-tf-benign",
        branch_text="assert_abstained(tf_outcome, tf_report, PROMISE_COLLECTION)",
        integrated='assert_blocked(tf_outcome, "tcp/22")',
        measurement=(
            "The same hook run over the widened .tf.json exits 2 with a "
            "`firewall_exposure` contradiction naming tcp/22: the file's OWN "
            "claims are extracted now, so the widening edit is a finding in its "
            "own right. The branch's premise was the opposite and is stated in "
            "its module docstring — 'no CLAIM is extracted from a .tf.json' — "
            "which held only while cli._ground prepared the raw {'resource': ...} "
            "body that preflight.detect_kind does not recognize. assert_abstained "
            "is a WHOLE-RUN assertion (it requires exit 0), so it cannot express "
            "'the run blocks while the promise abstains' at all."
        ),
        kept=(
            "Both halves are now asserted where the branch asserted one: "
            "assert_blocked for the run, and assert_sec_channel_abstained — the "
            "same three-bucket assertion narrowed to the sec: kinds — for the "
            "promise, so neither half can hide the other. The exit code is pinned "
            "in both arms rather than only the live one."
        ),
        superseded_by=(
            "The one-terraform-entry-point routing (a72bf27: cli._ground reaches "
            "plan.as_plan_document -> engine.prepare_proposal through "
            "gate.terraform_proposal), which retired the second route the "
            "branch's premise described."
        ),
    ),
    Repin(
        id="RP-D04-WITH-Z3",
        node_id=("tests/test_gcp_agentic_degradation.py::"
                 "test_D04_condition_evasion_abstains_in_both_worlds"),
        branch="agent/sx-agentic-degradation",
        branch_text='assert with_z3["status"] == "unverified", with_z3',
        integrated='assert with_z3["status"] == "contradicted", with_z3',
        measurement=(
            "A15's condition evasion grounded with the solver present answers "
            "`contradicted`: \"new⊈old: the new policy grants roles/storage.admin "
            "to user:bob@acme.example, at request.time <ts>, which the old policy "
            "does not\". The word 'conditional' is not in that message, so the "
            "branch's companion pin cannot hold either."
        ),
        kept=(
            "The property the case exists for is asserted in its sharper form: "
            "the capability's presence DECIDES, its absence abstains naming the "
            "solver (NO_Z3_REASON), the two messages are asserted DIFFERENT so an "
            "operator can still tell which capability to restore, and the no-z3 "
            "report's summary still carries contradicted == 0."
        ),
        superseded_by=(
            "agent/sx-iam-subset-conditional (09b4d3d, an ancestor of this "
            "branch): constraints._grant_pairs no longer raises _Undecidable on "
            "the mere presence of a `condition` key, so a conditional grant is "
            "compared at request.time. The branch's own docstring named that "
            "branch as PENDING and scoped its pin to 'until sx-iam-subset-"
            "conditional lands' — this is the successor state its author "
            "described, not a reversal of it."
        ),
    ),
    Repin(
        id="RP-D04-NO-Z3-REASON",
        node_id=("tests/test_gcp_agentic_degradation.py::"
                 "test_D04_condition_evasion_abstains_in_both_worlds"),
        branch="agent/sx-agentic-degradation",
        branch_text='assert "conditional" in without_z3["message"], (',
        integrated='assert NO_Z3_REASON in without_z3["message"], (',
        measurement=(
            "Without the solver the subset verdict is \"z3 is not available "
            "(solver backend 'builtin') — new⊆old was not decided\". 'conditional' "
            "is absent because the _Undecidable-on-a-condition-key abstain the "
            "branch was pinning no longer fires at all; the earlier abstain did "
            "not get swallowed by the later one, it stopped existing."
        ),
        kept=(
            "The reason this pin existed — the two worlds' answers must stay "
            "tellable apart — is asserted directly and more strongly: the abstain "
            "must name the missing capability, AND "
            "without_z3['message'] != with_z3['message'] is asserted outright "
            "rather than inferred from two substrings."
        ),
        superseded_by=(
            "agent/sx-iam-subset-conditional, as for RP-D04-WITH-Z3: the "
            "condition-key abstain the substring named is gone from the product."
        ),
    ),
    Repin(
        id="RP-PLUMBING-FLAG-VALUE-PIN",
        node_id=("tests/test_gcp_agentic_plumbing.py::"
                 "test_domain_probes_are_behavioural_not_kind_lookups"),
        branch="agent/gx-capability-probes",
        branch_text="assert getattr(env, name) is False, name",
        integrated="assert env.HAVE_FIREWALL_DOMAIN is True",
        measurement=(
            "All three families measure LIVE in the integrated tree "
            "(fw_checks / vpcsc_checks / org_checks each decide their family "
            "through a real ground_policy run), so the branch's `is False` — a "
            "checkout-local fact from a tree with no firewall or perimeter "
            "checker — is now simply untrue. NOTE the shape this replaces: "
            "432b80fe had relaxed BOTH of the branch's pins into the single "
            "`assert getattr(env, name) is measured.live`, which is "
            "`probe(X).live is probe(X).live` because env.py DEFINES each flag as "
            "that call — the exact tautology this test's docstring exists to "
            "forbid. That relaxation was made by an integrator and by no branch, "
            "and it is repaired here rather than recorded."
        ),
        kept=(
            "Concrete value pins for all three flags (`is True`), the "
            "vocabulary-AND-checker conjunction agent/tx-cli-state-flags "
            "contributed for org-enforcement, the kind-membership equalities "
            "agent/gx-debt-lineno-invariant wrote for the other two, and the "
            "dead-family arm (a dead probe must name itself and the report that "
            "killed it) — which now has a live counterpart that must own its "
            "claim kind AND its checker module."
        ),
        superseded_by=(
            "agent/sx-fw-checks, agent/sx-vpcsc-checks and "
            "agent/sx-org-enforcement landing their checkers, plus "
            "agent/sx-claim-kinds landing firewall_rule / perimeter_config / "
            "constraint_enforcement in gcp_grounding.claims.KINDS."
        ),
    ),
)


FROZEN_PATH_EDITS: tuple[FrozenPathEdit, ...] = (
    FrozenPathEdit(
        path="tests/spec_assertions.py",
        branch_blob="1ffd5c2d8d59a65aff0339c48b1ff8545d71e285",
        head_blob="2e1872219fa427d9f93a85793e813d0a5d0cf9de",
        commit="3ddf1e2fd79bde581afd4b718b6f36a682385dfe",
        what_changed=(
            "TASK_IDS loses `gx-mutation-contract` and gains its four AMENDMENT-4 "
            "successors (-machinery, -seed-a, -seed-b, -gate), plus a ten-line "
            "comment recording why. Every predicate in the register, including "
            "test_task_ids_are_a_subset_of_the_documents_own_task_ids itself, is "
            "textually untouched — only that one frozenset entry and the comment "
            "differ from the blob the branches carry."
        ),
        why_open=(
            "BOTH available resolutions are forbidden here, which is why this is "
            "recorded rather than fixed. (1) Reverting to branch_blob restores "
            "byte-identity and turns the suite RED: the id the register named is "
            "not declared by the design document any more, so "
            "test_task_ids_are_a_subset_of_the_documents_own_task_ids fails — a "
            "PRE-EXISTING red that belongs to agent/gx-spec-register, reproduced "
            "by checking the blob out and running the module. (2) Landing that "
            "assertion under xfail(strict=True) per house rule 4 requires editing "
            "tests/test_gcp_spec_assertions.py, which is frozen too and is "
            "byte-identical to its single branch blob today — trading one frozen "
            "path for another. The register's own docstring rules out the third "
            "option in as many words: 'Editing this register is not one of the "
            "options: it is a frozen acceptance path.' What was done instead — "
            "editing the DATA the frozen assertion inspects until it passes — "
            "leaves the assertion intact and replaces its subject, and that is "
            "not a resolution an integrator may take on its own authority."
        ),
        what_closes=(
            "Either owner acts: the design document declares `gx-mutation-contract` "
            "again (or declares the split in a form the register's existing text "
            "already satisfies), or agent/gx-spec-register — the branch that owns "
            "this register and on which the failure is already red — lands the "
            "successor ids itself. Until one of those, the divergence stays "
            "recorded here and the operator is the one who decides."
        ),
    ),
)
