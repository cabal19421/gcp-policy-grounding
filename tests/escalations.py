"""The APPEND-ONLY escalation register: clauses that cannot be satisfied.

House rule 4 — ESCALATE, DO NOT ROUTE AROUND. When a clause of
`designs/gcp-gx-fixes.md` cannot be satisfied where it was asked for, the
cheapest honest path is to say so by name: an entry here, and the spec-literal
assertion landed under ``pytest.mark.xfail(strict=True, reason=<the escalation
id>)``. That is a GREEN, NAMED state. Rewriting the assertion to fit the code
instead is a review FAIL.

Entries are APPEND-ONLY: an id, once published, is quoted from ``xfail``
reasons and from module docstrings, so removing or renaming one silently
detaches those references. An escalation is CLOSED by landing its fix and
deleting the ``xfail`` — the entry stays, with ``closed_by`` naming the change.

``strict=True`` is what stops an escalation from being forgotten: the day the
owning task lands the fix, the xfail becomes an XPASS and the suite goes RED,
which forces the entry to be retired deliberately rather than by rot.

This file is deliberately NOT frozen — every task may append to it. Its
self-test, ``tests/test_gcp_escalations.py``, IS frozen: it asserts that every
:data:`ESCALATIONS` node id really carries a STRICT xfail whose reason names its
id, that ids are unique, and that a required-id tuple is still a subset of this
register, so a mandated escalation cannot be quietly deleted.

TWO REGISTERS, ONE FILE. :data:`ESCALATIONS` is the xfail-governed register:
every entry names the pytest node whose strict xfail carries it, which is what
the frozen self-test walks. :data:`PRODUCT_ESCALATIONS` is for an escalation
whose subject is PRODUCT code that a test task may not edit — vendored
``gcp_grounding/core/`` above all — where there is no assertion to xfail
because the honest test already passes and it is the product that is wrong.
Such an entry carries ``product_fix`` and ``residual_risk`` instead of a
``node_id``, and is quoted from the module that works around it. Both tuples
are append-only; neither entry may be moved to the other register to make a
schema fit.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Escalation:
    """One clause that could not be satisfied, and where its xfail lives.

    ``id``            stable handle, named in the xfail ``reason``. Never
                      reused, never renamed.
    ``clause``        the VERBATIM design text that cannot be satisfied.
    ``unsatisfiable`` why it cannot be satisfied here — the measured fact, not
                      an opinion.
    ``owner_task``    the task id that raised it.
    ``node_id``       the pytest node carrying the strict-xfailed assertion.
    """

    id: str
    clause: str
    unsatisfiable: str
    owner_task: str
    node_id: str


@dataclass(frozen=True)
class ProductEscalation:
    """One clause blocked by PRODUCT code a test task may not edit.

    There is no assertion to xfail: the honest test passes, and it is the
    product that is wrong, so the entry records the fix and what is exposed
    until it lands rather than a node id.
    """

    #: Stable id, quoted from the module that works around it.
    id: str
    #: The clause, in the design's own words.
    clause: str
    #: What stops it being satisfied here — the measured fact, not an opinion.
    why: str
    #: The change that would close it, concretely enough to be actioned.
    product_fix: str
    #: What is exposed while it is open. An escalation is not a dismissal.
    residual_risk: str
    #: The commit or task that landed ``product_fix``; empty while open.
    closed_by: str = ""


ESCALATIONS: tuple[Escalation, ...] = (
    Escalation(
        id="ESC-GX-SPEC-001",
        clause="asserts the clause still occurs in some file under `designs/`",
        unsatisfiable=(
            "`designs/` is git-ignored repo-wide and is tracked on no branch, so "
            "it exists only in the main checkout: a clean clone, a CI container "
            "and every git worktree carry NO design corpus at all, and the clause "
            "anchor can only be resolved by following this worktree's `.git` "
            "pointer file back to the main checkout, or skipped loudly when even "
            "that fails. Tracking the corpus, or vendoring the clause text into "
            "the repo, is what would close it."
        ),
        owner_task="gx-spec-register",
        node_id=("tests/test_gcp_spec_assertions.py::"
                 "test_the_design_corpus_is_tracked_in_the_repository"),
    ),
    Escalation(
        id="ESC-GX-SPEC-002",
        clause="every owner must be a task id in this document",
        unsatisfiable=(
            "`SA-SECAST-CALLED-ONCE` pins the strict `calls[\"n\"] == 1` counter "
            "proof in tests/test_gcp_sec_ast.py, which today carries the weakened "
            "`<= 1` that zero calls satisfies; that module is owned by "
            "`sx-sec-ast`, a task of the PREDECESSOR design document, and no task "
            "in gcp-gx-fixes.md owns it — so the entry cannot name an in-document "
            "owner without either dropping the pin or inventing an owner that "
            "will never land. Adding a task to this document that owns "
            "tests/test_gcp_sec_ast.py is what would close it."
        ),
        owner_task="gx-spec-register",
        node_id=("tests/test_gcp_spec_assertions.py::"
                 "test_every_awaiting_owner_is_a_task_in_this_document"),
    ),
    Escalation(
        id="ESC-GX-SEXPR-001",
        clause="the same instance works as a dict key and a set member",
        unsatisfiable=(
            "`CompiledRule` IS frozen and its generated `__hash__` delegates to "
            "its one field, but `sec_artifact.Promise` carries the ast as a "
            "plain `dict`, so hashing an admitted rule raises `TypeError: "
            "unhashable type: 'dict'` on CLEAN, unmutated source — the instance "
            "enters neither a dict nor a set however the dataclass is declared, "
            "and no assertion inside this task's declared path can make it. "
            "Giving `Promise` a hashable ast (a canonical JSON string, or a "
            "frozen mapping) in `gcp_grounding/sec_artifact.py` is what would "
            "close it, and that module is outside the one path this task "
            "declares, `gcp_grounding/sec_rules.py`. MK-S01 itself is NOT parked "
            "and needs no amendment: its killing test still reports FAILED under "
            "the `frozen=False` mutant, on the immutability arm and on the "
            "which-type-refuses arm alike."
        ),
        owner_task="gx-sexpr-one-form",
        node_id=("tests/test_gcp_sec_rules.py::"
                 "test_compiled_rule_instance_is_usable_as_a_dict_key"),
    ),
    Escalation(
        id="ESC-GX-SECCLI-001",
        clause=("the recorded source paths are then cwd-relative and the check "
                "mode reports spurious drift"),
        unsatisfiable=(
            "`sec_compile._repo_relative` anchors a recorded source path against "
            "the nearest `pyproject.toml`, and with no such ancestor falls back "
            "to `os.path.relpath(document, os.getcwd())` — so the artifact's "
            "bytes depend on the working directory the compile ran from, and a "
            "`--check` run from a different one re-renders a different "
            "`source.file` and reports drift on a corpus nobody touched. The "
            "clause names this as the SYMPTOM of unanchored paths and the task "
            "body declares root-cause path anchoring out of scope per the "
            "Non-goals, carrying only the partial mitigation: the compile now "
            "REFUSES SILENCE about it, emitting an `unverified` sec:compile "
            "verdict that names the directory and this id. Anchoring the "
            "recorded path to the corpus directory itself — or storing it "
            "absolute — in `gcp_grounding/sec_compile.py` is what would close "
            "it, and that module is outside this task's declared path, "
            "`gcp_grounding/cli.py`."
        ),
        owner_task="gx-sec-cli-zero-rules",
        node_id=("tests/test_gcp_sec_cli.py::"
                 "test_check_outside_the_repo_does_not_report_spurious_drift"),
    ),
    Escalation(
        id="ESC-GX-HFW-FOLD-ENTRY",
        clause=("append an `Escalation` naming it so a human lands it in the "
                "register"),
        unsatisfiable=(
            "REM-GX-HFW-FOLD — the entry that empties the hierarchical fold — is "
            "SPECIFIED IN FULL beside the node below (subject, family, the "
            "`apply`, and the four node ids that must go RED, every one of them "
            "MEASURED red under the mutant and green clean), but it cannot be "
            "REGISTERED from here: as of AMENDMENT 2 both tests/mutation_entries.py "
            "and tests/mutation_contract.py are FROZEN ACCEPTANCE PATHS for "
            "`gx-hierfw-placement`, so any diff touching either fails review "
            "outright — which is how `gx-vpcsc-record-guards` died — and neither "
            "file is in this checkout at all, so there is nothing to append to "
            "even if the freeze allowed it. `gx-mutation-contract-seed-a` owns "
            "seeding it and has not landed. Landing that task, with this entry "
            "among the ones it seeds, is what closes this: the node below then "
            "XPASSes and forces the escalation to be retired. RESIDUAL RISK, the "
            "id mismatch, recorded in the same shape the spec register records "
            "its node-id one: seed-a landing the same subject under a DIFFERENT "
            "id leaves the xfail in place and the escalation goes quiet instead "
            "of biting, so the id is specified verbatim beside the node and the "
            "review gate, not this suite, is what catches a rename."
        ),
        owner_task="gx-hierfw-placement",
        node_id=("tests/test_gcp_hfw_checks.py::"
                 "test_the_folds_mutation_entry_is_seeded_in_the_in_repo_contract"),
    ),
    Escalation(
        id="ESC-GX-TFPROMISE-001",
        clause="the abstention is only correct if the positive case still works",
        unsatisfiable=(
            "THE POSITIVE HALF OF THE PAIR CANNOT BE DEMONSTRATED IN THE MERGED "
            "TREE, and no assertion inside the module that pins it can make it. "
            "`test_the_promise_abstains_over_terraform_and_is_live_over_the_estate` "
            "is written as a PAIR: arm one abstains over a terraform-only view, "
            "arm two adds the merged agentic estate snapshot, DECLARES the "
            "category complete, and the `sec:vpc_firewall` promise then decides — "
            "`contradicted` — which is what stops the abstention being an absent "
            "rule wearing a cautious face. MEASURED in the integrated tree, arm "
            "two's promise is `unverified` as well: `provenance` caps any category "
            "a TERRAFORM source contributed to at 'partial', arm two configures "
            "the terraform state beside the estate snapshot, and the "
            "universal-negative gate refuses to discharge a promise that reasons "
            "from absence over a partial view. `--completeness complete` does not "
            "lift that cap and must not — the alternative is an estate-wide clean "
            "bill of health from a view that sees only part of the estate. Nor can "
            "a witness supply the contradiction: the estate this suite commits "
            "holds no open-SSH rule, and the widened rule lives in the PROPOSAL, "
            "i.e. the `proposed_firewall_rules` collection this promise "
            "deliberately does not quantify over. So the promise abstains in BOTH "
            "arms. What would CLOSE this sits outside any test module: an estate "
            "source whose contribution is not capped at 'partial' by a terraform "
            "sibling, or a committed estate fixture carrying the open-SSH witness "
            "the promise quantifies over — the provenance and estate-fixture "
            "owners' decisions, not a test's. Until then the pair's positive half "
            "is carried on a DIFFERENT channel and asserted there rather than "
            "assumed: the estate-tier `firewall_reopen` check contradicts the "
            "widening over the estate and decides nothing over the terraform-only "
            "view, which the live test now pins on both arms."
        ),
        owner_task="tx-agentic-tf-benign",
        node_id=("tests/test_gcp_agentic_tf_benign.py::"
                 "test_the_promise_contradicts_the_widening_over_the_estate"),
    ),
    Escalation(
        id="ESC-GX-SEEDA-001",
        clause="if it will not fit, escalate for a further split rather than ship it",
        unsatisfiable=(
            "MEASURED, not projected, and measured BEFORE the rest was written as "
            "the body directs. Five entries of the mandated ten-field shape were "
            "written in final form and measured as diff lines: MK-P01 778, MK-P02 "
            "729, MK-P03 662, MK-I01 531, MK-I02 542 — mean 648, inside the body's "
            "own 450-700 estimate. So 44 entries alone are ~28,500 characters, the "
            "file header measured 743, and the removal set sits on top: ~34,000 "
            "against a binding 18,000. THE TWO HALVES THE BODY ASKS FOR DO NOT BOTH "
            "FIT EITHER: MK-I01..MK-I29 alone measure ~17,700 before a header, and "
            "the removal set cannot join either half. THE SPLIT THAT DOES FIT IS "
            "THREE WAYS, on MK id ranges: (a) MK-P01..MK-P15, measured 11,686 "
            "including the header, WHICH THIS DIFF SHIPS; (b) MK-I01..MK-I15, "
            "~9,200; (c) MK-I16..MK-I29 plus the removal set, ~14,200. Slicing to "
            "the measured diff and handing the remainder on is this chain's own "
            "established answer — the five machinery slices each did exactly that "
            "— and every guard is intact: nothing is thinned, no must_fail or "
            "behaviour trimmed, no annotation lowered, no exclusion added, no "
            "third state invented, and the 15 shipped entries are all ACTIVE and "
            "all MEASURED killing (mutant applied alone to a git archive HEAD "
            "copy, -rA reporting FAILED, the unmutated copy green). ONE FURTHER "
            "FINDING FOR WHOEVER SEEDS THE REMOVALS: the body mandates a `pending` "
            "mark, an `owner` and an EXPLICIT field naming which of the two "
            "spellings each removal uses, and the frozen `Removal` dataclass "
            "carries none of those three — it is id, subject, family, apply, "
            "must_fail — so that part must either subclass it in this data module "
            "or the frozen type must gain the fields, which is a decision for the "
            "gate's owner and not something to settle by dropping a mandated "
            "field. Landing parts (b) and (c) is what closes this."
        ),
        owner_task="gx-mutation-contract-seed-a",
        node_id=("tests/test_gcp_mutation_entries.py::"
                 "test_the_seed_covers_every_amendment_2_entry_and_the_removal_set"),
    ),
    Escalation(
        id="ESC-GX-GATE-001",
        clause=("assert the set of `Mutation` ids is a SUPERSET of an explicit "
                "tuple naming ALL 65 MK ids"),
        unsatisfiable=(
            "MEASURED: the register holds 44 of the 65 (MK-P01..P15, "
            "MK-I01..I29) and tests/mutation_entries.py is FROZEN here, so the "
            "missing 21 cannot be added from this task. Its declared dependency "
            "`gx-mutation-contract-seed-b`, which owns them, was NOT seeded — "
            "`git merge-base --is-ancestor agent/gx-mutation-contract-seed-b "
            "HEAD` is false while seed-a, -a2 and -a3 are — and that branch holds "
            "20 of the 21, MK-V05 having been held out, so even a correctly "
            "seeded tree reaches 64. A MIS-SEEDED-TREE FINDING, NOT A LICENCE: "
            "the AWAITING pin stays at ZERO, nothing is parked, and the tuple "
            "names all 65 already, so this xfail XPASSes the day they land."
        ),
        owner_task="gx-mutation-contract-gate",
        node_id=("tests/test_gcp_mutation_contract.py::"
                 "test_every_required_must_kill_id_is_in_the_register"),
    ),
    Escalation(
        id="ESC-GX-GATE-002",
        clause="EXECUTE EVERY ACTIVE ENTRY, both types, and read the result the same way",
        unsatisfiable=(
            "The MUTATION half already executes once per session, in the FROZEN "
            "tests/test_gcp_mutation_machinery.py::test_the_contract_is_now_"
            "ENFORCED_live_over_whatever_the_register_holds, which calls "
            "contract_failures(register(), REPO_ROOT, parent=tmp_path). MEASURED, "
            "that spends 192 of the 199 marked spawns contract_spawn_ceiling() "
            "allows, and the ceiling is 4*len(register()) + "
            "len(removal_register()) + 16 — ONE whole-register execution plus one "
            "child per Removal. A second needs 177 more, mutation_contract is "
            "frozen here so the formula cannot be rescaled, and raising a ceiling "
            "is a threshold move this document forbids. Rescaling it, or dropping "
            "the duplicate execution from the frozen module, closes this."
        ),
        owner_task="gx-mutation-contract-gate",
        node_id=("tests/test_gcp_mutation_contract.py::"
                 "test_this_gate_can_afford_to_execute_every_active_mutation_itself"),
    ),
    Escalation(
        id="ESC-GX-IAM-REPIN-SPLIT",
        clause=("add the missing adversarial case binding an escalation-class "
                "role to a public member"),
        unsatisfiable=(
            "A BUDGET SPLIT ADJUDICATED BY THE OPERATOR, not a finding about the "
            "code. The whole repin MEASURED 30,422 diff characters against the "
            "18,000 the prose binds and the 20,000 gitutil.diff_text clips at, "
            "and the verifier's round-1 ruling was to land the spec-restoration "
            "core here and hand the rest to `gx-agentic-iam-repin-2` by name. "
            "DEFERRED, EACH ITEM NAMED: (1) this clause's A19 case and its "
            "payload fixture; (2) B08's discriminating verdictless-pass "
            "certificate — the detected kind and source, plus the near-miss "
            "document the same assertion must REFUSE; (3) the three record-level "
            "fixtures the catalogue lacks, members absent, members empty and a "
            "mis-cased bindings key; (4) `RM-IAM-MEMBER-EXTRACTION`, whose "
            "must_fail names A19. NOTHING WAS WEAKENED TO FIT: the escalation "
            "channel is asserted by identity, A11's public channel by target, "
            "A15b's REGISTERED predicate is unconditional, and the two removals "
            "this task owns are LIVE. Landing A19 XPASSes the node below."
        ),
        owner_task="gx-agentic-iam-repin",
        node_id=("tests/test_gcp_agentic_iam.py::"
                 "test_an_escalation_class_role_bound_to_the_public_is_a_"
                 "catalogue_case"),
    ),
    Escalation(
        id="ESC-GX-NETWORK-PAIR-BASELINE",
        clause=("add one case that ONLY the pair check could catch and assert "
                "the honest abstain naming the absent baseline"),
        unsatisfiable=(
            "THE ABSTENTION EXISTS AND IS UNREACHABLE, measured both ways. "
            "`fw_checks.check_packet_set_pair` returns `unverified` naming \"no "
            "baseline document was available — no packet-set comparison was "
            "made\", but `preflight.ground_policy` calls `_subset_verdict` — the "
            "only caller of `registry.pair_check` — INSIDE `if baseline is not "
            "None`, and the `--hook` path passes no baseline at all, so on the "
            "hook path the check is never entered and NOTHING names its "
            "absence. A second wall sits behind that one: `PAIR_CHECKS` is keyed "
            "by the DETECTED document kind and `fw_claims.detect_kind` answers "
            "`firewall_rule` only for a Compute REST document (`kind == "
            "\"compute#firewall\"`), while every fixture in this catalogue is a "
            "`terraform show -json` plan detecting as `tf_plan` — so no agentic "
            "case can reach the pair check even if a baseline were supplied. "
            "Calling the resolved pair check on the no-baseline path, so the "
            "gate abstains instead of staying silent, is what closes this, and "
            "it is a change to `gcp_grounding/preflight.py`, not to a test. "
            "MEANWHILE THE CONSTANT IS NOT LEFT READING AS COVERAGE: "
            "`RM-NETWORK-PAIR-CHECKS` is LIVE, not pending, and kills through "
            "`test_the_pair_check_decides_a_widening_against_a_baseline`, which "
            "drives the committed REST pair in process — so emptying "
            "`fw_checks.PAIR_CHECKS` reddens a named node instead of nothing."
        ),
        owner_task="gx-agentic-network-repin",
        node_id=("tests/test_gcp_agentic_network.py::"
                 "test_a_hook_shaped_run_abstains_naming_the_absent_baseline"),
    ),
    Escalation(
        id="ESC-GX-NETWORK-REMOVAL-CEILING",
        clause="after the repin that removal must redden named cases",
        unsatisfiable=(
            "IT DOES REDDEN THEM, MEASURED, AND THE CEILING STILL REFUSES THE "
            "FLIP. Under `GCP_TEST_REMOVAL=RM-NETWORK-PLANE-UNAVAILABLE` both "
            "named nodes report FAILED and both report PASSED on clean source, "
            "so the removal is a kill and not a hypothesis. But "
            "`contract_spawn_ceiling()` is `4*len(register()) + "
            "len(removal_register()) + CONTRACT_CONTROL_SPAWNS`, and MEASURED "
            "in this checkout the contract's real control cost is 21 against a "
            "pinned `CONTRACT_CONTROL_SPAWNS = 16` — the five-slot gap is "
            "absorbed by the per-Removal term for the five removals that are "
            "NOT live, so a full run sits at exactly 199 of 199 with ZERO "
            "headroom. A NEW live removal is net zero (one slot, one `-rA` "
            "child); flipping an ALREADY-COUNTED one from pending to live is "
            "+1 spawn and +0 slots, so it overflows by exactly one whatever "
            "else the diff does. This task's two NEW removals — "
            "`RM-NETWORK-PAIR-CHECKS` and `RM-NETWORK-VOCABULARY-KIND` — are "
            "therefore LIVE and executed, and the seeded one stays `pending` "
            "with its measurement recorded beside it rather than the ceiling "
            "being raised, which mutation_contract.py is frozen against and "
            "which this document forbids in any case. Rescaling "
            "`CONTRACT_CONTROL_SPAWNS` to the 21 controls it really has — the "
            "same rescale ESC-GX-GATE-002 asks for — closes this and XPASSes "
            "the node below."
        ),
        owner_task="gx-agentic-network-repin",
        node_id=("tests/test_gcp_agentic_network.py::"
                 "test_the_network_plane_removal_is_live_in_the_contract"),
    ),
    Escalation(
        id="ESC-GX-NETWORK-LAYER4-SPELLING",
        clause=("then assert the CHANNEL and the PROPERTY — a re-open or "
                "widening verdict naming the port and the priority of the "
                "preempting deny — never a bare contradiction count"),
        unsatisfiable=(
            "THE PRIORITY HALF IS ASSERTED; THE PORT HALF CANNOT BE, for A02. "
            "`hfw_claims._from_terraform` reads the repeated layer-4 block as "
            "`match.layer4_config`, and the provider — with this repo's own real "
            "captures, `tests/fixtures/gcp/tf/hcl/main.tf`, `estate_plan.json` "
            "and `estate.tfstate` — spells it `layer4_configs`. An ABSENT key "
            "legitimately declares NO layer-4 restriction "
            "(`_unreadable_layer4` returns None for it), so A02's tcp/22 "
            "proposal folds as matching EVERY port: MEASURED, the three "
            "`hfw_reopen` verdicts it produces are against the estate's RDP "
            "denies with witness `port=3389`, and asserting that port for an SSH "
            "case would certify the gate with a finding about a rule the agent "
            "did not write. Reading `layer4_configs` in "
            "`gcp_grounding/hfw_claims.py` — or refusing a match block that "
            "carries neither spelling — closes it; that module belongs to the "
            "hierarchical-firewall tasks and not to this test-only repin. A02 "
            "therefore asserts the channel and the PRIORITY of the deny it "
            "preempts, A03 asserts port and priority both, and the port half is "
            "landed under the strict xfail below rather than dropped."
        ),
        owner_task="gx-agentic-network-repin",
        node_id=("tests/test_gcp_agentic_network.py::"
                 "test_a_hierarchical_proposals_own_port_reaches_the_verdict"),
    ),
    Escalation(
        id="ESC-GX-VPCSC-DRY-RUN-TRACE",
        clause=("require a TRACE for the cleared enforced block — a verdict "
                "naming the projects that stop being enforced"),
        unsatisfiable=(
            "THE TRACE IS A PRODUCT CHANGE THIS TEST-ONLY TASK MAY NOT MAKE, "
            "and the task body assigns it elsewhere: \"The domain-side fix "
            "lands in the enforcement-surface task; this task asserts it.\" "
            "That fix is NOT in this checkout — `vpcsc_checks.PAIR_CHECKS` "
            "holds only `vpc_sc_perimeter` and `check_perimeter_estate` still "
            "opens with the unconditional `if ctx.baseline is not None: return "
            "[]` — so there is nothing here to assert. MEASURED against A28, "
            "the missing adversarial case this task ADDS (a removal written in "
            "the dry-run spelling: the enforced `status` block cleared, and a "
            "`spec` block that drops `projects/111111111111` and "
            "`bigquery.googleapis.com`): ok TRUE, zero contradicted, a GROUNDED "
            "`vpcsc_dry_run` verdict saying the change does not alter "
            "enforcement, and ONE `vpcsc_protection` abstention that names only "
            "the perimeter. Neither the project nor the service that leaves "
            "enforcement appears in ANY verdict's target or message, so the "
            "minimum the clause allows — one abstention per project and service "
            "that leaves enforcement — is as unreachable as the block. What IS "
            "landed: A26 stops pinning the neutral \"does not alter "
            "enforcement\" wording as its expected message (pinning that is "
            "pinning the defect), both dry-run cases assert the abstention on "
            "the vpcsc channel so the ignorance is on the record rather than "
            "passed in silence, and the clause itself is the strict xfail below. "
            "`_compare` differencing the RAW old `status` against a cleared new "
            "one closes it."
        ),
        owner_task="gx-agentic-vpcsc-repin",
        node_id=("tests/test_gcp_agentic_vpcsc.py::"
                 "test_a_dry_run_removal_traces_the_projects_that_leave_"
                 "enforcement"),
    ),
    Escalation(
        id="ESC-GX-VPCSC-DELETION-BLINDNESS",
        clause=("The clause names the not-silently-dropped assertion for the "
                "removed project id; the module uses it only in the blocking "
                "branch and puts the vacuous helper in the degraded one"),
        unsatisfiable=(
            "THE DESIGN SAYS SO ITSELF — \"the clause as literally written is "
            "UNSATISFIABLE in the degraded world, where the only verdict is "
            "about the resource type\" — and this checkout MEASURES exactly "
            "that: with `gcp_grounding.vpcsc_checks` and "
            "`gcp_grounding.vpcsc_claims` bound to None in `sys.modules`, A06's "
            "document produces ONE verdict, `grounded resource_type`, so no "
            "trace of `projects/111111111111` can exist for "
            "`assert_not_silently_dropped` to find. Restoring it needs a claim "
            "extractor that survives its own domain being unregistered, which "
            "is a product change and not a test's. The DOWNGRADE the design "
            "objects to is what is fixed here: the degraded branch no longer "
            "falls back to \"the gate produced at least one verdict\" — an "
            "always-true statement, since every terraform plan draws a grounded "
            "`resource_type` for free — and "
            "`test_the_domain_gone_world_says_nothing_about_the_deletion` pins "
            "the honest floor instead, asserting EXACTLY ONE verdict, of an "
            "INCIDENTAL kind, and that no verdict's target or message mentions "
            "the removed project or the perimeter. The clause is landed "
            "literally under the strict xfail below rather than softened."
        ),
        owner_task="gx-agentic-vpcsc-repin",
        node_id=("tests/test_gcp_agentic_vpcsc.py::"
                 "test_the_removed_project_is_not_silently_dropped_in_the_"
                 "degraded_world"),
    ),
    Escalation(
        id="ESC-GX-VPCSC-REMOVAL-CEILING",
        clause=("after the repin BOTH removals must redden named cases, and "
                "both go in the mutation contract"),
        unsatisfiable=(
            "THEY DO REDDEN THEM, MEASURED, AND THE CEILING STILL REFUSES THE "
            "FLIP — the same arithmetic ESC-GX-NETWORK-REMOVAL-CEILING records, "
            "one wave later and with no headroom recovered. All THREE removals "
            "this task owns kill: under `GCP_TEST_REMOVAL=<id>` every named node "
            "reports FAILED and every one reports PASSED on clean source, for "
            "`RM-VPCSC-DOMAIN-UNREGISTERED` (2 nodes), "
            "`RM-VPCSC-ABSENT-VERSUS-EMPTY` (2 parametrized nodes) and "
            "`RM-VPCSC-DOCUMENT-AND-PAIR-CHECKS` (4 parametrized nodes). But "
            "`contract_spawn_ceiling()` is `4*len(register()) + "
            "len(removal_register()) + CONTRACT_CONTROL_SPAWNS` and a full run "
            "in this checkout MEASURES 201 marked spawns against a ceiling of "
            "exactly 201: the gap between the pinned "
            "`CONTRACT_CONTROL_SPAWNS = 16` and the controls' real cost is "
            "absorbed by the per-Removal term of the removals that are NOT "
            "live, so flipping an already-counted one to live is +1 `-rA` child "
            "and +0 slots and overflows by one apiece, whatever else the diff "
            "does. Raising the ceiling is forbidden and `mutation_contract.py` "
            "is frozen against it in any case, so the three stay `pending` with "
            "their measurement recorded beside them. Rescaling "
            "`CONTRACT_CONTROL_SPAWNS` to the controls it really has — the same "
            "rescale ESC-GX-GATE-002 asks for — closes this and XPASSes the node "
            "below."
        ),
        owner_task="gx-agentic-vpcsc-repin",
        node_id=("tests/test_gcp_agentic_vpcsc.py::"
                 "test_the_vpcsc_removals_are_live_in_the_contract"),
    ),
)


PRODUCT_ESCALATIONS: tuple[ProductEscalation, ...] = (
    ProductEscalation(
        id="ESC-HOOKRUNNER-NO-Z3-BANNER",
        clause=(
            "assert_passed's byte-empty-both-streams contract must hold in the "
            "no-z3 world the harness explicitly supports, without relaxing "
            "assert_passed."
        ),
        why=(
            "A clean hook run on a clean policy writes 236 bytes to stderr in "
            "that world: core/solver.py:116-120 logs 'z3 package found but "
            "failed to initialize (...) — falling back to the builtin solver' "
            "at WARNING, and with no setup_logging() call logging's lastResort "
            "handler puts the bare message on stderr. The harness side is "
            "fixed — tests.agentic.hookrunner.STDERR_ALLOWLIST filters that "
            "exact line out of HookOutcome.stderr and keeps it on stderr_raw — "
            "but that changes THE MEASURING INSTRUMENT, NOT THE PRODUCT. "
            "gcp_grounding/core/ is vendored and MUST NOT be edited, so the "
            "product half cannot be fixed from a test task at all."
        ),
        product_fix=(
            "Demote the fallback warning to debug on the hook path, in the "
            "module that owns the solver: core/solver.py's get_solver() should "
            "log the 'found but failed to initialize' fallback at DEBUG (the "
            "backend is already reported by --explain and by the report "
            "document's `backend` field), or gcp_grounding should own the "
            "solver selection in a non-vendored wrapper that logs at DEBUG "
            "when running as a PostToolUse hook."
        ),
        residual_risk=(
            "On a machine whose solver is installed but not initialisable — a "
            "mismatched libz3, a wrong-arch wheel — the gate writes that line "
            "to the hook's stderr ONCE PER TOOL CALL. The hook's stderr is a "
            "contract surface: Claude Code feeds it back to the agent, and the "
            "operator reads it. A guardrail that chatters on every clean edit "
            "is a guardrail that gets switched off. Nothing downstream may "
            "claim unconditional byte-silence without naming the filtered line "
            "and why it is filtered."
        ),
    ),
    ProductEscalation(
        id="ESC-GX-HFW-EQUIVALENT-SITES",
        clause="the twelve named survivors are dead",
        why=(
            "Nine are. THREE ARE MEASURED EQUIVALENT — each still green under "
            "its own mutant applied ALONE in a detached `git worktree`, "
            "validated by tests/test_gcp_hfw_checks.py, the run TABLED at the "
            "top of that file — and each is unobservable by construction, the "
            "proof house rule 7 demands beside the measurement. `402 <->=` is "
            "reached only under `if a.level != b.level`, where the operators "
            "agree on every input. `786 +->-` feeds a counter read ONLY "
            "through `not sum(contributed.values())` and its KEYS; all terms "
            "are non-negative, so negating them leaves the sum zero exactly "
            "when it was zero. `885 False->True` defaults a `disabled` key "
            "never absent where it is read: `_as_vpc_shape` always writes it, "
            "so only a raw VPC record can omit one, and a VPC rule sits at "
            "level `len(chain)`, inside every proposal, so `_wins_over(p, "
            "mine)` is False for it whatever the default says."
        ),
        product_fix=(
            "REMOVE the three sites — stronger than a kill, the route "
            "AMENDMENT 3 took for EQ-O01/EQ-O02: compare `_wins_over`'s "
            "operands as one `(level, rank)` tuple; make `contributed` a SET "
            "of contributing policies, not a count; normalise VPC records "
            "through `_as_vpc_shape` too, so `disabled` is always present. "
            "All three sit in gcp_grounding/hfw_checks.py, which this "
            "TEST-ONLY task may not edit."
        ),
        residual_risk=(
            "Nothing is exposed by 402 or 786. 885 is the one to watch: it is "
            "unreachable only because no VPC rule can preempt a hierarchical "
            "proposal, so the day the VPC layer folds at a level a proposal "
            "can reach, the default goes live and a rule whose `disabled` key "
            "the capture dropped leaves the preemption set — the FALSE-CLEAN "
            "direction. Whoever changes `_place`'s level arithmetic owns it."
        ),
    ),
    ProductEscalation(
        id="ESC-GX-HFW-NETWORK-DIMENSION",
        clause=("Append an `Escalation` naming the axiom that would close it "
                "properly."),
        why=(
            "MEASURED: an org-level deny scoped to vpc-dmz and a proposed allow "
            "scoped to vpc-main were reported `contradicted hfw_reopen` with the "
            "witness packet `src=35.0.0.0 dst=0.0.0.0 proto=6 port=3389` — a "
            "packet that CANNOT EXIST, because network self-links were OR-ed "
            "into the target-tag channel and nothing forbids the solver "
            "satisfying two disjoint networks at once. There is no assertion to "
            "xfail: `gcp_grounding/hfw_checks.py` now carries the conservative "
            "local mitigation the design asks for — self-links out of the tag "
            "channel, provably disjoint peers dropped before comparison, a LOUD "
            "`unverified` when disjointness cannot be decided — and the honest "
            "tests of it pass. It is the PACKET ALGEBRA that is wrong: "
            "`packet.PacketVars` has no network dimension at all, so no term can "
            "say two scopes exclude each other, and the design declares the full "
            "fix OUT OF SCOPE for this task."
        ),
        product_fix=(
            "THE AXIOM: give `packet.PacketVars` a network variable and "
            "constrain it in `packet.universe_axioms` to EXACTLY ONE of the "
            "captured networks — the same at-most-one shape that function "
            "already applies to tags and service accounts — then have "
            "`packet.rule_match` conjoin `network == <self-link>` for a scoped "
            "rule. Two disjoint scopes become unsat by construction, both "
            "pairwise findings and the whole-order fold get it for free, and the "
            "mitigation in `hfw_checks._network_scoped` / `_rule_networks` is "
            "DELETED rather than kept beside it."
        ),
        residual_risk=(
            "THE PRICE, recorded here as well as in the code comment on "
            "`_rule_networks` because `report.ok` treats `unverified` as a PASS: "
            "an undecidable-overlap abstention converts a would-be BLOCK into a "
            "pass, so this mitigation trades a false contradiction for a "
            "possible missed one. It is acceptable only because the abstention "
            "is LOUD — one `unverified` on the hierarchical channel naming both "
            "networks and every rule it declined to compare — and because it is "
            "bounded by the axiom above. It is never spelled as silence and "
            "never widened to the decidable case: two scopes that provably "
            "intersect, and a rule scoped to no network at all, are compared "
            "exactly as before. Separately, the FOLD is a whole-order statement "
            "rather than a pairwise one, so it keeps the undecidable rules and "
            "over-approximates rather than losing a level."
        ),
    ),
)


# Escalation owners that are not tasks of designs/gcp-gx-fixes.md. It exists so
# an escalation raised against a PREDECESSOR document's task has an append-only
# home and is never forced to edit the frozen self-test.
#
# `tx-agentic-tf-benign` is declared in designs/gcp-tf-source.md, the predecessor
# document that owns tests/test_gcp_agentic_tf_benign.py; ESC-GX-TFPROMISE-001 is
# raised against its promise pair and no task of gcp-gx-fixes.md owns that module.
OUT_OF_DOCUMENT_OWNER_TASKS: frozenset[str] = frozenset({
    "tx-agentic-tf-benign",
})
