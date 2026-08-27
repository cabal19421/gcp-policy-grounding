"""The seeded mutation contract entries. DATA ONLY -- nothing here executes.

The machinery, the shape gate and the live flip are ``tests/mutation_contract.py``'s;
no register-wide assertion belongs here (that is part 4's, ``-gate``).

SOURCE OF EVERY ``must_fail``, recorded once because it is the same for all:
THIS CHECKOUT'S COLLECT-ONLY PASS -- ``mutation_contract.CHECKOUT_COLLECT``, the
state line's default -- both owner branches being ancestors of HEAD (asserted with
``git merge-base --is-ancestor`` before a single entry was written). Each node
below was then MEASURED, not read: the mutant applied alone to a ``git archive
HEAD`` copy, ``-rA`` reporting the node FAILED, and the unmutated copy green.

``line_hint`` is the design's number from the day of measurement and has DRIFTED;
every anchor is the content slice found in the owner's landed source, widened to
the smallest slice unique inside its ``enclosing`` scope.

MK-I01..MK-I15 and then MK-I16..MK-I29 PLUS THE REMOVAL SET -- pieces (b) and
(c) of ESC-GX-SEEDA-001's measured three-way split, which landing CLOSES -- are
appended under those same rules, read from ``agent/gx-evidence-invokers``.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, replace
from importlib import import_module
from pathlib import Path

from tests.mutation_contract import Mutation, Removal

_MOD = "gcp_grounding/preflight.py"
_OWNER = "gx-preflight-empty-key"
_T = "tests/test_gcp_preflight.py::"
_G = "tests/test_gcp_policy_gate.py::"

_IR, _ID = "gcp_grounding/registry.py", "gcp_grounding/sec_domains.py"
_IS, _IOWNER = "gcp_grounding/sec_rules.py", "gx-evidence-invokers"
_TR = "tests/test_gcp_registry.py::"
_TD = "tests/test_gcp_sec_domains.py::"
_TS = "tests/test_gcp_sec_rules.py::"
_TF = "tests/test_gcp_evidence_floor.py::"
#: The protocol table is module-level, so its anchor is the one-line snippet of
#: its own statement -- which occurs exactly once -- and not a def name.
_TABLE = "PROTOCOL_NUMBERS: dict[str, int] = {"

#: A JSON document has no line to point at, so every verdict carries lineno 0.
#: The lineno family below all mutate that 0 and are all widened by one message
#: line, the ``report.add(Verdict(...`` opener repeating inside every scope.
ENTRIES: tuple[Mutation, ...] = (
    Mutation(
        id="MK-P01", module=_MOD, enclosing="ground_policy",
        before='        report.add(Verdict("unverified", "document", source, 0,\n'
               '                           f"{source}: {error} — nothing was checked"))',
        after='        report.add(Verdict("unverified", "document", source, 1,\n'
              '                           f"{source}: {error} — nothing was checked"))',
        line_hint=104,
        behaviour="the unreadable-or-invalid-document abstention points at line 1 "
                  "of a document that has no lines",
        must_fail=(_T + "test_missing_file_fails_open_to_unverified",
                   _T + "test_invalid_json_fails_open_to_unverified"),
        owner=_OWNER),
    Mutation(
        id="MK-P02", module=_MOD, enclosing="ground_policy",
        before='            report.add(Verdict("unverified", "subset", "iam-policy", 0,\n'
               '                               f"{source}: {error} — new⊆old was not decided"))',
        after='            report.add(Verdict("unverified", "subset", "iam-policy", 1,\n'
              '                               f"{source}: {error} — new⊆old was not decided"))',
        line_hint=107,
        behaviour="the new⊆old-not-decided abstention raised beside an unreadable "
                  "document points at a line",
        must_fail=(_T + "test_missing_file_fails_open_to_unverified",),
        owner=_OWNER),
    Mutation(
        id="MK-P03", module=_MOD, enclosing="ground_policy",
        before='        report.add(Verdict("unverified", "document", source, 0,\n'
               '                           f"{source}: detected {kind} content, but nothing "',
        after='        report.add(Verdict("unverified", "document", source, 1,\n'
              '                           f"{source}: detected {kind} content, but nothing "',
        line_hint=121,
        behaviour="the zero-claims honesty abstention points at a line",
        must_fail=(_T + "test_absent_bindings_key_is_unverified_not_legitimately_empty",),
        owner=_OWNER),
    Mutation(
        id="MK-P04", module=_MOD, enclosing="ground_policy",
        before='if claim.kind == "cel":', after='if claim.kind != "cel":',
        line_hint=130,
        behaviour="every non-CEL claim is sent to the CEL checker and every CEL "
                  "claim skips it. RE-MEASURED IN ISOLATION, which is why it is "
                  "seeded already-killed: applied alone to a git-archive copy it "
                  "reddens 21 nodes across test_gcp_preflight.py and "
                  "test_gcp_policy_gate.py, so its appearance in the live survivor "
                  "list was a sequential-loop artefact and never a coverage gap",
        must_fail=(_G + "test_good_policy_files_pass_with_no_risk",
                   _G + "test_bad_iam_policy_fails_the_gate_with_findings"),
        owner=_OWNER),
    Mutation(
        id="MK-P05", module=_MOD, enclosing="ground_policy",
        before='            report.add(Verdict("unverified", claim.kind, claim.value, 0,',
        after='            report.add(Verdict("unverified", claim.kind, claim.value, 1,',
        line_hint=135,
        behaviour="the no-offline-check-is-wired abstention points at a line",
        must_fail=(_T + "test_claim_kind_no_layer_decides_is_unverified_naming_the_kind",),
        owner=_OWNER),
    Mutation(
        id="MK-P06", module=_MOD, enclosing="_extract_claims",
        before='        report.add(Verdict("unverified", "document", source, 0,\n'
               '                           f"{source}: document kind was not recognized ({shape}) "',
        after='        report.add(Verdict("unverified", "document", source, 1,\n'
              '                           f"{source}: document kind was not recognized ({shape}) "',
        line_hint=192,
        behaviour="the unrecognized-document-kind abstention points at a line",
        must_fail=(_T + "test_unrecognized_document_fails_open_to_unverified",),
        owner=_OWNER),
    Mutation(
        id="MK-P07", module=_MOD, enclosing="_extract_claims",
        before='            report.add(Verdict("unverified", "document", source, 0,\n'
               '                               f"{source}: detected a terraform plan, but the tf-plan "',
        after='            report.add(Verdict("unverified", "document", source, 1,\n'
              '                               f"{source}: detected a terraform plan, but the tf-plan "',
        line_hint=199,
        behaviour="the plan-detected-but-no-extractor abstention points at a line",
        must_fail=(_T + "test_tf_plan_without_its_extractor_is_unverified",),
        owner=_OWNER),
    Mutation(
        id="MK-P08", module=_MOD, enclosing="_extract_claims",
        before="                     exc_info=True)", after="                     exc_info=False)",
        line_hint=210,
        behaviour="the claim-extraction-failed debug record loses its traceback. "
                  "The trap: logging stores the literal False, so `exc_info is not "
                  "None` still passes -- only truthiness kills it",
        must_fail=(_T + "test_claim_extraction_failure_logs_its_traceback",),
        owner=_OWNER),
    Mutation(
        id="MK-P09", module=_MOD, enclosing="_extract_claims",
        before='        report.add(Verdict("unverified", "document", source, 0,\n'
               '                           f"{source}: {kind} claim extraction failed ({exc}) "',
        after='        report.add(Verdict("unverified", "document", source, 1,\n'
              '                           f"{source}: {kind} claim extraction failed ({exc}) "',
        line_hint=211,
        behaviour="the claim-extraction-raised abstention points at a line",
        must_fail=(_T + "test_claim_extraction_raising_fails_open_to_unverified",),
        owner=_OWNER),
    Mutation(
        id="MK-P10", module=_MOD, enclosing="_subset_verdict",
        before='        return [Verdict("unverified", "subset", "iam-policy", 0,\n'
               '                        f"a baseline was given, but the document was detected as "',
        after='        return [Verdict("unverified", "subset", "iam-policy", 1,\n'
              '                        f"a baseline was given, but the document was detected as "',
        line_hint=236,
        behaviour="the baseline-against-a-non-IAM-document abstention points at a line",
        must_fail=(_T + "test_baseline_against_non_iam_document_is_unverified",),
        owner=_OWNER),
    Mutation(
        id="MK-P11", module=_MOD, enclosing="_subset_verdict",
        before="{kind or 'unrecognized'}", after="{kind and 'unrecognized'}",
        line_hint=238,
        behaviour="the abstention LIES about what was detected: a detected "
                  "org_policy is reported as 'unrecognized' and an undetected "
                  "document renders as 'None'",
        must_fail=(_T + "test_baseline_against_non_iam_document_is_unverified",),
        owner=_OWNER),
    Mutation(
        id="MK-P12", module=_MOD, enclosing="ground_policy",
        before='            report.add(Verdict("unverified", "subset", "iam-policy", 0,\n'
               '                               f"{baseline_source}: baseline {baseline_error} "',
        after='            report.add(Verdict("unverified", "subset", "iam-policy", 1,\n'
              '                               f"{baseline_source}: baseline {baseline_error} "',
        line_hint=242,
        behaviour="the unreadable-baseline abstention points at a line",
        must_fail=(_T + "test_unreadable_baseline_is_unverified_not_contradicted",),
        owner=_OWNER),
    Mutation(
        id="MK-P13", module=_MOD, enclosing="_subset_verdict",
        before='        return [Verdict("unverified", "subset", "iam-policy", 0,\n'
               '                        f"{baseline_source}: the baseline\'s shape was not "',
        after='        return [Verdict("unverified", "subset", "iam-policy", 1,\n'
              '                        f"{baseline_source}: the baseline\'s shape was not "',
        line_hint=248,
        behaviour="the baseline-is-not-an-IAM-allow-policy abstention points at a line",
        must_fail=(_T + "test_unrecognized_baseline_shape_is_unverified_not_contradicted",),
        owner=_OWNER),
    Mutation(
        id="MK-P14", module=_MOD, enclosing="_subset_verdict",
        before='        return [Verdict("unverified", "subset", "iam-policy", 0,\n'
               '                        f"new⊆old was not decided: {exc}")]',
        after='        return [Verdict("unverified", "subset", "iam-policy", 1,\n'
              '                        f"new⊆old was not decided: {exc}")]',
        line_hint=254,
        behaviour="the subset-check-raised-ValueError abstention points at a line",
        must_fail=(_T + "test_subset_check_raising_value_error_is_unverified",),
        owner=_OWNER),
    Mutation(
        id="MK-P15", module=_MOD, enclosing="_legitimately_empty",
        before='doc["bindings"] == []', after='doc["bindings"] != []',
        line_hint=155,
        behaviour="an IAM policy that grants nothing stops being legitimately "
                  "empty and one that grants something starts being it -- the "
                  "inversion of the very fix this task landed. Seeded "
                  "already-killed so a later refactor cannot quietly free it",
        must_fail=(_T + "test_legitimately_empty_iam_policy_yields_no_verdicts",),
        owner=_OWNER),
    # -- ESC-GX-SEEDA-001 piece (b): the evidence funnel's first fifteen. ----
    Mutation(
        id="MK-I01", module=_IR, enclosing="CheckContext",
        before="frozen=True", after="frozen=False", line_hint=77,
        behaviour="CheckContext stops being frozen, so a check can mutate the "
                  "context it is handed and the record is no longer hashable",
        must_fail=(_TR + "test_check_context_is_frozen_and_hashable_by_intent",),
        owner=_IOWNER),
    Mutation(
        id="MK-I02", module=_ID, enclosing=_TABLE,
        before='"icmp": 1', after='"icmp": 2', line_hint=171,
        behaviour="the IANA table calls icmp 2, which is igmp, so an icmp rule "
                  "encodes the wrong number and matches the wrong promise",
        must_fail=(_TD + "test_a_protocol_name_encodes_its_own_iana_number[icmp-1-2]",),
        owner=_IOWNER),
    Mutation(
        id="MK-I03", module=_ID, enclosing=_TABLE,
        before='"udp": 17', after='"udp": 18', line_hint=171,
        behaviour="the table calls udp 18, silently changing which promise "
                  "matches a udp firewall rule, with no verdict text to say so",
        must_fail=(_TD + "test_a_protocol_name_encodes_its_own_iana_number[udp-17-18]",),
        owner=_IOWNER),
    Mutation(
        id="MK-I04", module=_ID, enclosing=_TABLE,
        before='"ipv6-icmp": 58', after='"ipv6-icmp": 59', line_hint=172,
        behaviour="the table calls ipv6-icmp 59, silently changing which promise "
                  "matches an ipv6-icmp rule",
        must_fail=(_TD + "test_a_protocol_name_encodes_its_own_iana_number"
                         "[ipv6-icmp-58-59]",),
        owner=_IOWNER),
    Mutation(
        id="MK-I05", module=_ID, enclosing="_sorted",
        before="(0, str(record[field]))", after="(1, str(record[field]))",
        line_hint=225,
        behaviour="the sort key collapses the two ranks, so an absent key sorts "
                  "BEFORE every present one and the records a witness is drawn "
                  "from are silently reordered",
        must_fail=(_TD + "test_a_row_missing_a_field_sorts_after_every_row_that_"
                         "carries_it",),
        owner=_IOWNER),
    Mutation(
        id="MK-I06", module=_ID, enclosing="_str_dimension",
        before="isinstance(v, str) and v", after="isinstance(v, str) or v",
        line_hint=254,
        behaviour="empty strings AND non-string truthy values enter a string "
                  "dimension, whose empty string is reserved for an honest "
                  "captured-empty scalar",
        must_fail=(_TD + "test_a_string_dimension_takes_real_strings_and_nothing_else",),
        owner=_IOWNER),
    Mutation(
        id="MK-I07", module=_ID, enclosing="_protocol_number",
        before='protocol is None or protocol == "all"',
        after='protocol is None and protocol == "all"', line_hint=290,
        behaviour="both the absent protocol and the literal \"all\" fall through "
                  "to the undecidable, so EVERY all-protocols rule abstains "
                  "instead of omitting the protocol key",
        must_fail=(_TD + "test_an_all_protocols_rule_omits_the_protocol_key_and_"
                         "still_evaluates",),
        owner=_IOWNER),
    Mutation(
        id="MK-I08", module=_ID, enclosing="_protocol_number",
        before="not 0 <= number <= 255", after="not 1 <= number <= 255",
        line_hint=302,
        behaviour="protocol 0, HOPOPT, is refused as though it had no IANA "
                  "number, so a legal value makes the whole rule abstain",
        must_fail=(_TD + "test_protocol_zero_is_hopopt_and_is_a_legal_value",),
        owner=_IOWNER),
    Mutation(
        id="MK-I09", module=_ID, enclosing="_port_values",
        before="high - low + 1 > MAX_PORT_SPAN",
        after="high - low + 1 >= MAX_PORT_SPAN", line_hint=321,
        behaviour="a range of exactly MAX_PORT_SPAN ports is treated as wide and "
                  "stops being enumerated -- a real boundary, off by one port",
        must_fail=(_TD + "test_a_range_of_exactly_the_maximum_span_is_still_enumerated",),
        owner=_IOWNER),
    Mutation(
        id="MK-I10", module=_ID, enclosing="_port_values",
        before="wide = True", after="wide = False", line_hint=324,
        behaviour="the wide flag is never set, so the port-key-omitted row is "
                  "never appended and a port-mentioning promise UNDER-MATCHES a "
                  "wide range instead of abstaining loudly -- RC1 in the port axis",
        must_fail=(_TD + "test_a_wide_port_range_omits_the_port_key_so_a_port_"
                         "promise_abstains",),
        owner=_IOWNER),
    Mutation(
        id="MK-I11", module=_ID, enclosing="_port_bounds",
        before="0 <= low", after="0 < low", line_hint=342,
        behaviour="port 0 abstains as though it were outside 0..65535. The chain "
                  "carries three `<=`, so the slice names the FIRST comparison",
        must_fail=(_TD + "test_port_zero_is_a_legal_port",),
        owner=_IOWNER),
    Mutation(
        id="MK-I12", module=_ID, enclosing="_port_bounds",
        before="high <= 65535", after="high <= 65536", line_hint=342,
        behaviour="the port upper bound is relaxed so the impossible port 65536 "
                  "is accepted instead of abstaining by name. Widened past the "
                  "bare 65535, which the abstention message spells too",
        must_fail=(_TD + "test_the_last_port_is_65535_and_one_past_it_abstains_by_name",),
        owner=_IOWNER),
    Mutation(
        id="MK-I13", module=_ID, enclosing="_guarded.extract",
        before="exc_info=True", after="exc_info=False", line_hint=548,
        behaviour="the extractor-failed debug record loses its traceback. SAME "
                  "TRAP as MK-P08: logging stores the literal False, so "
                  "`exc_info is not None` still passes -- only truthiness kills it",
        must_fail=(_TD + "test_a_crashing_domain_extractor_logs_its_traceback",),
        owner=_IOWNER),
    Mutation(
        id="MK-I14", module=_IS, enclosing="RuleContext",
        before="frozen=True", after="frozen=False", line_hint=112,
        behaviour="RuleContext stops being frozen, so a tier can mutate the one "
                  "record all three consult and it is no longer hashable",
        must_fail=(_TS + "test_rule_context_is_frozen_and_hashable",),
        owner=_IOWNER),
    Mutation(
        id="MK-I15", module=_IS, enclosing="CompiledRule.evaluate",
        before='                return Verdict("unverified", f"sec:{domain}", pid, 0,\n'
               '                               f"{pid}: z3 is not available (solver '
               'backend {backend!r}) — "',
        after='                return Verdict("unverified", f"sec:{domain}", pid, 1,\n'
              '                               f"{pid}: z3 is not available (solver '
              'backend {backend!r}) — "',
        line_hint=219,
        behaviour="the solver-not-available abstention points at line 1 of a "
                  "document that has no lines. Widened by its message line: the "
                  "not-evaluated abstention above it opens identically",
        must_fail=(_TS + "test_the_z3_absent_abstention_is_identified_and_carries_"
                         "no_line_number",),
        owner=_IOWNER),
    # -- ESC-GX-SEEDA-001 piece (c): the funnel's last fourteen. -------------
    Mutation(
        id="MK-I16", module=_IS, enclosing="CompiledRule._decide_closed",
        before='        return Verdict("contradicted", f"sec:{domain}", pid, 0,\n'
               '                       f"{pid}: the obligation is violated but no '
               'single record "',
        after='        return Verdict("contradicted", f"sec:{domain}", pid, 1,\n'
              '                       f"{pid}: the obligation is violated but no '
              'single record "',
        line_hint=264,
        behaviour="the lineno on \"the obligation is violated but no single "
                  "record witnesses it\", widened by its message line",
        must_fail=(_TS + "test_a_violation_no_single_record_witnesses_is_identified_"
                         "and_has_no_lineno",),
        owner=_IOWNER),
    Mutation(
        id="MK-I17", module=_IS, enclosing="CompiledRule._decide_open",
        before='            return Verdict("grounded", f"sec:{domain}", pid, 0,',
        after='            return Verdict("grounded", f"sec:{domain}", pid, 1,',
        line_hint=279,
        behaviour="the lineno on the open-or-validity grounded verdict",
        must_fail=(_TS + "test_the_validity_fallback_grounds_with_an_identity_and_"
                         "no_line_number",),
        owner=_IOWNER),
    Mutation(
        id="MK-I18", module=_IS, enclosing="_render_model",
        before="model_completion=True", after="model_completion=False",
        line_hint=332,
        behaviour="with completion off, unassigned terms render as bare symbol "
                  "names instead of concrete values, so a contradicted verdict's "
                  "counter-model stops being concrete evidence while still "
                  "reading like one",
        must_fail=(_TS + "test_a_counter_model_renders_a_value_for_every_term",),
        owner=_IOWNER),
    Mutation(
        id="MK-I19", module=_IS, enclosing="_org_constraint_name",
        before="name.split(marker, 1)", after="name.split(marker, 2)",
        line_hint=474,
        behaviour="the MAXSPLIT of the org-policy name split, not an index: with "
                  "maxsplit 2 a name containing two policy markers yields a "
                  "different constraint id",
        must_fail=(_TS + "test_the_constraint_id_is_the_whole_tail_after_the_"
                         "first_marker",),
        owner=_IOWNER),
    Mutation(
        id="MK-I20", module=_IS, enclosing="org_policy_rules",
        before="if not isinstance(policy, Mapping):",
        after="if isinstance(policy, Mapping):", line_hint=487,
        behaviour="CATASTROPHIC AND FREE TODAY: a VALID org policy returns "
                  "immediately with \"the Org Policy is not a JSON object\", so the "
                  "org-policy rule tier ALWAYS abstains. It survives because "
                  "nothing in the whole suite drives that tier with a real "
                  "org-policy document",
        must_fail=(_TS + "test_a_real_org_policy_yields_records_and_no_reason",),
        owner=_IOWNER),
    Mutation(
        id="MK-I21", module=_IS, enclosing="org_policy_rules",
        before='bool(rule.get("enforce", False))',
        after='bool(rule.get("enforce", True))', line_hint=507,
        behaviour="an ABSENT enforce key records enforce True — a silent inversion "
                  "of the org-policy enforcement dimension, which is decision-"
                  "relevant and is exactly the axis gx-org-prior-content reasons over",
        must_fail=(_TS + "test_an_absent_enforce_key_records_enforce_false",),
        owner=_IOWNER),
    Mutation(
        id="MK-I22", module=_IS, enclosing="org_policy_rules",
        before="if not isinstance(entry, str):",
        after="if isinstance(entry, str):", line_hint=521,
        behaviour="the surprise guard inverted, so string entries refuse and "
                  "non-string entries are appended into records",
        must_fail=(_TS + "test_a_list_of_strings_is_accepted_and_a_non_string_"
                         "entry_refuses",),
        owner=_IOWNER),
    Mutation(
        id="MK-I23", module=_IS, enclosing="_carry_verdict",
        before='        return Verdict("unverified", f"sec:{promise.domain}", '
               'promise.id, 0,',
        after='        return Verdict("unverified", f"sec:{promise.domain}", '
              'promise.id, 1,',
        line_hint=567,
        behaviour="the lineno on the not-run verdict for a rejected or failed "
                  "promise, sliced with the REJECTED arm's own indent",
        must_fail=(_TS + "test_a_carry_verdict_names_the_requirement_and_has_no_"
                         "line_number",),
        owner=_IOWNER),
    Mutation(
        id="MK-I24", module=_IS, enclosing="_admit",
        before='"integrity was not verified; the rule was registered")], True)',
        after='"integrity was not verified; the rule was registered")], False)',
        line_hint=595,
        behaviour="NOT a lineno: it is the REGISTER flag returned on the "
                  "unsupported-term path, whose own message says the rule WAS "
                  "registered. The mutant makes the message lie and silently "
                  "unregisters a rule whose stored AST cannot be re-encoded",
        must_fail=(_TS + "test_an_unsupported_term_registers_the_rule_its_message_"
                         "says_it_registered",),
        owner=_IOWNER),
    Mutation(
        id="MK-I25", module=_IS, enclosing="_admit",
        before="if positive_ok is None or negative_ok is None:",
        after="if positive_ok is None and negative_ok is None:", line_hint=616,
        behaviour="ONE undecidable pinned witness stops reporting \"a pinned "
                  "witness could not be re-classified\" and integrity reads as "
                  "fully verified — an abstention silently converted into a "
                  "positive, RC1's shape at the artifact tier",
        must_fail=(_TS + "test_one_undecidable_witness_is_reported_and_the_rule_"
                         "still_registers",),
        owner=_IOWNER),
    Mutation(
        id="MK-I26", module=_IS, enclosing="load_rules",
        before='        verdicts.append(Verdict("contradicted", "sec:artifact", pid, 0,',
        after='        verdicts.append(Verdict("contradicted", "sec:artifact", pid, 1,',
        line_hint=664,
        behaviour="the lineno on the duplicate-promise-id-across-artifacts verdict",
        must_fail=(_TS + "test_a_duplicate_promise_id_is_identified_and_has_no_"
                         "line_number",),
        owner=_IOWNER),
    Mutation(
        id="MK-I27", module=_IR, enclosing="_stands_on_nothing",
        before="led.collections_read > 0 and", after="led.collections_read > 0 or",
        line_hint=220,
        behaviour="the downgrade predicate THIS TASK writes — already killed by "
                  "this task's own tests. Named so it stays killed",
        must_fail=(_TF + "test_a_check_that_reads_nothing_is_not_downgraded",),
        owner=_IOWNER),
    Mutation(
        id="MK-I28", module=_IR, enclosing="_stands_on_nothing",
        before="led.rows_examined == 0", after="led.rows_examined == 1",
        line_hint=220,
        behaviour="the `rows_examined == 0` comparison in the same predicate, "
                  "which is also the REGISTERED predicate — already killed. "
                  "Named so it stays killed",
        must_fail=(_TF + "test_a_decision_over_an_empty_collection_is_downgraded",),
        owner=_IOWNER),
    Mutation(
        id="MK-I29", module=_IS, enclosing="CompiledRule._decide_closed",
        before='("; " + "; ".join(observed_empty))',
        after='("; " - "; ".join(observed_empty))', line_hint=248,
        behaviour="on the line this task writes in the compiled-rule tier — "
                  "already killed. Named so it stays killed",
        must_fail=(_TS + "test_attested_empty_collection_keeps_the_quantifier_"
                         "semantics",),
        owner=_IOWNER),
)


@dataclass(frozen=True)
class SeededRemoval(Removal):
    """The FROZEN ``Removal`` plus the three fields seed-a's body mandates and
    that type lacks -- ESC-GX-SEEDA-001's finding, answered by SUBCLASSING and
    never by dropping one. ``owner`` is REQUIRED: no family is parked forever."""

    owner: str = ""
    pending: bool = True
    spelling: str = ""


AFTER_COLLECTION = ("monkeypatched after collection; the family's cases keep "
                    "RUNNING and must FAIL on the verdicts that stop existing")
IMPORT_TIME = ("bound to None in sys.modules; its probes go false and its cases "
               "SKIP, so must_fail names the not-all-cases-may-skip guard and "
               "the capability-liveness assertion")
RE_MEASURED = ("bound to None in sys.modules AFTER collection, so the marks are "
               "already fixed and nothing skips; the two guards named below "
               "RE-MEASURE the probes instead of reading a memo taken before "
               "the removal, and both go RED when the plane cannot decide")


def _patch(monkeypatch, module: str, **fields) -> None:
    target = import_module(module)
    for name, value in fields.items():
        monkeypatch.setattr(target, name, value)


def _unimport(monkeypatch, *names: str) -> None:
    for name in names:
        monkeypatch.setitem(sys.modules, name, None)
    import_module("gcp_grounding.registry").reset_cache()


_AI = ("tests/test_gcp_agentic_iam.py::"
       "test_adversarial_proposal_is_blocked_or_recorded[")
_AN, _AV = "tests/test_gcp_agentic_network.py::", "tests/test_gcp_agentic_vpcsc.py::"
_AB = "tests/test_gcp_agentic_abstain.py::"

#: `gx-agentic-benign-repin`'s six, and the nodes each reddens.
_BG = "tests/test_gcp_agentic_benign.py::"
_BID = _BG + "test_spot_checked_turns_ground_the_claims_by_identity["
_BPAIR = _BG + "test_the_paired_hook_really_opened_that_path["
_BOWNER = "gx-agentic-benign-repin"
IN_PROCESS = ("monkeypatched after collection; the benign module's report and its "
              "hook MIRROR both run IN PROCESS, which is where a removal reaches "
              "them -- it can never reach a spawned child")


def _drop_claim_kind(monkeypatch, kind: str) -> None:
    """Take away exactly the claims of one KIND, at BOTH bindings: `preflight` and
    `tf_claims` each did `from .claims import iam_policy_claims`, so patching
    `claims` alone leaves the plan turn holding what the IAM turn lost."""
    real = import_module("gcp_grounding.claims").iam_policy_claims
    without = lambda policy: [c for c in real(policy) if c.kind != kind]  # noqa: E731
    for module in ("gcp_grounding.preflight", "gcp_grounding.tf_claims"):
        _patch(monkeypatch, module, iam_policy_claims=without)


def _drop_extractor(monkeypatch, rtype: str) -> None:
    """Empty ONE terraform resource type's extractor, leaving the walker's own
    unconditional `resource_type_ref` claim and nothing else -- the exact state
    the design measured a grounded-COUNT floor staying green over."""
    table = import_module("gcp_grounding.tf_claims")._EXTRACTORS
    _patch(monkeypatch, "gcp_grounding.tf_claims",
           _EXTRACTORS=dict(table, **{rtype: lambda address, values: []}))

#: `gx-agentic-secreq-repin`'s two, and the nodes each reddens. A BENIGN case
#: cannot tell a real positive from a rubber-stamped one — silence is exactly
#: what a rule set that stopped deciding produces — so both name VIOLATING nodes
#: only, and never one of the false-positive-budget cases.
_SQ = "tests/test_gcp_agentic_secreq.py::"
_SOWNER = "gx-agentic-secreq-repin"
SECREQ_IN_PROCESS = ("monkeypatched after collection; the secreq module's report "
                     "sidecars are an IN-PROCESS `cli.main` mirror, which is "
                     "where a removal reaches them — the hook runs beside them "
                     "stay children and are untouched, so each named node fails "
                     "on its report assertion and not on its block")


def _mute_rule_evaluator(monkeypatch) -> None:
    """Take away THE RULE EVALUATOR: every compiled requirement returns the
    not-applicable answer, so no promise ever reaches a verdict."""
    sec_rules = import_module("gcp_grounding.sec_rules")
    monkeypatch.setattr(sec_rules.CompiledRule, "evaluate",
                        lambda self, ctx: None)


def _empty_the_artifact_writer(monkeypatch) -> None:
    """Take away THE ARTIFACT WRITER's promise records: what it serialises is a
    well-formed ``*.promises.json`` holding no promise at all."""
    sec_artifact = import_module("gcp_grounding.sec_artifact")
    real = sec_artifact.dumps
    monkeypatch.setattr(sec_artifact, "dumps",
                        lambda doc: real(replace(doc, promises=())))


#: The path ``RM-HOOK-WRONG-FILE``'s mutant grounds instead of the event's. A
#: repo-relative path that DOES NOT EXIST, so the hook reaches the gate, the
#: gate opens nothing, and the abstention it prints names this file and not the
#: one the agent edited -- the same answer on every backend.
_HARDCODED = str(Path(__file__).resolve().parents[1]
                 / "hardcoded_by_the_mutant.policy.json")

#: The RC2-measured removals: the review EXECUTED each -- 19 of 19, 27 of 27,
#: 22 of 27, 10 of 14 green with the subject GONE -- so each is a must-kill and
#: not a hypothesis. Each names the task that must make it live and whose body
#: requires the nodes that do not collect TODAY; the three `gx-agentic-iam-repin`
#: owns are LIVE, so the frozen gate EXECUTES them, and five stay `pending`.
REMOVALS: tuple[SeededRemoval, ...] = (
    SeededRemoval(
        id="RM-IAM-ESCALATION-LAYER", family="iam",
        subject="iam_checks.DOCUMENT_CHECKS, the escalation decision layer",
        apply=lambda mp: _patch(mp, "gcp_grounding.iam_checks", DOCUMENT_CHECKS=()),
        must_fail=(_AI + "A07_sa_token_creator]", _AI + "A08_sa_user_actas]",
                   _AI + "A09_owner_to_real_principal]"),
        owner="gx-agentic-iam-repin", pending=False, spelling=AFTER_COLLECTION),
    SeededRemoval(
        id="RM-IAM-PUBLIC-PRINCIPAL-KIND", family="iam",
        subject="the public_principal claim kind, dropped from claims.KINDS",
        apply=lambda mp: _patch(mp, "gcp_grounding.claims", KINDS=tuple(
            k for k in import_module("gcp_grounding.claims").KINDS
            if k != "public_principal")),
        must_fail=(_AI + "A11_allusers_public]",),
        owner="gx-agentic-iam-repin", pending=False, spelling=AFTER_COLLECTION),
    SeededRemoval(
        id="RM-IAM-MEMBER-EXTRACTION", family="iam",
        subject="iam_checks._MEMBER_KINDS: the escalation check stops pairing a "
                "binding's role with the members it was granted to",
        apply=lambda mp: _patch(mp, "gcp_grounding.iam_checks", _MEMBER_KINDS=()),
        must_fail=(_AI + "A07_sa_token_creator]",
                   _AI + "A09_owner_to_real_principal]",
                   _AI + "A19_escalation_role_to_public]"),
        owner="gx-agentic-iam-repin", pending=False, spelling=AFTER_COLLECTION),
    SeededRemoval(
        id="RM-NETWORK-PLANE-UNAVAILABLE", family="network",
        subject="fw_checks, fw_estate, hfw_checks and armor_checks — the whole "
                "network-plane check layer the catalogue is decided by",
        # armor_checks and fw_estate join the two the seed named. MEASURED on
        # HEAD's module: renaming all FOUR away leaves it 19 of 19 GREEN, which
        # is the defect; renaming only three leaves A01 still blocked by the
        # estate tier, and renaming only the seed's two leaves the armor
        # capability live, both guards passing, and the removal SURVIVING.
        #
        # STILL `pending`, and NOT because it does not kill: MEASURED both ways
        # in this checkout, both nodes report FAILED under the mutant and
        # PASSED on clean source. It cannot be flipped live from here on the
        # SPAWN CEILING alone -- ESC-GX-NETWORK-REMOVAL-CEILING, which carries
        # the arithmetic.
        apply=lambda mp: _unimport(mp, "gcp_grounding.fw_checks",
                                   "gcp_grounding.fw_estate",
                                   "gcp_grounding.hfw_checks",
                                   "gcp_grounding.armor_checks"),
        must_fail=(_AN + "test_not_every_network_case_may_skip",
                   _AN + "test_the_network_capabilities_are_live"),
        owner="gx-agentic-network-repin", spelling=RE_MEASURED),
    SeededRemoval(
        id="RM-NETWORK-PAIR-CHECKS", family="network",
        subject="fw_checks.PAIR_CHECKS, the packet-set non-enlargement map",
        apply=lambda mp: _patch(mp, "gcp_grounding.fw_checks", PAIR_CHECKS={}),
        must_fail=(_AN + "test_the_pair_check_decides_a_widening_against_a_"
                         "baseline",),
        owner="gx-agentic-network-repin", pending=False,
        spelling=AFTER_COLLECTION),
    SeededRemoval(
        id="RM-NETWORK-VOCABULARY-KIND", family="network",
        subject="the resource_type verdict kind, renamed where the Datalog "
                "pass maps a claim kind to its snapshot category",
        apply=lambda mp: _patch(
            mp, "gcp_grounding.reasoner",
            _CLAIM_CATEGORIES=dict(
                import_module("gcp_grounding.reasoner")._CLAIM_CATEGORIES,
                resource_type_ref="resource_kind")),
        must_fail=(_AN + "test_the_false_vocabulary_block_guard_can_fire_and_"
                         "is_silent",),
        owner="gx-agentic-network-repin", pending=False,
        spelling=AFTER_COLLECTION),
    SeededRemoval(
        id="RM-VPCSC-DOCUMENT-AND-PAIR-CHECKS", family="vpcsc",
        subject="vpcsc_checks.DOCUMENT_CHECKS and PAIR_CHECKS, unregistered",
        apply=lambda mp: _patch(mp, "gcp_grounding.vpcsc_checks",
                                DOCUMENT_CHECKS=(), PAIR_CHECKS={}),
        # RETARGETED ON MEASUREMENT, never widened: the seed named A05, A24 and
        # A25, and all three drive the gate in a CHILD process, which an
        # after-collection monkeypatch of the parent cannot reach -- measured,
        # all three still PASSED with both tables emptied. The three nodes below
        # ground IN PROCESS, one per half of what this removal takes: the pair
        # check, the document check's estate arm, and its solver arm.
        must_fail=(_AV + "test_the_pair_check_decides_a_removal_against_a_"
                         "baseline",
                   _AV + "test_an_uncaptured_perimeter_category_abstains_once_"
                         "per_perimeter",
                   _AV + "test_a_widening_against_a_narrow_previous_policy_is_"
                         "decided"),
        owner="gx-agentic-vpcsc-repin", spelling=AFTER_COLLECTION),
    SeededRemoval(
        id="RM-VPCSC-DOMAIN-UNREGISTERED", family="vpcsc",
        subject="the whole VPC-SC domain: vpcsc_checks and vpcsc_claims",
        apply=lambda mp: _unimport(mp, "gcp_grounding.vpcsc_checks",
                                   "gcp_grounding.vpcsc_claims"),
        must_fail=(_AV + "test_not_every_vpcsc_case_may_skip",
                   _AV + "test_the_vpcsc_capabilities_are_live"),
        owner="gx-agentic-vpcsc-repin", spelling=IMPORT_TIME),
    SeededRemoval(
        id="RM-VPCSC-ABSENT-VERSUS-EMPTY", family="vpcsc",
        subject="vpcsc_checks._unreadable_field, the record-level "
                "absent-versus-empty guard",
        apply=lambda mp: _patch(mp, "gcp_grounding.vpcsc_checks",
                                _unreadable_field=lambda *a, **k: None),
        must_fail=(_AV + "test_a_removed_policy_list_yields_the_absent_versus_"
                         "empty_abstention",),
        owner="gx-agentic-vpcsc-repin", spelling=AFTER_COLLECTION),
    SeededRemoval(
        id="RM-HOOK-SUCCESS-BEFORE-THE-EVENT", family="abstain",
        subject="cli._run_hook: the hook returns success as its FIRST "
                "statement, never reading the event",
        apply=lambda mp: _patch(mp, "gcp_grounding.cli", _run_hook=lambda args: 0),
        # MEASURED BOTH WAYS in this checkout. Before `gx-agentic-abstain-repin`
        # this removal killed NOTHING: every one of the module's 14 cases drove
        # the hook in a CHILD process, which an after-collection monkeypatch of
        # the PARENT cannot reach, so all 14 PASSED with the subject gone. The
        # repin gives every case an IN-PROCESS mirror of the same
        # `cli._run_hook`, and under the mutant all three nodes below now report
        # FAILED and all three PASS on clean source.
        #
        # STILL `pending`, and NOT because it does not kill:
        # `contract_spawn_ceiling()` is `4*len(register()) +
        # len(removal_register()) + CONTRACT_CONTROL_SPAWNS`, and a full run
        # measures the marked total at exactly the ceiling. A NEW live removal
        # is net zero (one slot, one `-rA` child); flipping an ALREADY-COUNTED
        # one from pending to live is +1 spawn and +0 slots, so it overflows by
        # exactly one whatever else the diff does. This task's NEW removal below
        # is therefore the live one -- ESC-GX-ABSTAIN-REMOVAL-CEILING carries
        # the arithmetic, exactly as ESC-GX-NETWORK-REMOVAL-CEILING does.
        must_fail=(_AB + "test_c01_raw_hcl_abstains_and_never_blocks",
                   _AB + "test_c04_unrecognized_kind_abstains_naming_the_keys",
                   _AB + "test_c08_uncaptured_category_is_unverified_never_ungrounded"),
        owner="gx-agentic-abstain-repin", spelling=AFTER_COLLECTION),
    SeededRemoval(
        id="RM-HOOK-WRONG-FILE", family="abstain",
        subject="cli._hook_file_path: the hook ignores the event's path and "
                "grounds a hardcoded one instead",
        # The second mutant `gx-agentic-abstain-repin` records: a hook that
        # never reads the event's `file_path` still exits 0 with byte-empty
        # stdout and still abstains -- about a document nobody edited -- which
        # left 11 of that module's 14 cases green before the repin. The
        # hardcoded path is deliberately one that does not exist, so the mutant
        # is world-independent: the gate opens it, fails to READ it, and prints
        # a reason no case here asks for, whatever the solver backend is.
        apply=lambda mp: _patch(mp, "gcp_grounding.cli",
                                _hook_file_path=lambda event: _HARDCODED),
        must_fail=(_AB + "test_c01_raw_hcl_abstains_and_never_blocks",
                   _AB + "test_c04_unrecognized_kind_abstains_naming_the_keys",
                   _AB + "test_c08_uncaptured_category_is_unverified_never_ungrounded",
                   _AB + "test_a_document_whose_grants_were_never_read_is_not_a_"
                         "verdictless_pass[bindings_key_mis_cased]",
                   _AB + "test_c10_bad_baseline_abstains_on_the_subset"
                         "[nonexistent_path]"),
        owner="gx-agentic-abstain-repin", pending=False,
        spelling=AFTER_COLLECTION),
    # THE FIVE CLAIM-EXTRACTION DELETIONS AND THE EMPTIED HOOK SUFFIX SET, the six
    # `gx-agentic-benign-repin` measured. BEFORE that repin all six left
    # tests/test_gcp_agentic_benign.py GREEN -- 19 of 19 passed, each mutant applied
    # alone to a `git archive HEAD` copy -- because the spot-checks asserted a
    # grounded COUNT and the hook was asserted only for silence. AFTER it each node
    # below reports FAILED and every one PASSES on clean source. All six are LIVE:
    # a NEW live removal is one slot and one `-rA` child, net zero on
    # `contract_spawn_ceiling()`, so none of them needs the flip
    # ESC-GX-ABSTAIN-REMOVAL-CEILING records as unaffordable.
    SeededRemoval(
        id="RM-BENIGN-PLAN-MEMBER-EXTRACTION", family="iam",
        subject="the plan walker's whole role and principal extraction for "
                "google_project_iam_member",
        apply=lambda mp: _drop_extractor(mp, "google_project_iam_member"),
        must_fail=(_BID + "B06_tfplan_iam_member]",
                   _BPAIR + "B06_tfplan_iam_member]"),
        owner=_BOWNER, pending=False, spelling=IN_PROCESS),
    SeededRemoval(
        id="RM-BENIGN-ROLE-CLAIMS", family="iam",
        subject="every role claim an IAM policy makes, at both extractor bindings",
        apply=lambda mp: _drop_claim_kind(mp, "role"),
        must_fail=(_BID + "B02_iam_grant_data_eng]",
                   _BID + "B06_tfplan_iam_member]"),
        owner=_BOWNER, pending=False, spelling=IN_PROCESS),
    SeededRemoval(
        id="RM-BENIGN-PRINCIPAL-CLAIMS", family="iam",
        subject="every principal claim an IAM policy makes, at both bindings",
        apply=lambda mp: _drop_claim_kind(mp, "principal"),
        must_fail=(_BID + "B02_iam_grant_data_eng]",
                   _BID + "B06_tfplan_iam_member]"),
        owner=_BOWNER, pending=False, spelling=IN_PROCESS),
    SeededRemoval(
        id="RM-BENIGN-CUSTOM-ROLE-PERMISSIONS", family="iam",
        subject="every permission claim a google_project_iam_custom_role makes",
        apply=lambda mp: _drop_extractor(mp, "google_project_iam_custom_role"),
        must_fail=(_BID + "B07_tfplan_custom_role]",),
        owner=_BOWNER, pending=False, spelling=IN_PROCESS),
    SeededRemoval(
        id="RM-BENIGN-CONSTRAINT-EXISTENCE", family="orgpolicy",
        subject="the constraint-existence claim an org policy makes, leaving only "
                "its value-type one",
        apply=lambda mp: _patch(
            mp, "gcp_grounding.preflight",
            org_policy_claims=lambda policy: [
                c for c in import_module("gcp_grounding.claims").org_policy_claims(
                    policy) if c.kind != "constraint"]),
        must_fail=(_BID + "B04_orgpolicy_shielded_vm]",),
        owner=_BOWNER, pending=False, spelling=IN_PROCESS),
    SeededRemoval(
        id="RM-BENIGN-HOOK-SUFFIXES", family="abstain",
        subject="cli._HOOK_SUFFIXES: the hook recognizes no file as a policy "
                "document, so it grounds nothing and can never block",
        apply=lambda mp: _patch(mp, "gcp_grounding.cli", _HOOK_SUFFIXES=()),
        must_fail=(_BPAIR + "B02_iam_grant_data_eng]",
                   _BPAIR + "B04_orgpolicy_shielded_vm]",
                   _BPAIR + "B06_tfplan_iam_member]"),
        owner=_BOWNER, pending=False, spelling=IN_PROCESS),
    # THE REQUIREMENTS CAPSTONE'S TWO, the halves a compiled promise stands on:
    # the thing that DECIDES it and the thing that WRITES it down. Both are LIVE
    # (a new live removal is one slot and one `-rA` child, net zero on
    # `contract_spawn_ceiling()`), and both were MEASURED both ways in this
    # checkout: every node below reports FAILED under its removal and PASSES on
    # clean source.
    SeededRemoval(
        id="RM-SECREQ-RULE-EVALUATOR", family="secreq",
        subject="sec_rules.CompiledRule.evaluate, the compiled-requirement "
                "evaluator — every promise answers not-applicable and none "
                "ever reaches a verdict",
        apply=_mute_rule_evaluator,
        must_fail=(_SQ + "test_S03_agent_violates_each_promise",
                   _SQ + "test_S03b_the_perimeter_vacuity_is_blocked",
                   _SQ + "test_S09_the_pruned_artifact_still_blocks"),
        owner=_SOWNER, pending=False, spelling=SECREQ_IN_PROCESS),
    SeededRemoval(
        id="RM-SECREQ-ARTIFACT-WRITER", family="secreq",
        subject="the promise records sec_artifact.dumps writes: the artifact is "
                "still well-formed and still loads, and holds no promise",
        apply=_empty_the_artifact_writer,
        # ONE node, and a violating one on purpose. The pruned artifact this
        # module builds in process is the false-positive budget's instrument,
        # and an instrument that lost its rules is BYTE-SILENT — which is what
        # the benign cases assert. Only a document that must be REFUTED can tell
        # the two apart.
        must_fail=(_SQ + "test_S09_the_pruned_artifact_still_blocks",),
        owner=_SOWNER, pending=False, spelling=SECREQ_IN_PROCESS),
)


# -- the IAM-deny pair's twelve must-kills, PARKED -----------------------------
#
# MK-D01..MK-D12 belong to designs/gcp-iam-deny.md (owner task
# `gx-iam-deny-pair`). They are seeded HERE as data but deliberately NOT in
# :data:`ENTRIES`: the frozen flip test executes every ACTIVE entry against a
# fresh ``git archive HEAD`` copy, and the session that landed the deny pair
# may not commit — an ACTIVE entry whose anchor and witnesses exist only in
# the working tree reddens the machinery on every full run. The state machine
# offers no honest parking spot either (AWAITING is forbidden while the owner
# is present, and the AWAITING pins are shrink-only), so the entries wait as
# data under ESC-DENY-REGISTER-ACTIVATION, whose strict-xfail node —
# tests/test_gcp_iam_deny_checks.py::
# test_the_deny_mutation_entries_are_active_in_the_register — XPASSes (and so
# reddens the suite) the moment they are moved into ENTRIES, forcing the
# escalation to be retired deliberately. REQUIRED_MK_IDS already names all
# twelve, so the gate's required-id xfail carries them as visible debt.
#
# SOURCE OF EVERY ``must_fail``, recorded once because it is the same for all:
# this checkout's collect-only pass. Each entry below was then MEASURED, not
# read — per the register's doctrine with ONE recorded substitution: the
# scratch copy was a full copy of the WORKING TREE (a git archive cannot
# contain uncommitted code). Unmutated copy green over the 16-node union;
# each mutant applied ALONE through tests.mutation_contract.mutate (the same
# scope-confined rewrite the flip test runs); every named node observed
# FAILED via ``-rA``. ``line_hint`` is the line the rewrite landed on at
# measurement time.

_DD = "gcp_grounding/sec_domains.py"
_DC = "gcp_grounding/iam_deny_checks.py"
_DOWNER = "gx-iam-deny-pair"
_TDD = "tests/test_gcp_deny_domains.py::"
_TDC = "tests/test_gcp_iam_deny_checks.py::"

DENY_ENTRIES: tuple[Mutation, ...] = (
    Mutation(
        id="MK-D01", module=_DD, enclosing="_deny_walk",
        before="            effective = [p for p in denied_norm if p not in excepted_norm]",
        after="            effective = [p for p in denied_norm]",
        line_hint=1441,
        behaviour="the exceptionPermissions subtraction is dropped, so an "
                  "excepted permission mints a deny_rules row stating a "
                  "falsehood the strong promise grounds on",
        must_fail=(_TDD + "test_permission_exceptions_are_subtracted_before_rows_exist",),
        owner=_DOWNER),
    Mutation(
        id="MK-D02", module=_DD, enclosing="_deny_walk",
        before='                "has_principal_exceptions": bool(entries["exception_principals"]),',
        after='                "has_principal_exceptions": not bool(entries["exception_principals"]),',
        line_hint=1444,
        behaviour="the no-principal-exceptions conjunct inverts: the strong "
                  "promise grounds on a policy WITH a carve-out",
        must_fail=(_TDD + "test_principal_exceptions_set_the_bool_and_mint_exception_rows",),
        owner=_DOWNER),
    Mutation(
        id="MK-D03", module=_DD, enclosing="_deny_walk",
        before='                           for p in entries["denied_permissions"]]',
        after='                           for p in entries["denied_permissions"] if module._normalize_permission(p) is not None]',
        line_hint=1438,
        behaviour="a wildcard deny permission silently drops its row instead "
                  "of aborting the rule naming the raw string",
        must_fail=(_TDD + "test_a_wildcard_permission_aborts_the_rule_naming_the_raw_string",),
        owner=_DOWNER),
    Mutation(
        id="MK-D04", module=_DD, enclosing="_deny_walk",
        before="        if tf and rules and not unit:",
        after="        if tf and rules and not unit and False:",
        line_hint=1410,
        behaviour="the plan census is disabled: a deny block that yielded no "
                  "readable claims loses its by-name census abstention",
        must_fail=(_TDD + "test_a_deny_block_that_yielded_no_claims_aborts_by_census",),
        owner=_DOWNER),
    Mutation(
        id="MK-D05", module=_DD, enclosing="_deny_condition",
        before="    return {}",
        after='    return {"has_condition": False, "condition": ""}',
        line_hint=1493,
        behaviour="an unreadable denialCondition block reads as no condition, "
                  "so the unconditional promise is satisfied over a condition "
                  "nobody read",
        must_fail=(_TDD + "test_an_unreadable_condition_block_omits_both_keys",),
        owner=_DOWNER),
    Mutation(
        id="MK-D06", module=_DC, enclosing="_member_in",
        before="    if spelling == PUBLIC_ALL:",
        after="    if spelling == member_v2 == PUBLIC_ALL:",
        line_hint=197,
        behaviour="the public:all universal arm reads exact-match only, so a "
                  "deny of everyone covers nobody and the masked-grant "
                  "warning vanishes",
        must_fail=(_TDC + "test_public_all_is_the_universal_set",
                   _TDC + "test_c1_masks_the_grant_and_names_rule_resource_and_class"),
        owner=_DOWNER),
    Mutation(
        id="MK-D07", module=_DC, enclosing="_member_in",
        before='        return _Tri("undecided", f"group membership of {member_v1!r} in {spelling!r} is not captured in any snapshot category")',
        after='        return _Tri("yes", f"group membership of {member_v1!r} in {spelling!r} is not captured in any snapshot category")',
        line_hint=208,
        behaviour="group-set containment fabricates TRUE from unknowable "
                  "membership: a masking warning is minted where the honest "
                  "answer is unverified naming the group",
        must_fail=(_TDC + "test_group_membership_is_undecided_by_name",
                   _TDC + "test_c1_group_coverage_abstains_naming_the_group_not_a_warning"),
        owner=_DOWNER),
    Mutation(
        id="MK-D08", module=_DC, enclosing="_covered",
        before='    if state == "covered" and rule.condition_state == "present":',
        after='    if state == "covered" and rule.condition_state != "present":',
        line_hint=443,
        behaviour="a conditional deny rule claims coverage (and an "
                  "unconditional one abstains): request-time truth is decided "
                  "offline",
        must_fail=(_TDC + "test_a_conditional_rule_cannot_prove_coverage",
                   _TDC + "test_c1_a_conditional_deny_rule_abstains_naming_the_condition"),
        owner=_DOWNER),
    Mutation(
        id="MK-D09", module=_DC, enclosing="_wake_findings",
        before='        status = "contradicted" if (escalation_class or public) else "grounded"',
        after='        status = "grounded" if (escalation_class or public) else "grounded"',
        line_hint=1098,
        behaviour="a woken escalation-class (or public) grant no longer "
                  "blocks: the guardrail-removal polarity is lost in both the "
                  "plan (C3) and pair (C4) arcs",
        must_fail=(_TDC + "test_c3_deleting_the_guardrail_wakes_the_dormant_escalation_grant",
                   _TDC + "test_c4_dropping_the_rule_wakes_the_dormant_grant"),
        owner=_DOWNER),
    Mutation(
        id="MK-D10", module=_DC, enclosing="check_deny_pair",
        before='    reason = _require_complete(ctx.snapshot, "iam_bindings")',
        after='    reason = None  # _require_complete(ctx.snapshot, "iam_bindings")',
        line_hint=1217,
        behaviour="the C4 self-gate is removed: a clean 'wakes nothing' is "
                  "stated over a partial iam_bindings view",
        must_fail=(_TDC + "test_c4_self_gates_the_clean_answer_on_iam_bindings_coverage",),
        owner=_DOWNER),
    Mutation(
        id="MK-D11", module="gcp_grounding/cli.py", enclosing="_decision_lines",
        before='        0 if (v.kind in ("iam_escalation", "iam_scope_diff", "iam_deny_shadow",',
        after='        0 if (v.kind in ("iam_escalation", "iam_scope_diff",',
        line_hint=3087,
        behaviour="iam_deny_shadow loses its JUDGMENT taste seat: a deny "
                  "interaction abstention trails the coverage noise and falls "
                  "out of the capped decision block",
        must_fail=(_TDC + "test_the_deny_shadow_abstention_leads_the_decision_blocks_taste",),
        owner=_DOWNER),
    Mutation(
        id="MK-D12", module="gcp_grounding/knowledge.py",
        enclosing="_parse_iam_deny_policies",
        before="        if decoded not in agreed:",
        after="        if decoded not in agreed and False:",
        line_hint=364,
        behaviour="the key/attachment_point agreement rejection is removed: a "
                  "mismatched record is accepted and the containment walk can "
                  "govern the wrong node",
        must_fail=(_TDC + "test_a_mismatched_key_and_attachment_point_is_rejected",),
        owner=_DOWNER),
)


# -- the effective org-policy fold's fourteen, PARKED like DENY_ENTRIES ------
#
# The MK-F must-kills of the effective org-policy design (its own table names
# the family MK-E01..E14; the ids are seeded here as MK-F01..F14 because
# MK-E01..MK-E07 are ALREADY RESERVED in the gate's required-id tuple for
# gx-iam-escalation-evidence — designs/gcp-gx-fixes.md's closed exchange —
# and one id may not name two mutants). Seeded PARKED, not in ENTRIES, for
# exactly the reason ESC-DENY-REGISTER-ACTIVATION records for the deny
# twelve: this work lands UNCOMMITTED, and the frozen flip test executes
# every ACTIVE entry against a fresh `git archive HEAD` copy where these
# anchors and witness nodes do not exist. The activation debt is carried by
# tests/test_gcp_org_effective.py's strict-xfail
# `test_the_org_effective_mutation_entries_are_active_in_the_register`, which
# XPASSes — and forces a deliberate retirement — the day these move into
# ENTRIES.
#
# SOURCE OF EVERY ``must_fail``, recorded once because it is the same for
# all: this checkout's collect-only pass. Each entry below was then MEASURED,
# not read — per the register's doctrine with the deny block's ONE recorded
# substitution (a full copy of the WORKING TREE; a git archive cannot contain
# uncommitted code): unmutated copy green over the 14-node union, each mutant
# applied ALONE through tests.mutation_contract.mutate (the same
# scope-confined, one-line-differs rewrite the flip test runs), every named
# node observed FAILED via ``-rA``. ``line_hint`` is the line the rewrite
# landed on at measurement time.

_OE = "gcp_grounding/org_effective.py"
_FOWNER = "fx-org-effective"
_TOE = "tests/test_gcp_org_effective.py::"

ORG_EFFECTIVE_ENTRIES: tuple[Mutation, ...] = (
    Mutation(
        id="MK-F01", module=_OE, enclosing="_effective_bool",
        before="    for node in reversed(chain):",
        after="    for node in tuple(chain):",
        line_hint=478,
        behaviour="the nearest-first walk becomes root-first: an org-level "
                  "enforce overrides the project's own false, and the "
                  "disablement grounds",
        must_fail=(_TOE + "test_bool_nearest_set_wins",),
        owner=_FOWNER),
    Mutation(
        id="MK-F02", module=_OE, enclosing="_effective_bool",
        before='        if policy["reset"]:\n'
               '            return _default_bool(record, constraint)',
        after='        if policy["reset"]:\n'
              '            continue',
        line_hint=490,
        behaviour="a reset stops clearing: the walk continues past it and "
                  "the ancestor's enforce leaks through the "
                  "restore-the-default decision",
        must_fail=(_TOE + "test_bool_reset_restores_default",),
        owner=_FOWNER),
    Mutation(
        id="MK-F03", module=_OE, enclosing="_default_bool",
        before='    if default == "DENY":\n        return True',
        after='    if default == "DENY":\n        return False',
        line_hint=235,
        behaviour="an enforced-by-default constraint reads unenforced when "
                  "no policy is set anywhere on the chain",
        must_fail=(_TOE + "test_bool_default_deny_is_enforced",),
        owner=_FOWNER),
    Mutation(
        id="MK-F04", module=_OE, enclosing="_effective_list",
        before='                     "denied": parent["denied"] | local["denied"],',
        after='                     "denied": local["denied"],',
        line_hint=531,
        behaviour="the inherit union drops the parent's denied side: "
                  "inherited denials vanish and a widening grounds",
        must_fail=(_TOE + "test_list_inherit_merges_parent_values",),
        owner=_FOWNER),
    Mutation(
        id="MK-F05", module=_OE, enclosing="_effective_list",
        before='        if policy["inherit_from_parent"]:\n'
               '            parent = resolved(state)',
        after='        if True or policy["inherit_from_parent"]:\n'
              '            parent = resolved(state)',
        line_hint=528,
        behaviour="the replace branch merges like inherit: a replace that "
                  "drops the parent's allowlist reads as keeping it (or "
                  "abstains reaching for a default the walk should never "
                  "read)",
        must_fail=(_TOE + "test_list_replace_drops_parent_values",),
        owner=_FOWNER),
    Mutation(
        id="MK-F06", module=_OE, enclosing="_list_rows",
        before='    for value in sorted(state["allowed"] - state["denied"]):',
        after='    for value in sorted(state["allowed"]):',
        line_hint=566,
        behaviour="a both-sides value emits an allow row beside its deny "
                  "row; 'must not allow v' is falsely refuted by a state "
                  "that in fact denies v",
        must_fail=(_TOE + "test_deny_precedence_suppresses_allow_row",),
        owner=_FOWNER),
    Mutation(
        id="MK-F07", module=_OE, enclosing="_list_rows",
        before='    if state["deny_all"]:\n'
               '        rows.append({**base, "polarity": "deny", "value": "",\n'
               '                     "all_values": True})\n'
               '        return rows',
        after='    if state["deny_all"]:\n'
              '        rows.append({**base, "polarity": "deny", "value": "",\n'
              '                     "all_values": True})\n'
              '        pass  # the early return removed',
        line_hint=559,
        behaviour="the deny_all early return is removed: allow rows coexist "
                  "with an effective deny-all",
        must_fail=(_TOE + "test_deny_all_emits_no_allow_rows",),
        owner=_FOWNER),
    Mutation(
        id="MK-F08", module=_OE, enclosing="_policy_gates",
        before='        if rule["condition"]:',
        after='        if rule["condition"] and False:',
        line_hint=414,
        behaviour="a conditional rule is folded instead of abstaining: a "
                  "tag-gated rule decides the effective state offline",
        must_fail=(_TOE + "test_condition_on_chain_abstains_by_name",),
        owner=_FOWNER),
    Mutation(
        id="MK-F09", module=_OE, enclosing="_pol.resolve",
        before="        if entry is not None:",
        after='        if entry is not None and snapshot.org_policy(node, f"{_PREFIX}{constraint}") is None:',
        line_hint=837,
        behaviour="the overlay stops replacing the captured record it "
                  "targets: at a node with both, the OLD set-policy keeps "
                  "deciding and the proposal's replacement is ignored",
        must_fail=(_TOE + "test_rest_overlay_replaces_captured_policy",),
        owner=_FOWNER),
    Mutation(
        id="MK-F10", module=_OE, enclosing="_stated_key",
        before="    if len(stated) > 1:",
        after="    if len(stated) > 2:",
        line_hint=395,
        behaviour="an ambiguous two-key oneof rule decides on the first "
                  "stated key instead of abstaining",
        must_fail=(_TOE + "test_ambiguous_rule_abstains",),
        owner=_FOWNER),
    Mutation(
        id="MK-F11", module=_OE, enclosing="_chain",
        before="        record = table.get(cursor)",
        after='        record = table.get(cursor) or {"parent": None}',
        line_hint=176,
        behaviour="a dangling parent is treated as the root: a truncated "
                  "hierarchy silently shortens the fold",
        must_fail=(_TOE + "test_dangling_parent_abstains",),
        owner=_FOWNER),
    Mutation(
        id="MK-F12", module=_OE, enclosing="_universe",
        before="        if node in _chain(table, name):",
        after="        if node in _chain(table, name) and False:",
        line_hint=198,
        behaviour="the universe collapses to the proposal's own node: a "
                  "folder-level change's project-level effect goes unjudged",
        must_fail=(_TOE + "test_descendants_in_universe",),
        owner=_FOWNER),
    Mutation(
        id="MK-F13", module=_OE, enclosing="_estate_gates",
        before='    _require_complete(snapshot, "resource_hierarchy")',
        after='    _require_complete(snapshot, "org_policies")',
        line_hint=856,
        behaviour="the resource_hierarchy completeness check is dropped (a "
                  "second org_policies ask replaces it): a partial hierarchy "
                  "licenses the fold",
        must_fail=(_TOE + "test_partial_hierarchy_refused",),
        owner=_FOWNER),
    Mutation(
        id="MK-F14", module=_OE, enclosing="check_org_effective",
        before="        except _Undecidable as exc:\n"
               "            verdicts.append(Verdict(",
        after="        except _Undecidable as exc:\n"
              "            (lambda *_a, **_k: None)(Verdict(",
        line_hint=1071,
        behaviour="an undecidable before/after fold disappears from the "
                  "report instead of landing as one unverified per target",
        must_fail=(_TOE +
                   "test_an_undecidable_fold_is_on_the_record_never_skipped",),
        owner=_FOWNER),
)
