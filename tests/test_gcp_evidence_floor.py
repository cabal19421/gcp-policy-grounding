"""The evidence floor at the two invokers
(:func:`gcp_grounding.registry._invoke` and
:meth:`gcp_grounding.sec_rules.CompiledRule._collect`).

``preflight.ground_policy`` reaches domain CHECK code exclusively through
``registry.run_claim_checks`` / ``run_document_checks`` / ``run_pair_check``, all
of which call ``registry._invoke``, and it reaches PROMISE code exclusively
through ``sec_rules.CompiledRule.evaluate``, which collects its inputs through
``_collect`` over the ``EXTRACTORS`` table. Nothing bypasses those two, so the
floor is enforced there ONCE rather than remembered per domain.

Written as in-process unit tests over stub providers and stub extractors — fast,
offline, and independent of which domain modules are part of a given checkout.

THE FUNNEL'S ONE ACKNOWLEDGED EDGE: claim EXTRACTION runs UPSTREAM of both
funnels (``preflight._extract_claims`` and the provider ``DOCUMENT_EXTRACTORS`` /
``TF_EXTRACTORS`` tables build claims before any ledger is open), so an extractor
that silently produces zero claims is NOT downgraded here. That tier is carried
by the AST lint and by the per-site tasks; this file pins only what the two
invokers own, and :func:`test_the_funnel_does_not_cover_claim_extraction` states
the residual risk so the floor is never mistaken for total coverage.

NAMED MUTATION MUST-KILLS PINNED HERE: MK-I27, MK-I28 and MK-I29 — the whole of
this task's own diff in the measured sample, already killed by the tests below
and named so they stay killed.
"""

from pathlib import Path

import pytest

from gcp_grounding import (evidence, preflight, registry, sec_artifact, sec_ast,
                           sec_domains, sec_rules)
from gcp_grounding.core.report import Verdict
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.registry import CheckContext
from gcp_grounding.sec_ast import CollectionSpec

HAVE_Z3 = get_solver().backend == "z3"

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"

SNAP = GcpSnapshot(captured_at="2026-01-01T00:00:00Z")

STUB = "gcp_grounding_stub_provider"


def ctx(**overrides) -> CheckContext:
    """A CheckContext carrying everything a stub check needs and nothing more."""
    fields = dict(snapshot=SNAP, solver=None, document={"marker": True},
                  document_kind="iam_policy", source="<policy object>", claims=())
    fields.update(overrides)
    return CheckContext(**fields)


def provider(fn):
    """Label *fn* as a provider callable so ``_label`` names the stub module."""
    fn.__module__ = STUB
    return fn


# =============================================================================
# the domain-check tier — registry._invoke
# =============================================================================

#: The document the present-but-empty collection is read out of. ``rules`` is
#: THERE and holds nothing: the collection was read, and it had no records.
EMPTY_DOC = {"rules": []}


def _read_the_empty_collection(check_ctx):
    """Read a present-but-empty collection the sanctioned way, then forget."""
    return evidence.rows(check_ctx.document, "rules", what="policy 'fp-baseline'")


def _decides(status):
    """A stub document check that reads an empty collection and decides anyway —
    the exact shape every reproduced vacuity had."""
    @provider
    def check(check_ctx):
        _read_the_empty_collection(check_ctx)
        return [Verdict(status, "firewall_policy", "fp-baseline", 0,
                        "the 3-level order decides every packet identically")]
    return check


@pytest.mark.parametrize("status", ["grounded", "contradicted"])
def test_a_decision_over_an_empty_collection_is_downgraded(status):
    """(1) and (2): a decided verdict standing on zero examined rows abstains.

    ``contradicted`` is downgraded too — a contradiction manufactured out of an
    unreadable old side is the same defect wearing the other polarity.
    """
    empty = ctx(document=EMPTY_DOC)
    verdicts = registry._invoke(_decides(status), empty, empty)

    assert len(verdicts) == 1
    [v] = verdicts
    assert v.status == "unverified"
    # SAME kind and target: the abstention REPLACES the verdict, it is not a
    # second opinion standing next to it.
    assert v.kind == "firewall_policy" and v.target == "fp-baseline"
    # It names the empty collection...
    assert "'rules' is present and holds no records" in v.message
    assert "fp-baseline" in v.message
    # ...and the status it replaced.
    assert status in v.message


def test_a_check_that_reads_nothing_is_not_downgraded():
    """(3) BLAST-RADIUS CONTROL, deliberate: ``collections_read == 0`` means
    untouched. A scalar-only check opens no collection by design, so the floor
    must not turn its honest decision into an abstention."""
    @provider
    def scalar_only(check_ctx):
        enforced = evidence.scalar(
            check_ctx.document, "enforced",
            what="constraint 'compute.disableSerialPortAccess'", type=bool)
        return [Verdict("grounded", "constraint", "c", 0,
                        f"the constraint is enforced={enforced}")]

    scalars = ctx(document={"enforced": True})
    [v] = registry._invoke(scalar_only, scalars, scalars)

    assert v.status == "grounded"
    assert v.message == "the constraint is enforced=True"


def test_an_attested_emptiness_survives_and_carries_its_reason():
    """(4): ``emptiness_is_dispositive`` is the ONE sanctioned way to ground over
    nothing, and the invoker is required to print its reason, so the claim
    "nothing was there, and that settles it" never travels silently."""
    reason = "a policy with no rules denies nothing, which is what was asserted"

    @provider
    def attests(check_ctx):
        _read_the_empty_collection(check_ctx)
        evidence.emptiness_is_dispositive(reason)
        return [Verdict("grounded", "firewall_policy", "fp-baseline", 0,
                        "the empty policy decides every packet identically")]

    empty = ctx(document=EMPTY_DOC)
    [v] = registry._invoke(attests, empty, empty)

    assert v.status == "grounded"
    assert v.kind == "firewall_policy" and v.target == "fp-baseline"
    assert reason in v.message


def test_a_typed_abstain_is_one_unverified_naming_what_and_why():
    """(5): ``NotEvaluated`` is a first-class abstain that cannot be swallowed —
    exactly one ``unverified`` naming both halves, and nothing propagates."""
    @provider
    def abstains(check_ctx):
        # 'rules' holds a dict, not a list: the shape a raw doc.get("rules", [])
        # would have silently read as "no records".
        evidence.rows(check_ctx.document, "rules", what="policy 'fp-baseline'")
        raise AssertionError("unreachable — rows() abstains on a dict")

    doc = ctx(document={"rules": {"count": 3}})
    verdicts = registry._invoke(abstains, doc, doc)  # must not propagate

    assert len(verdicts) == 1
    [v] = verdicts
    assert v.status == "unverified"
    assert v.target == "<policy object>"
    assert "policy 'fp-baseline'" in v.message         # what
    assert "got dict" in v.message                     # why — the shape is named


def test_the_typed_abstain_carries_the_checks_own_kind():
    """CHANNEL DISCIPLINE: a claim check's abstention is a verdict of the claim's
    OWN kind, not the generic ``document`` the broad crash arm uses — an
    abstention a family does not own can never discharge that family's
    assertion."""
    @provider
    def abstains(claim, check_ctx):
        raise evidence.NotEvaluated("firewall rule 'allow-ssh'",
                                    "has no readable 'layer4' list, got str")

    [v] = registry._invoke(abstains, ctx(), None, ctx(), kind="firewall_rule")

    assert v.status == "unverified" and v.kind == "firewall_rule"
    assert "firewall rule 'allow-ssh'" in v.message
    assert "got str" in v.message


def test_run_claim_checks_names_the_claims_kind(monkeypatch):
    """The same, reached the way ``ground_policy`` reaches it."""
    @provider
    def abstains(claim, check_ctx):
        raise evidence.NotEvaluated(f"firewall rule {claim.value!r}",
                                    "has no readable 'layer4' list, got str")

    from gcp_grounding.claims import Claim

    monkeypatch.setattr(registry, "claim_checks", lambda kind: (abstains,))
    claim = Claim("firewall_rule", "allow-ssh", "rules[0]")
    [v] = registry.run_claim_checks(claim, ctx())

    assert v.status == "unverified" and v.kind == "firewall_rule"
    assert "allow-ssh" in v.message


def test_the_broad_crash_arm_is_unchanged_in_meaning():
    """The pre-existing fail-open arm still sits UNDERNEATH the typed abstain:
    any other exception is one ``unverified document`` naming the provider."""
    @provider
    def boom(check_ctx):
        raise RuntimeError("kaboom")

    [v] = registry._invoke(boom, ctx(), ctx())

    assert v.status == "unverified" and v.kind == "document"
    assert STUB in v.message
    assert "raised RuntimeError: kaboom" in v.message and "not decided" in v.message


def test_every_invocation_gets_its_own_ledger():
    """One ledger per invocation: what the previous check examined can never be
    what makes this one's verdict non-vacuous."""
    seen = []

    @provider
    def reads_two_rows(check_ctx):
        evidence.rows({"rules": [{"a": 1}, {"a": 2}]}, "rules", what="p")
        return [Verdict("grounded", "firewall_policy", "first", 0, "two rows")]

    @provider
    def reads_none(check_ctx):
        _read_the_empty_collection(check_ctx)
        return [Verdict("grounded", "firewall_policy", "second", 0, "no rows")]

    empty = ctx(document=EMPTY_DOC)
    seen.extend(registry._invoke(reads_two_rows, empty, empty))
    seen.extend(registry._invoke(reads_none, empty, empty))

    first, second = seen
    assert first.status == "grounded"        # it examined two rows
    assert second.status == "unverified"     # it examined none, on its own ledger


def test_the_funnel_does_not_cover_claim_extraction():
    """THE ONE ACKNOWLEDGED EDGE, pinned so nobody mistakes the floor for total
    coverage: claim extraction runs upstream of both funnels, so a document that
    yields zero claims reaches a VERDICTLESS report — not an abstention. What
    closes it is a ledger around ``preflight._extract_claims``; the lint is the
    interim net, and Gate 0 owns ``preflight.py`` first."""
    report = preflight.ground_policy({"bindings": []},
                                     GcpSnapshot.load(FIXTURES / "snapshot.json"))

    assert report.verdicts == []      # the residual risk, stated rather than hidden
    assert report.ok                  # and it passes the gate today


# =============================================================================
# the compiled-rule tier — sec_rules.CompiledRule._collect
# =============================================================================

FLOOR = CollectionSpec("floor_estate", "estate", {"name": "Str", "flag": "Bool"})
sec_ast.register_collection(FLOOR)

#: A forall over ``floor_estate`` — trivially TRUE over an empty instance, which
#: is exactly the vacuity the floor makes unreachable without an attestation.
AST_FLOOR = {"node": "forall", "var": "e", "collection": "floor_estate",
             "body": {"node": "cmp", "op": "eq",
                      "left": {"node": "field", "var": "e", "field": "name"},
                      "right": {"node": "lit", "sort": "Str", "value": "ok"}}}


@pytest.fixture(autouse=True)
def _isolate():
    """No test may leak a stub extractor or a rule into the next."""
    saved = dict(sec_rules.EXTRACTORS)
    sec_rules.RULES.clear()
    yield
    sec_rules.RULES.clear()
    sec_rules.EXTRACTORS.clear()
    sec_rules.EXTRACTORS.update(saved)


def _promise(pid):
    """A structurally-valid compiled Promise over :data:`AST_FLOOR`.

    ``evaluate`` never reads the sexpr or the witnesses, so placeholders are
    enough and this suite depends on no stage-1 compile code."""
    return sec_artifact.Promise(
        id=pid, source=sec_artifact.Source(file="req.md", line=3,
                                           text="a security requirement"),
        domain="hier_firewall", mode="assert_satisfiable", state="estate",
        severity="high", vocabulary=(), ast=AST_FLOOR, sexpr="(assert true)",
        free_consts=(),
        positive=sec_artifact.Witness(assignment={"floor_estate#e.name": "ok"},
                                      origin="pinned"),
        negative=sec_artifact.Witness(assignment={"floor_estate#e.name": "no"},
                                      origin="pinned"),
        wellformedness=sec_artifact.Wellformedness(satisfiable=True,
                                                   non_tautological=True),
        status="compiled", reason="")


def _rule_ctx():
    # document_kind None is the loud default: applicability cannot be determined,
    # so the rule is applicable and must speak.
    return sec_rules.RuleContext(snapshot=SNAP, document=None, document_kind=None)


def test_a_bare_empty_extraction_abstains_instead_of_grounding():
    """(6) THE FORCED CASE: no records and no reason becomes a missing_reason, so
    the vacuous forall never reaches the solver at all."""
    sec_rules.register_extractor("floor_estate", lambda c: ((), None))
    r = sec_rules.CompiledRule(promise=_promise("floor-bare"))

    v = r.evaluate(_rule_ctx())

    assert v.status == "unverified"
    assert v.status != "grounded"
    assert v.kind == "sec:hier_firewall"
    assert "floor_estate" in v.message
    assert "did not say whether" in v.message
    # missing_inputs and evaluate agree — one floor, not two.
    assert len(r.missing_inputs(_rule_ctx())) == 1


def test_an_observed_empty_extraction_grounds_and_says_how_it_knows():
    """(7): a genuinely-empty-but-KNOWN collection still grounds AND says so."""
    sec_rules.register_extractor(
        "floor_estate",
        lambda c: evidence.observed_empty("the floor_estate table",
                                          "it was captured and holds no rows"))
    r = sec_rules.CompiledRule(promise=_promise("floor-known"))

    assert r.missing_inputs(_rule_ctx()) == ()   # nothing is missing: it is empty
    v = r.evaluate(_rule_ctx())

    if not HAVE_Z3:
        # Environment-honest: without z3 the rule abstains for THAT reason and
        # that reason only — never the forced one.
        assert v.status == "unverified" and "z3 is not available" in v.message
        assert "did not say whether" not in v.message
        return
    assert v.status == "grounded"
    assert "the floor_estate table: it was captured and holds no rows" in v.message


def test_a_legacy_two_tuple_is_accepted_unchanged():
    """The legacy shape keeps working in both its states: records, and a
    missing_reason carried verbatim."""
    sec_rules.register_extractor(
        "floor_estate", lambda c: (({"name": "ok", "flag": True},), None))
    r = sec_rules.CompiledRule(promise=_promise("floor-records"))
    assert r.missing_inputs(_rule_ctx()) == ()
    if HAVE_Z3:
        assert r.evaluate(_rule_ctx()).status == "grounded"

    sec_rules.register_extractor(
        "floor_estate", lambda c: ((), "snapshot did not capture floor_estate"))
    r2 = sec_rules.CompiledRule(promise=_promise("floor-missing"))
    assert r2.missing_inputs(_rule_ctx()) == (
        "snapshot did not capture floor_estate",)


def test_normalize_extraction_is_the_one_place_the_floor_lives():
    """The three cases of the normalizer, stated directly."""
    passthrough = evidence.Extraction(records=({"name": "ok"},))
    assert sec_rules._normalize_extraction("c", passthrough) == (
        ({"name": "ok"},), None, None)

    assert sec_rules._normalize_extraction("c", ((), "the snapshot lacks c")) == (
        (), "the snapshot lacks c", None)

    records, missing, empty = sec_rules._normalize_extraction("c", ((), None))
    assert records == () and empty is None
    assert missing == ("the c extractor produced no records and did not say "
                       "whether c is empty or unreadable — the rule was not "
                       "evaluated")


# =============================================================================
# the shared typed abstain reaches the extractor channel too
# =============================================================================

def test_sec_domains_guarded_routes_not_evaluated_through_missing_reason():
    """``sec_domains._guarded`` accepts EITHER abstain: its own ``_Undecidable``
    or the shared :class:`gcp_grounding.evidence.NotEvaluated`."""
    def raises_typed(c):
        raise evidence.NotEvaluated("hierarchical firewall policy 'fp-baseline'",
                                    "has no readable 'rules' list, got dict")

    records, missing = sec_domains._guarded("hier_firewall_rules",
                                            raises_typed)(None)
    assert records == ()
    assert missing == ("hierarchical firewall policy 'fp-baseline': has no "
                       "readable 'rules' list, got dict")

    def raises_own(c):
        raise sec_domains._Undecidable("snapshot did not capture x")

    _records, own = sec_domains._guarded("hier_firewall_rules", raises_own)(None)
    assert own == "snapshot did not capture x"


# =============================================================================
# the lineno invariant, and this task's own three named must-kills
#
# MK-I27 (registry.py:220, ``and`` -> ``or`` on the downgrade predicate) and
# MK-I28 (registry.py:220, the REGISTERED ``rows_examined == 0``) are killed by
# test_a_decision_over_an_empty_collection_is_downgraded and
# test_a_check_that_reads_nothing_is_not_downgraded above; MK-I29
# (sec_rules.py:248, the ``+`` that appends the observed-empty reason) is killed
# by test_an_observed_empty_extraction_grounds_and_says_how_it_knows. All three
# are named here so they stay killed, and all three were re-measured ALONE in an
# isolated copy of the tree (house rule 7).
# =============================================================================

def assert_policy_documents_have_no_line_numbers(verdicts):
    """A policy document has no line numbers, so EVERY verdict's ``lineno`` is 0
    and the json-path location leads the message instead.

    The REGISTERED predicate is ``all(v.lineno == 0 for v in`` — asserting it per
    abstention path is coverage of exactly the fail-open branches the vacuity
    class lives on. THE INVARIANT IS THE KILLER, NOT THE WHOLE TEST: its caller
    also pins each path's IDENTITY — status, kind, target and the reason named in
    the message."""
    verdicts = list(verdicts)
    assert verdicts, "an invariant over no verdicts proves nothing"
    assert all(v.lineno == 0 for v in verdicts), (
        "policy documents have no line numbers: "
        f"{[(v.target, v.lineno) for v in verdicts]}")


def test_the_floors_own_abstentions_are_identified_and_carry_no_line_number():
    """The three verdicts ``_invoke`` can author — the downgrade, the typed
    abstain and the broad crash arm — each pinned by status, kind, target and
    reason, and all three carrying the documented lineno invariant."""
    @provider
    def crashes(check_ctx):
        raise RuntimeError("kaboom")

    @provider
    def abstains(check_ctx):
        raise evidence.NotEvaluated("hierarchical firewall policy 'fp-baseline'",
                                    "has no readable 'rules' list, got dict")

    empty = ctx(document=EMPTY_DOC)
    [downgraded] = registry._invoke(_decides("grounded"), empty, empty)
    [abstained] = registry._invoke(abstains, empty, empty, kind="firewall_policy")
    [crashed] = registry._invoke(crashes, empty, empty)

    assert downgraded.status == "unverified" and downgraded.kind == "firewall_policy"
    assert downgraded.target == "fp-baseline"
    assert "'rules' is present and holds no records" in downgraded.message

    assert abstained.status == "unverified" and abstained.kind == "firewall_policy"
    assert abstained.target == "<policy object>"
    assert "got dict" in abstained.message

    assert crashed.status == "unverified" and crashed.kind == "document"
    assert crashed.target == "<policy object>"
    assert "raised RuntimeError: kaboom" in crashed.message

    assert_policy_documents_have_no_line_numbers([downgraded, abstained, crashed])
