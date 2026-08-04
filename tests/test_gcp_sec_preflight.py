"""Wiring tests: compiled requirement rules dispatched by
:func:`gcp_grounding.preflight.ground_policy`.

The contract under test is the *dispatch*, not the rules themselves (those are
:mod:`tests.test_gcp_sec_rules`'s): ``rules=None`` must be byte-identical to
today's report, a supplied rule must render through the same Verdict channel as
the built-in checks, a rule that is not applicable to the document kind must add
nothing, and a rule whose state tier the caller does not satisfy must record
``unverified`` naming the missing input — never a silent skip.

Uses the ``HAVE_Z3`` branch idiom of the sec_* suites: rather than *skip* the
z3-dependent cases on the builtin backend, each test BRANCHES, asserting the
documented builtin behaviour (every rule abstains ``unverified``) when z3 is
absent and the real grounded/contradicted assertions when it is present.
Promises are built in code, so this suite depends on no stage-1 compiler code.
"""

import importlib
import json
from pathlib import Path

import pytest

from gcp_grounding import preflight, sec_artifact, sec_rules
from gcp_grounding.core.solver import get_solver
from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.preflight import ground_policy

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"

HAVE_Z3 = get_solver().backend == "z3"


@pytest.fixture()
def snap() -> GcpSnapshot:
    return GcpSnapshot.load(FIXTURES / "snapshot.json")


# -- AST / promise builders ---------------------------------------------------

def _fld(name, var="b"):
    return {"node": "field", "var": var, "field": name}


def _lit(value):
    return {"node": "lit", "sort": "Str", "value": value}


def _eq(left, right):
    return {"node": "cmp", "op": "eq", "left": left, "right": right}


def _exists(body, var="b", coll="iam_bindings"):
    return {"node": "exists", "var": var, "collection": coll, "body": body}


#: proposal tier — "some binding grants roles/viewer"; under ``refute`` the
#: promise is "no binding grants roles/viewer".
AST_VIEWER = _exists(_eq(_fld("role"), _lit("roles/viewer")))

#: pair tier — quantifies over BOTH the new and the old bindings, so the rule
#: cannot resolve its inputs without a baseline.
AST_PAIR = {"node": "and", "args": [
    _exists(_eq(_fld("member", "n"), _lit("allUsers")), var="n",
            coll="new_iam_bindings"),
    _exists(_eq(_fld("member", "o"), _lit("allUsers")), var="o",
            coll="old_iam_bindings"),
]}


def _promise(pid, ast, *, mode="refute", domain="iam", state="proposal"):
    """A structurally-valid compiled Promise with placeholder sexpr/witnesses —
    enough for :meth:`CompiledRule.evaluate`, which never reads them."""
    return sec_artifact.Promise(
        id=pid, source=sec_artifact.Source(file="req.md", line=3,
                                           text="a security requirement"),
        domain=domain, mode=mode, state=state, severity="high", vocabulary=(),
        ast=ast, sexpr="(assert true)", free_consts=(),
        positive=sec_artifact.Witness(assignment={"iam_bindings#b.role": "x"},
                                      origin="pinned"),
        negative=sec_artifact.Witness(assignment={"iam_bindings#b.role": "y"},
                                      origin="pinned"),
        wellformedness=sec_artifact.Wellformedness(satisfiable=True,
                                                   non_tautological=True),
        status="compiled", reason="")


def _rule(pid, ast, **kwargs):
    return sec_rules.CompiledRule(promise=_promise(pid, ast, **kwargs))


def _sec(report):
    return [v for v in report.verdicts if v.kind.startswith("sec:")]


def _blob(report) -> str:
    """The report as deterministic JSON text — the byte-identity comparison."""
    return json.dumps(report.to_dict(), sort_keys=True)


# -- the no-regression assertions ---------------------------------------------


def test_rules_none_is_byte_identical_to_not_passing_rules(snap):
    """The default preserves today's behaviour exactly."""
    without = ground_policy(POLICIES / "iam_policy_good.json", snap)
    explicit_none = ground_policy(POLICIES / "iam_policy_good.json", snap, rules=None)
    assert _blob(explicit_none) == _blob(without)
    assert without.ok and not _sec(without)


def test_empty_rules_behaves_like_none(snap):
    """An empty sequence is falsy, so the dispatch arm never runs — no
    ``sec:compile`` note about zero rules, no other change."""
    without = ground_policy(POLICIES / "iam_policy_good.json", snap)
    empty = ground_policy(POLICIES / "iam_policy_good.json", snap, rules=[])
    assert _blob(empty) == _blob(without)
    assert not _sec(empty)


def test_baseline_and_rules_none_is_byte_identical_with_a_baseline(snap):
    """The baseline path is untouched by the new parameter."""
    args = (POLICIES / "iam_policy_good.json", snap, POLICIES / "iam_policy_good.json")
    assert _blob(ground_policy(*args, rules=None)) == _blob(ground_policy(*args))


# -- proposal tier ------------------------------------------------------------


def test_one_proposal_rule_adds_exactly_one_sec_verdict(snap):
    report = ground_policy(POLICIES / "iam_policy_good.json", snap,
                           rules=[_rule("no-viewer", AST_VIEWER)])
    sec = _sec(report)
    assert len(sec) == 1
    assert sec[0].kind == "sec:iam" and sec[0].target == "no-viewer"
    if not HAVE_Z3:
        assert sec[0].status == "unverified"
        assert "z3 is not available" in sec[0].message
        return
    # the good fixture grants no roles/viewer, so the refute promise holds
    assert sec[0].status == "grounded"
    assert report.ok


def test_a_violating_policy_fails_the_gate_through_the_rule_alone(snap, tmp_path):
    """Every claim in this policy grounds — role, member and the policy shape —
    so without the rule it passes; the rule is the only thing that can fail it."""
    path = tmp_path / "viewer.json"
    path.write_text(json.dumps({
        "version": 3, "etag": "BwYn8x2Qb0c=",
        "bindings": [{"role": "roles/viewer",
                      "members": ["group:data-eng@acme.example"]}],
    }), encoding="utf-8")

    baseline_report = ground_policy(path, snap)
    assert baseline_report.ok, "the fixture must be clean but for the rule"

    report = ground_policy(path, snap, rules=[_rule("no-viewer", AST_VIEWER)])
    sec = _sec(report)
    assert len(sec) == 1 and sec[0].kind == "sec:iam"
    if not HAVE_Z3:
        assert sec[0].status == "unverified"
        assert report.ok, "unverified never fails the gate"
        return
    assert sec[0].status == "contradicted"
    assert "roles/viewer" in sec[0].message
    assert not report.ok


def test_a_non_applicable_rule_adds_nothing(snap):
    """``evaluate`` returns None for a recognized kind the promise's domain
    cannot speak about, and the dispatch must add nothing — the abstain-flood
    fix. An org-policy promise has nothing to say about an IAM policy."""
    rule = _rule("org-req", AST_VIEWER, domain="org_policy")
    assert rule.evaluate(sec_rules.RuleContext(snapshot=snap, document={},
                                               document_kind="iam_policy")) is None
    report = ground_policy(POLICIES / "iam_policy_good.json", snap, rules=[rule])
    assert not _sec(report)
    assert _blob(report) == _blob(ground_policy(POLICIES / "iam_policy_good.json", snap))


# -- pair tier ----------------------------------------------------------------


def test_pair_rule_without_a_baseline_is_unverified(snap):
    report = ground_policy(POLICIES / "iam_policy_good.json", snap,
                           rules=[_rule("pair-req", AST_PAIR, state="pair")])
    sec = _sec(report)
    assert len(sec) == 1 and sec[0].status == "unverified"
    assert "no baseline document was given" in sec[0].message
    assert report.ok


def test_pair_rule_with_a_baseline_is_decided(snap):
    """The rule reads the SAME parsed baseline the subset check does."""
    report = ground_policy(POLICIES / "iam_policy_good.json", snap,
                           POLICIES / "iam_policy_good.json",
                           rules=[_rule("pair-req", AST_PAIR, state="pair")])
    sec = _sec(report)
    assert len(sec) == 1
    assert "no baseline document was given" not in sec[0].message
    if not HAVE_Z3:
        assert sec[0].status == "unverified"
        assert "z3 is not available" in sec[0].message
        return
    assert sec[0].status in ("grounded", "contradicted")


def test_unreadable_baseline_abstains_in_both_the_rule_and_the_subset_check(
        snap, tmp_path):
    """One parse, one verdict about it in each consumer — and no exception."""
    missing = tmp_path / "gone.json"
    report = ground_policy(POLICIES / "iam_policy_good.json", snap, missing,
                           rules=[_rule("pair-req", AST_PAIR, state="pair")])

    sec = _sec(report)
    assert len(sec) == 1 and sec[0].status == "unverified"
    assert "no baseline document was given" in sec[0].message

    subset = [v for v in report.verdicts if v.kind == "subset"]
    assert len(subset) == 1 and subset[0].status == "unverified"
    assert "new⊆old was not decided" in subset[0].message
    assert report.ok


# -- bad input ----------------------------------------------------------------


def test_rules_with_an_unparsable_document_still_returns_early(snap, tmp_path):
    path = tmp_path / "broken.json"
    path.write_text("{not json", encoding="utf-8")
    report = ground_policy(path, snap, rules=[_rule("no-viewer", AST_VIEWER)])
    assert [v.kind for v in report.verdicts] == ["document"]
    assert report.verdicts[0].status == "unverified"
    assert not _sec(report)
    assert report.ok


def test_rules_without_the_sec_rules_module_are_honestly_unverified(snap, monkeypatch):
    """A checkout that ships no ``sec_rules`` degrades to one honest verdict
    naming the supplied-but-unrun rules, never an ImportError."""
    real = importlib.import_module

    def fake(name, *args, **kwargs):
        if name == "gcp_grounding.sec_rules":
            raise ImportError("no sec_rules in this checkout")
        return real(name, *args, **kwargs)

    monkeypatch.setattr(preflight.importlib, "import_module", fake)
    assert preflight._sec_rules_module() is None

    report = ground_policy(POLICIES / "iam_policy_good.json", snap,
                           rules=[_rule("no-viewer", AST_VIEWER)])
    sec = _sec(report)
    assert len(sec) == 1 and sec[0].kind == "sec:compile"
    assert sec[0].status == "unverified"
    assert "1 compiled requirement(s) were supplied" in sec[0].message
    assert "gcp_grounding.sec_rules is not available" in sec[0].message
    assert report.ok


def test_rules_with_an_unrecognized_document_are_still_offered_the_document(snap):
    """A kind the applicability table does not recognize is LOUD: the rule is
    treated as applicable and abstains for a stated reason rather than
    vanishing."""
    report = ground_policy({"totally": "unknown"}, snap,
                           rules=[_rule("no-viewer", AST_VIEWER)])
    sec = _sec(report)
    assert len(sec) == 1 and sec[0].status == "unverified"
    assert "not an IAM allow policy" in sec[0].message
    assert report.ok
