"""Exercises the shared agentic-suite plumbing: the probes and helpers in
:mod:`tests.agentic.env`, the fixtures in ``tests/conftest.py``, the subprocess
budget, and the degraded-world import blocker driven through a real child
process boundary.
"""

import importlib.util
import os
import subprocess
import sys

import pytest

from gcp_grounding.knowledge import GcpSnapshot
from tests.agentic import capabilities, env
from tests.agentic.budget import SubprocessBudget

# Set the sec-llm env vars at *import* time (i.e. during collection). The
# session-scoped autouse ``_scrub_sec_llm_env`` fixture runs after collection, so
# every test still sees them gone — see
# ``test_sec_llm_env_is_scrubbed_for_the_whole_session``.
os.environ["GCP_SEC_LLM"] = "1"
os.environ["GCP_SEC_LLM_CMD"] = "some-llm --json"
os.environ["GCP_SEC_LLM_TIMEOUT"] = "60"


# -- child programs run across the real process boundary ----------------------

_BACKEND_CODE = """\
import sys
from gcp_grounding.core.solver import get_solver
sys.stdout.write(get_solver().backend)
"""

_TF_IMPORT_CODE = """\
import importlib
try:
    importlib.import_module('gcp_grounding.tf_claims')
except ImportError:
    print('ImportError')
else:
    print('imported')
"""

_FIND_SPEC_CODE = """\
import importlib.util
spec = importlib.util.find_spec('z3')
print('spec' if spec is not None else 'none')
"""


def _run_child(code, extra_env=None) -> subprocess.CompletedProcess:
    child_env = os.environ.copy()
    if extra_env:
        child_env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=env.REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        env=child_env,
    )


# -- capability probes --------------------------------------------------------

_PROBE_NAMES = (
    "HAVE_Z3",
    "HAVE_TF_CLAIMS",
    "HAVE_SEC_RULES",
    "HAVE_SEC_COMPILE",
    "HAVE_BASH_MUTATION",
    "HAVE_FIREWALL_DOMAIN",
    "HAVE_HIER_FIREWALL_DOMAIN",
    "HAVE_ARMOR_DOMAIN",
    "HAVE_VPCSC_DOMAIN",
    "HAVE_PUBLIC_PRINCIPAL",
    "HAVE_ORG_ENFORCEMENT",
    "HAVE_ESTATE_CATEGORY",
)


def test_capability_probes_are_plain_bools():
    for name in _PROBE_NAMES:
        assert isinstance(getattr(env, name), bool), name


def test_tf_claims_probe_reflects_this_checkout():
    # Not "tf_claims.py is on disk" — the extractor really turned a planned
    # google_project_iam_binding into a role claim the reasoner then found
    # ungrounded, and left the good near-twin alone.
    assert env.HAVE_TF_CLAIMS is True


def test_domain_probes_are_behavioural_not_kind_lookups():
    """The domain probes MEASURE; they no longer look a name up in a tuple.

    What this replaced was ``env.HAVE_X is ("kind" in KINDS)`` with ``HAVE_X``
    DEFINED as that same membership test — ``X is X``, which cannot fail.
    Measured: deleting the kind from the vocabulary left this module at 20
    passed while every firewall family silently skipped. So the vocabulary fact
    is restored as an assertion in its own right, and the probes are asserted
    against what :func:`tests.agentic.capabilities.probe` measured through a
    real ``ground_policy`` run, which does not consult the vocabulary at all.

    This runs in the INTEGRATED tree, where the kind vocabulary
    (:mod:`gcp_grounding.claims`) has landed for the firewall / perimeter /
    org-enforcement families whether or not their checkers have. That split is
    the very thing the tautology hid, so it is asserted in both directions
    here: the vocabulary fact stands on its own (a kind vanishing from ``KINDS``
    goes red below), and each family's flag is asserted equal to what ``probe``
    MEASURED — which may be either value, because the vocabulary carrying a
    kind does not make anything able to decide it. A dead family still has to
    say so in the words of the report it actually got; a live one has to own its
    claim kind. The ``is True`` anchors are the two capabilities this checkout
    really does decide — without them "every probe is False" would satisfy every
    assertion below.

    EACH FLAG IS ALSO PINNED TO A CONCRETE VALUE, which the equality-to-measured
    is not. ``env.HAVE_X`` IS ``capabilities.probe(X).live``, so
    ``env.HAVE_X is measured.live`` reads ``probe(X).live is probe(X).live`` — X
    is X, unfailable, the same shape this docstring's first paragraph condemns.
    The three ``is True`` pins below are the concrete half, and they are honest
    in this tree because all three checkers have landed: fw_checks, vpcsc_checks
    and org_checks each decide their family through a real ``ground_policy`` run.

    ABSORBS ``test_domain_probes_track_the_kinds_that_have_landed``, the variant
    ``agent/gx-sexpr-one-form`` and ``agent/gx-debt-lineno-invariant`` landed
    against the same problem: ``env.HAVE_X is ("kind" in KINDS)``, plus the
    vocabulary-AND-checker conjunction ``agent/tx-cli-state-flags`` pinned for
    org-enforcement. Those equalities were tautological only while the probes
    WERE that membership test; with behavioural probes their right-hand sides are
    computed without calling ``probe`` at all, and in THIS tree — where every one
    of the three kinds is registered AND its checker decides — they are true and
    they bite. So they are kept as well, not chosen between: a checker that
    regresses to dead while its kind stays in the vocabulary reddens here.
    """
    from gcp_grounding.claims import KINDS

    # Restored: the vocabulary conjunct the probes no longer carry. Independent
    # of the probes now, so a kind leaving KINDS goes red HERE.
    for kind in ("firewall_rule", "perimeter_config", "constraint_enforcement"):
        assert kind in KINDS, kind
        assert env.have_claim_kinds(kind) is True, kind

    # THE CONCRETE VALUE PIN, RESTORED — the assertion an integrator relaxed and
    # no branch did. `assert getattr(env, name) is measured.live` below is, on
    # its own, `probe(X).live is probe(X).live`: tests/agentic/env.py DEFINES
    # each of these three flags as `capabilities.probe(...).live`, so that
    # equality is X is X and can only fail if probe() is nondeterministic — the
    # exact shape the docstring above condemns, reintroduced in the shape it was
    # written to forbid. All three families HAVE landed in the integrated tree,
    # so the honest concrete value is True for each, and a probe that regresses
    # to dead (a deleted checker module, an emptied check tuple, a renamed
    # verdict kind, a claim kind dropped from the vocabulary) reddens HERE
    # instead of quietly taking the dead-family branch below and passing.
    assert env.HAVE_FIREWALL_DOMAIN is True
    assert env.HAVE_VPCSC_DOMAIN is True
    assert env.HAVE_ORG_ENFORCEMENT is True

    # ... and each flag against the CONJUNCTION `agent/gx-debt-lineno-invariant`
    # and `agent/tx-cli-state-flags` both pinned it to. Not a tautology either:
    # the kind membership and the `find_spec` are computed without calling
    # probe() at all, so this says the vocabulary and the checker travel
    # together, which is the claim the live arm of the loop below makes per
    # family. Both sides of the merge assert it; both are kept.
    assert env.HAVE_FIREWALL_DOMAIN is ("firewall_rule" in KINDS)
    assert env.HAVE_VPCSC_DOMAIN is ("perimeter_config" in KINDS)
    assert "constraint_enforcement" in KINDS
    assert env.HAVE_ORG_ENFORCEMENT is (
        "constraint_enforcement" in KINDS
        and importlib.util.find_spec("gcp_grounding.org_checks") is not None)

    # Measured: each family's flag is what a real ``ground_policy`` run
    # measured, never a vocabulary lookup — the kinds above are all present
    # while these capabilities may be dead or live independently of that.
    for name, cap, kind, owner in (
            ("HAVE_FIREWALL_DOMAIN", capabilities.FIREWALL, "firewall_rule",
             "gcp_grounding.fw_checks"),
            ("HAVE_VPCSC_DOMAIN", capabilities.VPCSC, "perimeter_config",
             "gcp_grounding.vpcsc_checks"),
            ("HAVE_ORG_ENFORCEMENT", capabilities.ORG_ENFORCEMENT,
             "constraint_enforcement", "gcp_grounding.org_checks")):
        measured = capabilities.probe(cap)
        assert getattr(env, name) is measured.live, name
        if measured.live:
            # A family that really decides must own BOTH conjuncts: its claim
            # kind in the vocabulary and its checker module in the checkout.
            # (The conjunction is the fact agent/tx-cli-state-flags pinned for
            # org-enforcement; it holds for every family, so it is asserted for
            # all three.)
            assert kind in KINDS, name
            assert importlib.util.find_spec(owner) is not None, name
        else:
            # A dead family names itself and the report that killed it.
            assert cap.family in measured.reason, name
            assert cap.name in measured.reason, name

    # The probe machinery is not stuck at False: the same call on capabilities
    # this checkout DOES decide measures live.
    assert capabilities.probe(capabilities.IAM_EXISTENCE).live is True
    assert capabilities.probe(capabilities.ORG_CONSTRAINT_VALUE).live is True

    # HAVE_ESTATE_CATEGORY was False while no estate fixture existed. The
    # integrated tree carries one, so the honest value is True — and True
    # BECAUSE a real merged estate document loads, not because an exception was
    # swallowed into a flag: the loaded snapshot must actually carry the record
    # tables the estate-tier checks read.
    assert env.HAVE_ESTATE_CATEGORY is True
    estate = GcpSnapshot.from_dict(env.merged_estate_document())
    assert "firewall_rules" in estate.captured_categories()
    # And the branch's own shape for the same probe, kept alongside the concrete
    # pin rather than instead of it: the flag is True exactly when ``from_dict``
    # accepts the overlay's categories. The concrete `is True` above says WHICH
    # world this is; the re-derivation says the flag is not lying about it.
    accepts = True
    try:
        GcpSnapshot.from_dict(env.merged_estate_document())
    except Exception:
        accepts = False
    assert env.HAVE_ESTATE_CATEGORY is accepts


def test_have_claim_kinds_matches_current_kinds():
    assert env.have_claim_kinds("role") is True
    assert env.have_claim_kinds("role", "constraint") is True
    assert env.have_claim_kinds("not_a_real_kind") is False
    assert env.have_claim_kinds("role", "not_a_real_kind") is False


def test_merged_estate_document_carries_overlay_keys():
    merged = env.merged_estate_document()
    assert "captured_at" in merged
    assert "roles" in merged
    assert "firewall_rules" in merged


# -- path fixtures ------------------------------------------------------------


def test_path_fixtures(repo_root, fixtures_dir, policies_dir, agentic_dir, toy_snapshot_path):
    assert repo_root == env.REPO_ROOT
    assert (repo_root / "gcp_grounding").is_dir()
    assert fixtures_dir == env.FIXTURES
    assert policies_dir == env.POLICIES
    assert agentic_dir == env.AGENTIC
    assert toy_snapshot_path == env.TOY_SNAPSHOT
    assert toy_snapshot_path.exists()


# -- estate snapshot & variants -----------------------------------------------


def test_estate_snapshot_captured_at(estate_snapshot):
    assert estate_snapshot.captured_at == env.ESTATE_CAPTURED_AT


def test_snapshot_variant_drops_a_category(snapshot_variant):
    path = snapshot_variant(drop=["principals"])
    snap = GcpSnapshot.load(path)
    categories = snap.captured_categories()
    assert "principals" not in categories
    for other in ("roles", "permissions", "constraints", "resource_types"):
        assert other in categories


def test_snapshot_variant_captured_at_round_trips(snapshot_variant,
                                                 estate_snapshot_path,
                                                 estate_snapshot):
    stale = "2019-01-01T00:00:00Z"
    path = snapshot_variant(captured_at=stale)
    snap = GcpSnapshot.load(path)
    assert snap.captured_at == stale
    # Overriding captured_at drops NOTHING: the variant captures exactly what
    # the source estate snapshot captures. Asserted against the source rather
    # than a literal list, because the integrated estate fixture carries the six
    # flat vocabularies and the seven record tables as well as the five original
    # ones — a hardcoded five would silently stop noticing a dropped table.
    source = GcpSnapshot.load(estate_snapshot_path)
    assert set(snap.captured_categories()) == set(source.captured_categories())
    # The same statement through the loaded fixture `agent/gx-debt-lineno-invariant`
    # asks for. Both sides name the base snapshot rather than a literal list;
    # both fixtures exist in tests/conftest.py (`estate_snapshot` is built FROM
    # `estate_snapshot_path`), so keeping both costs one comparison and neither
    # side's text is dropped.
    assert set(snap.captured_categories()) == set(estate_snapshot.captured_categories())
    assert {"roles", "permissions", "principals", "constraints",
            "resource_types"} <= set(snap.captured_categories())


def test_snapshot_variant_name_is_stable(snapshot_variant):
    first = snapshot_variant(drop=["principals"])
    second = snapshot_variant(drop=["principals"])
    assert first == second


# -- agent working tree -------------------------------------------------------


def test_agent_workdir_is_empty_but_for_transcript(agent_workdir):
    assert agent_workdir.is_dir()
    entries = sorted(agent_workdir.iterdir())
    assert len(entries) == 1
    assert entries[0].name == "transcript.jsonl"
    assert (agent_workdir / "transcript.jsonl").read_text(encoding="utf-8") == ""


# -- the degraded-world import blocker ----------------------------------------


def test_blocked_import_env_forces_builtin_backend(blocked_import_env):
    proc = _run_child(_BACKEND_CODE, blocked_import_env("z3"))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "builtin"


@pytest.mark.skipif(not env.HAVE_Z3, reason="z3 backend not available in this interpreter")
def test_unblocked_child_uses_z3_backend():
    proc = _run_child(_BACKEND_CODE)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "z3"


def test_blocked_import_env_find_spec_returns_a_loadfailing_spec(blocked_import_env):
    # The finder returns a spec (not None) whose *load* fails — it must never
    # raise from find_spec, or core/solver.py:113 would crash instead of degrade.
    proc = _run_child(_FIND_SPEC_CODE, blocked_import_env("z3"))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "spec"


def test_blocked_import_env_blocks_tf_claims(blocked_import_env):
    proc = _run_child(_TF_IMPORT_CODE, blocked_import_env("gcp_grounding.tf_claims"))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "ImportError"


def test_blocked_import_env_aliases(blocked_import_env, no_z3_env, no_tf_claims_env):
    assert no_z3_env["GCP_TEST_BLOCK_IMPORTS"] == "z3"
    assert str(env.BLOCKIMPORTS_DIR) in no_z3_env["PYTHONPATH"]
    assert no_tf_claims_env["GCP_TEST_BLOCK_IMPORTS"] == "gcp_grounding.tf_claims"
    # The same two overlays are reachable as attributes of the factory itself.
    assert blocked_import_env.no_z3_env == no_z3_env
    assert blocked_import_env.no_tf_claims_env == no_tf_claims_env


# -- session hygiene ----------------------------------------------------------


def test_sec_llm_env_is_scrubbed_for_the_whole_session():
    assert "GCP_SEC_LLM" not in os.environ
    assert "GCP_SEC_LLM_CMD" not in os.environ
    assert "GCP_SEC_LLM_TIMEOUT" not in os.environ


# -- the subprocess budget ----------------------------------------------------


def test_subprocess_budget_accumulates(subprocess_budget):
    label = "tests.test_gcp_agentic_plumbing"
    before = subprocess_budget.total
    subprocess_budget.increment(label)
    subprocess_budget.increment(label)
    assert subprocess_budget.total == before + 2
    assert subprocess_budget.counts[label] >= 2


def test_subprocess_budget_teardown_fails_past_a_tiny_ceiling():
    # Drive a stub counter past a deliberately tiny ceiling rather than actually
    # spawning MAX_SUBPROCESS_SPAWNS processes.
    stub = SubprocessBudget(max_spawns=2)
    assert stub.increment("hookrunner") == 1
    assert stub.increment("hookrunner") == 2
    assert stub.increment("fake_agent") == 3
    assert stub.total == 3
    with pytest.raises(AssertionError) as excinfo:
        stub.check()
    message = str(excinfo.value)
    assert "budget exceeded" in message
    assert "hookrunner=2" in message
    assert "fake_agent=1" in message


def test_subprocess_budget_default_ceiling_is_not_exceeded_by_a_quiet_run():
    quiet = SubprocessBudget()
    # Re-derived for the integrated suite (nineteen spawn-using modules measure
    # 408 spawns); see SubprocessBudget.MAX_SUBPROCESS_SPAWNS for the derivation.
    # 466 -> 478 when the IAM-deny catalogue landed (its declared
    # MODULE_SPAWN_CAP of 12: ten measured children plus two of headroom).
    # 478 -> 488 when the effective org-policy catalogue landed (its declared
    # MODULE_SPAWN_CAP of 10: eight measured children plus two of headroom).
    assert quiet.MAX_SUBPROCESS_SPAWNS == 488
    quiet.increment("hookrunner")
    quiet.check()  # well under the ceiling: no assertion
