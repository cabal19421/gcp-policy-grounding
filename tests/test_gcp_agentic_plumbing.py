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
from tests.agentic import env
from tests.agentic.budget import SubprocessBudget

# Set the sec-llm env vars at *import* time (i.e. during collection). The
# session-scoped autouse ``_scrub_sec_llm_env`` fixture runs after collection, so
# every test still sees them gone — see
# ``test_sec_llm_env_is_scrubbed_for_the_whole_session``.
os.environ["GCP_SEC_LLM"] = "1"
os.environ["GCP_SEC_LLM_MODEL"] = "claude-opus-4-8"
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
    # tf_claims.py is part of this checkout, so the probe is True.
    assert env.HAVE_TF_CLAIMS is True


def test_domain_probes_track_the_kinds_that_have_landed():
    # This test was written when nothing had landed and asserted a flat False.
    # ``sx-claim-kinds`` registers EVERY domain kind up front, several tasks
    # before the checkers that read them, so on a merged seed the kind-only
    # probes are already True while nothing can yet block. The contract each
    # adversarial family keys its skips off is not "False", it is "agrees with
    # claims.KINDS" — assert that, so this stays meaningful in both worlds.
    from gcp_grounding.claims import KINDS

    assert env.HAVE_FIREWALL_DOMAIN is ("firewall_rule" in KINDS)
    assert env.HAVE_VPCSC_DOMAIN is ("perimeter_config" in KINDS)
    # The conjunction probe is exactly the case that motivated it: the kind
    # lands tasks before its checker, so the probe tracks BOTH conjuncts —
    # False while org_checks is absent, True once it lands and A12/A13 can
    # really block. Assert the conjunction, never either world's answer.
    assert "constraint_enforcement" in KINDS
    assert env.HAVE_ORG_ENFORCEMENT is (
        "constraint_enforcement" in KINDS
        and importlib.util.find_spec("gcp_grounding.org_checks") is not None)
    # Same shape for the estate probe: it is True exactly when ``from_dict``
    # accepts the overlay's categories, which the domain knowledge work has
    # now taught it. Re-derive it rather than pin the pre-landing answer.
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


def test_snapshot_variant_captured_at_round_trips(snapshot_variant, estate_snapshot):
    stale = "2019-01-01T00:00:00Z"
    path = snapshot_variant(captured_at=stale)
    snap = GcpSnapshot.load(path)
    assert snap.captured_at == stale
    # Rewriting captured_at touches no category: the variant carries exactly
    # what the base snapshot captured. Pinning the base's own set keeps this
    # exact as the estate categories land, rather than pinning the five the
    # snapshot happened to carry when this was written.
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
    assert "GCP_SEC_LLM_MODEL" not in os.environ
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
    assert quiet.MAX_SUBPROCESS_SPAWNS == 260
    quiet.increment("hookrunner")
    quiet.check()  # well under the ceiling: no assertion
