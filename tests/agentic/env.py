"""Module-level constants and capability probes for the agentic gate suite.

These live *outside* ``conftest.py`` on purpose: they must be importable at
*decorator time* (``@pytest.mark.skipif(...)``, ``@pytest.mark.parametrize``),
and pytest fixtures cannot be used there. A fixture is evaluated per-test; a
probe is a plain module-level ``bool`` decided once, at import.

The domain probes (``HAVE_FIREWALL_DOMAIN`` … ``HAVE_ORG_ENFORCEMENT``) are the
decoupling mechanism between this suite and the six-domain grounding work: each
adversarial family's tests skip until the kind name it keys off appears in
:data:`gcp_grounding.claims.KINDS` — the one mandatory edit point the domain
tasks share — so this suite can land and stay green before any domain module
exists.

Every probe is computed inside a ``try``/``except`` and can never raise at
import: a broken or absent dependency degrades a probe to ``False``, it does not
break collection of the whole suite.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

# -- paths --------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "gcp"
POLICIES = FIXTURES / "policies"
AGENTIC = FIXTURES / "agentic"
TOY_SNAPSHOT = FIXTURES / "snapshot.json"
ESTATE_SNAPSHOT = FIXTURES / "agentic_snapshot.json"
ESTATE_OVERLAY = FIXTURES / "agentic_estate_overlay.json"
BLOCKIMPORTS_DIR = Path(__file__).parent / "_blockimports"

#: The estate snapshot's committed capture timestamp, pinned so tests can assert
#: freshness without re-opening the file.
ESTATE_CAPTURED_AT = "2026-07-25T08:00:00Z"


# -- helpers ------------------------------------------------------------------


def have_claim_kinds(*kinds: str) -> bool:
    """True when every name in *kinds* is a member of
    :data:`gcp_grounding.claims.KINDS`. Never raises: a missing or broken module
    degrades to ``False``."""
    try:
        from gcp_grounding.claims import KINDS

        return all(kind in KINDS for kind in kinds)
    except Exception:
        return False


def merged_estate_document() -> dict:
    """The base estate snapshot document with the overlay's domain categories
    merged over its top-level keys — the input the domain knowledge work must
    teach :meth:`gcp_grounding.knowledge.GcpSnapshot.from_dict` to accept."""
    base = json.loads(ESTATE_SNAPSHOT.read_text(encoding="utf-8"))
    overlay = json.loads(ESTATE_OVERLAY.read_text(encoding="utf-8"))
    merged = dict(base)
    merged.update(overlay)
    return merged


def _module_available(name: str) -> bool:
    """``find_spec(name) is not None``, folded into a bool that can never raise
    at import (a missing *parent* package would otherwise raise)."""
    try:
        return importlib.util.find_spec(name) is not None
    except Exception:
        return False


# -- capability probes --------------------------------------------------------

# z3 may import and yet ``Z3Solver()`` still fail, so mirror the code's own
# degradation (as tests/test_gcp_constraints.py:27 does) rather than probing the
# import directly.
try:
    from gcp_grounding.core.solver import get_solver

    HAVE_Z3 = get_solver().backend == "z3"
except Exception:
    HAVE_Z3 = False

HAVE_TF_CLAIMS = _module_available("gcp_grounding.tf_claims")
HAVE_SEC_RULES = _module_available("gcp_grounding.sec_rules")
HAVE_SEC_COMPILE = _module_available("gcp_grounding.sec_compile")
HAVE_BASH_MUTATION = _module_available("gcp_grounding.bash_mutation")

# -- domain probes (one per adversarial family) -------------------------------
#
# Kind-only, because for each of these the kind name and its checker land in the
# same task: the moment ``claims.KINDS`` carries the kind, a check can block.
HAVE_FIREWALL_DOMAIN = have_claim_kinds("firewall_rule")
HAVE_HIER_FIREWALL_DOMAIN = have_claim_kinds("firewall_policy_rule")
HAVE_ARMOR_DOMAIN = have_claim_kinds("security_policy_rule")
# ``perimeter_config`` — NOT ``perimeter`` — is the kind sx-vpcsc-claims emits.
HAVE_VPCSC_DOMAIN = have_claim_kinds("perimeter_config")
HAVE_PUBLIC_PRINCIPAL = have_claim_kinds("public_principal")

# The lone CONJUNCTION probe, and the comment says why: ``sx-claim-kinds`` adds
# ``constraint_enforcement`` several tasks BEFORE ``sx-org-enforcement`` supplies
# the ``org_checks`` checker. A kind-only probe would flip True while nothing can
# yet block, turning sx-agentic-orgpolicy's A12 and A13 red for the wrong reason.
# Requiring BOTH conjuncts keeps this False before sx-org-enforcement and True
# after, at which point A12 and A13 really do block.
HAVE_ORG_ENFORCEMENT = have_claim_kinds("constraint_enforcement") and _module_available(
    "gcp_grounding.org_checks"
)

# ``from_dict`` rejects unknown top-level keys today, so this stays False until
# the domain knowledge work teaches it the new categories.
try:
    from gcp_grounding.knowledge import GcpSnapshot as _GcpSnapshot

    _GcpSnapshot.from_dict(merged_estate_document())
    HAVE_ESTATE_CATEGORY = True
except Exception:
    HAVE_ESTATE_CATEGORY = False
