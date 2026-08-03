"""Module-level constants and capability probes for the agentic gate suite.

These live *outside* ``conftest.py`` on purpose: they must be importable at
*decorator time* (``@pytest.mark.skipif(...)``, ``@pytest.mark.parametrize``),
and pytest fixtures cannot be used there. A fixture is evaluated per-test; a
probe is a plain module-level ``bool`` decided once, at import.

The domain probes (``HAVE_FIREWALL_DOMAIN`` … ``HAVE_ORG_ENFORCEMENT``) are the
decoupling mechanism between this suite and the six-domain grounding work, and
they are BEHAVIOURAL: each is a thin delegate to
:func:`tests.agentic.capabilities.probe`, which runs the real gate over a
known-bad input and a known-good near-twin and requires it to decide the first
and stay quiet on the second. The names here are unchanged so no consumer
breaks; the COMPUTATION behind them no longer asks whether a name is in a tuple.

That change is the whole point. ``"firewall_rule" in claims.KINDS`` keeps
answering True after the checker is deleted, after its ``DOCUMENT_CHECKS``
tuple is emptied, after its verdict kind is renamed — every one of which leaves
a family collecting greens from a gate that can no longer block. A probe that
measures cannot be fooled that way, and a dead capability produces a LOUD SKIP
carrying the report it actually measured.

:func:`_module_available` survives for exactly one job: components with NO
``ground_policy`` channel to measure (the sec-requirements compiler and the
bash mutation scanner, which are reached through their own CLI entry points)
and genuinely external optionality such as z3. Nothing else may use it —
``tests/test_gcp_capabilities.py`` parses this file and pins the argument list,
so a re-added presence check for a module under test goes red there.

Every probe is computed inside a ``try``/``except`` and can never raise at
import: a broken or absent dependency degrades a probe to ``False``, it does not
break collection of the whole suite.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from tests.agentic import capabilities

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
    degrades to ``False``.

    A VOCABULARY QUESTION, and only that. No probe here keys off it any more:
    the vocabulary carries a kind long before — and long after — anything can
    decide it, which is exactly why the domain gates became behavioural. Assert
    it in its own right where the vocabulary is the property under test."""
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
    at import (a missing *parent* package would otherwise raise).

    ONLY for components whose evidence never reaches a
    :class:`~gcp_grounding.core.report.GroundingReport`, and so cannot be
    measured by :func:`tests.agentic.capabilities.probe`, plus genuinely
    external optionality. Anything a check decides is probed behaviourally
    instead — presence answers True for a gutted checker, which is how a
    family collects greens from a gate that cannot block."""
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

# The sec-requirements compiler and the bash mutation scanner never reach
# ``ground_policy``: their findings are produced by their own CLI entry points,
# so there is no report for a capability probe to measure. These three are the
# whole permitted residue of presence-checking, and the pin in
# tests/test_gcp_capabilities.py stops it growing.
HAVE_SEC_RULES = _module_available("gcp_grounding.sec_rules")
HAVE_SEC_COMPILE = _module_available("gcp_grounding.sec_compile")
HAVE_BASH_MUTATION = _module_available("gcp_grounding.bash_mutation")

# -- behavioural probes (one per adversarial family) --------------------------
#
# Each of these is the MEASUREMENT described in tests/agentic/capabilities.py:
# the real gate decided a known-bad input on a kind this family owns, and left
# the good near-twin alone. Deleting the module, emptying its check tuple,
# renaming its verdict kind, dropping its claim kind or stamping every input
# with the same answer all come out ``False`` here, with the measured report in
# ``capabilities.probe(...).reason``.
HAVE_TF_CLAIMS = capabilities.probe(capabilities.TF_CLAIMS).live
HAVE_FIREWALL_DOMAIN = capabilities.probe(capabilities.FIREWALL).live
HAVE_HIER_FIREWALL_DOMAIN = capabilities.probe(capabilities.HIER_FIREWALL).live
HAVE_ARMOR_DOMAIN = capabilities.probe(capabilities.ARMOR).live
HAVE_VPCSC_DOMAIN = capabilities.probe(capabilities.VPCSC).live
HAVE_PUBLIC_PRINCIPAL = capabilities.probe(capabilities.PUBLIC_PRINCIPAL).live

# Formerly the lone CONJUNCTION probe — ``have_claim_kinds`` AND a ``find_spec``
# for ``gcp_grounding.org_checks`` — because the kind lands several tasks before
# the checker that reads it, and a kind-only probe would flip True while nothing
# could yet block. The conjunction was a workaround for a probe that measured
# the wrong thing; the behavioural probe answers the real question directly, so
# both conjuncts are gone.
HAVE_ORG_ENFORCEMENT = capabilities.probe(capabilities.ORG_ENFORCEMENT).live

# Whether ``from_dict`` accepts the overlay's domain categories (it rejects
# unknown top-level keys today).
#
# NOT A DOMAIN GATE, and never again a conjunct on one. A snapshot category a
# case needs belongs in that capability's OWN bad-input fixture — see
# ``capabilities.estate_snapshot`` — so that a family whose fixture cannot be
# built skips under its own name with its own measured reason, instead of under
# a shared flag no reader can attribute to a family. Removing it from the gates
# that still AND it in belongs to those families' tasks.
try:
    from gcp_grounding.knowledge import GcpSnapshot as _GcpSnapshot

    _GcpSnapshot.from_dict(merged_estate_document())
    HAVE_ESTATE_CATEGORY = True
except Exception:
    HAVE_ESTATE_CATEGORY = False
