"""The terraform provider hook: :func:`~gcp_grounding.tf_claims.terraform_plan_claims`
resolving per-domain resource extractors through the lazy
:func:`gcp_grounding.registry.tf_extractors` seam.

A later domain module (VPC firewall, Cloud Armor, …) contributes extractors for
new ``google`` resource types by defining a module-level ``TF_EXTRACTORS`` table,
discovered exactly the way production discovers it — a stub injected into
``sys.modules`` and named in a monkeypatched ``PROVIDER_MODULES``. Pinned here:
a provider's claims land alongside the always-emitted ``resource_type_ref``; a
built-in extractor can never be shadowed by a provider; a crashing extractor
degrades to the type-reference-only path without propagating; and the ``_blocks``
helper the domain extractors reuse walks repeated nested blocks correctly.
"""

import sys
import types

import pytest

from gcp_grounding import registry
from gcp_grounding.claims import Claim
from gcp_grounding.tf_claims import _blocks, terraform_plan_claims

STUB = "gcp_grounding_stub_tf_provider"


@pytest.fixture(autouse=True)
def _clean_registry():
    """No test may leak an injected provider or a warm cache into the next."""
    registry.reset_cache()
    yield
    registry.reset_cache()


def install(monkeypatch, extractors) -> types.ModuleType:
    """Inject a stub provider exposing ``TF_EXTRACTORS`` and name it (and only
    it) in ``PROVIDER_MODULES`` — the exact discovery recipe production uses."""
    module = types.ModuleType(STUB)
    module.TF_EXTRACTORS = extractors
    monkeypatch.setitem(sys.modules, STUB, module)
    monkeypatch.setattr(registry, "PROVIDER_MODULES", (STUB,))
    registry.reset_cache()
    return module


def plan_with(address: str, rtype: str, after,
              provider="registry.terraform.io/hashicorp/google") -> dict:
    """A one-resource ``terraform show -json`` plan (resource_changes form)."""
    return {"resource_changes": [{
        "address": address,
        "mode": "managed",
        "type": rtype,
        "name": address.rsplit(".", 1)[-1],
        "provider_name": provider,
        "change": {"actions": ["create"], "before": None, "after": after},
    }]}


# -- a provider contributing a new resource type ------------------------------


def test_provider_extractor_claims_land_beside_the_type_reference(monkeypatch):
    def fw_extractor(address, values):
        return [Claim("network_ref", values["network"], f"{address}.network")]

    install(monkeypatch, {"google_compute_firewall": fw_extractor})

    plan = plan_with("google_compute_firewall.allow_ssh",
                     "google_compute_firewall", {"network": "prod-vpc"})
    assert terraform_plan_claims(plan) == [
        Claim("resource_type_ref", "google_compute_firewall",
              "google_compute_firewall.allow_ssh"),
        Claim("network_ref", "prod-vpc",
              "google_compute_firewall.allow_ssh.network"),
    ]


def test_provider_extractor_sees_address_and_values(monkeypatch):
    seen = {}

    def fw_extractor(address, values):
        seen["address"] = address
        seen["values"] = values
        return []

    install(monkeypatch, {"google_compute_firewall": fw_extractor})

    terraform_plan_claims(plan_with("google_compute_firewall.f",
                                    "google_compute_firewall", {"network": "n"}))
    assert seen["address"] == "google_compute_firewall.f"
    assert seen["values"] == {"network": "n"}


# -- fail-open on a crashing provider extractor -------------------------------


def test_a_raising_provider_extractor_leaves_only_the_type_reference(monkeypatch):
    def boom(address, values):
        raise RuntimeError("kaboom")

    install(monkeypatch, {"google_compute_firewall": boom})

    plan = plan_with("google_compute_firewall.allow_ssh",
                     "google_compute_firewall", {"network": "prod-vpc"})
    # The crash must not propagate — terraform_plan_claims never raises.
    assert terraform_plan_claims(plan) == [
        Claim("resource_type_ref", "google_compute_firewall",
              "google_compute_firewall.allow_ssh"),
    ]


# -- built-ins always win -----------------------------------------------------


def test_provider_cannot_shadow_a_built_in_resource_type(monkeypatch):
    def hijack(address, values):
        raise AssertionError("built-in extractor must win, provider must not run")

    install(monkeypatch, {"google_project_iam_binding": hijack})

    plan = plan_with("google_project_iam_binding.viewers",
                     "google_project_iam_binding",
                     {"role": "roles/viewer",
                      "members": ["user:alice@acme.example"]})
    # The built-in binding extractor ran (role + principal claims); the
    # provider's hijack was never consulted.
    assert terraform_plan_claims(plan) == [
        Claim("resource_type_ref", "google_project_iam_binding",
              "google_project_iam_binding.viewers"),
        Claim("role", "roles/viewer",
              "google_project_iam_binding.viewers.role"),
        Claim("principal", "user:alice@acme.example",
              "google_project_iam_binding.viewers.members[0]"),
    ]


# -- the _blocks helper repeated-block walker ---------------------------------


def test_blocks_returns_every_object_of_a_repeated_block():
    a, b = {"port": "22"}, {"port": "443"}
    assert _blocks([a, b], "allow") == [(a, "allow[0]"), (b, "allow[1]")]


def test_blocks_accepts_a_bare_object():
    obj = {"port": "22"}
    assert _blocks(obj, "allow") == [(obj, "allow")]


def test_blocks_of_none_is_empty():
    assert _blocks(None, "allow") == []


def test_blocks_of_a_non_list_scalar_is_empty():
    assert _blocks("22", "allow") == []
