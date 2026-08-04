"""The frozen structured ``payload`` channel on :class:`Claim`: a checker kind
can carry a nested JSON-ish record that round-trips exactly, stays hashable and
comparable, and refuses to travel if mis-built."""

import pytest

from gcp_grounding.claims import KINDS, Claim, freeze, unfreeze


# -- round-trip -----------------------------------------------------------


def test_structured_payload_round_trips():
    claim = Claim.of(
        "firewall_rule", "r", "loc",
        direction="INGRESS",
        priority=1000,
        source_ranges=["0.0.0.0/0"],
        layer4=[{"protocol": "tcp", "ports": ["22"]}],
    )
    assert claim.fields() == {
        "direction": "INGRESS",
        "priority": 1000,
        "source_ranges": ["0.0.0.0/0"],
        "layer4": [{"protocol": "tcp", "ports": ["22"]}],
    }


def test_freeze_unfreeze_are_inverse():
    value = {"a": 1, "b": ["x", {"c": None, "d": True}], "e": 2.5}
    assert unfreeze(freeze(value)) == value


# -- hashable and comparable ---------------------------------------------


def test_identical_claims_are_equal_and_hashable():
    def build():
        return Claim.of("firewall_rule", "r", "loc",
                        direction="INGRESS", ports=["22", "443"])

    a, b = build(), build()
    assert a == b
    assert hash(a) == hash(b)
    assert len({a, b}) == 1


def test_payload_key_order_is_canonical():
    # kwargs given in any order yield the same (sorted) payload.
    a = Claim.of("firewall_rule", "r", "loc", b=2, a=1)
    b = Claim.of("firewall_rule", "r", "loc", a=1, b=2)
    assert a == b
    assert a.payload == (("a", 1), ("b", 2))


# -- a mis-built payload must not travel ----------------------------------


def test_unsorted_payload_keys_raise():
    with pytest.raises(ValueError):
        Claim("firewall_rule", "r", "loc", payload=(("b", 1), ("a", 2)))


def test_duplicate_payload_keys_raise():
    with pytest.raises(ValueError):
        Claim("firewall_rule", "r", "loc", payload=(("a", 1), ("a", 2)))


def test_non_str_payload_keys_raise():
    with pytest.raises(ValueError):
        Claim("firewall_rule", "r", "loc", payload=((1, "x"),))


def test_empty_str_payload_key_raises():
    with pytest.raises(ValueError):
        Claim("firewall_rule", "r", "loc", payload=(("", "x"),))


def test_non_frozen_payload_value_raises():
    with pytest.raises(ValueError):
        Claim("firewall_rule", "r", "loc", payload=(("a", [1, 2]),))


def test_freeze_rejects_unhashable_object():
    with pytest.raises(ValueError):
        freeze(object())


# -- backward compatibility ----------------------------------------------


def test_default_payload_is_empty():
    claim = Claim("role", "roles/viewer", "bindings[0].role")
    assert claim.payload == ()
    assert claim.fields() == {}


def test_constraint_value_still_requires_is_list():
    Claim("constraint_value", "constraints/x", "loc", is_list=True)  # ok
    with pytest.raises(ValueError):
        Claim("constraint_value", "constraints/x", "loc")


def test_role_still_forbids_is_list():
    Claim("role", "roles/viewer", "loc")  # ok
    with pytest.raises(ValueError):
        Claim("role", "roles/viewer", "loc", is_list=True)


# -- vocabulary -----------------------------------------------------------


def test_kinds_are_unique():
    assert len(KINDS) == len(set(KINDS))


def test_new_kinds_present():
    for kind in ("firewall_rule", "perimeter_config", "network_ref",
                 "constraint_enforcement", "denied_permission"):
        assert kind in KINDS
        # a structured kind constructs fine with a payload
    Claim.of("perimeter_config", "p", "loc", restricted_services=["storage.googleapis.com"])
