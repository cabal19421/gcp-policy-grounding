"""The reconciled snapshot: a drop-in ``GcpSnapshot`` that records what was read.

Every assertion here defends one of the two ways this object could go wrong.

The first is that it stops being a drop-in. A dataclass's generated ``__eq__``
compares ``other.__class__ is self.__class__`` before anything else, so an
inherited equality would make a reconciled snapshot compare UNEQUAL to a plain
one holding identical fields — and every golden-output test in the repo would
start failing for a reason that has nothing to do with what it tests. The
equality, ``to_dict`` and ``ground_policy`` pins below are all one claim: swap
the plain snapshot for the reconciled one and NOTHING observable changes.

The second is that the read tap stops being inert. A tap that could alter,
suppress or lose an answer would make the estate depend on who was watching;
worse, a suppressed row in a category declared *complete* would let a check
prove an absence that is not proven. So the tap is asserted to record beside the
answer, never in place of it, and to unwind its own stack even when the check it
was watching raises.
"""

import contextlib
import dataclasses
import importlib.util
import json
from pathlib import Path

import pytest

from gcp_grounding import preflight, provenance, reconciled
from gcp_grounding.knowledge import UNKNOWN, GcpSnapshot
from gcp_grounding.reconciled import ReconciledSnapshot

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
VOCAB_SNAPSHOT = FIXTURES / "snapshot.json"
ESTATE_SNAPSHOT = FIXTURES / "estate_snapshot.json"
POLICIES = FIXTURES / "policies"

# The record-table accessors land with sx-kb-estate-tables. Branch on the
# capability with a plain module-level boolean (the suite's HAVE_Z3 idiom)
# rather than skipping, so a tree without them asserts the honest degradation —
# the module imports and simply does not tap what does not exist — instead of
# quietly deleting half of this file.
HAVE_ESTATE_TABLES = hasattr(GcpSnapshot, "org_policy")


@pytest.fixture
def plain():
    return GcpSnapshot.load(ESTATE_SNAPSHOT)


@pytest.fixture
def snapshot(plain):
    return ReconciledSnapshot.from_snapshot(plain)


# -- equality across the class boundary ---------------------------------------


def test_a_reconciled_snapshot_equals_a_plain_one_in_both_directions(plain, snapshot):
    # BOTH directions, deliberately: `plain == snapshot` runs the PARENT's
    # generated __eq__ first, which returns NotImplemented for a subclass
    # instance, and Python then falls back to the reflected operand. If the
    # subclass had inherited that generated __eq__ instead of defining its own,
    # both operands would answer NotImplemented and Python would fall all the
    # way back to identity — quietly false.
    assert snapshot == plain
    assert plain == snapshot
    assert not (snapshot != plain)
    assert not (plain != snapshot)

    # Provenance is not part of estate identity: two views of the same estate
    # that merged from different sources ARE the same estate.
    ledger = provenance.SourceLedger.unattributed(plain)
    assert ReconciledSnapshot.from_snapshot(plain, ledger=ledger,
                                            policy_name="api-wins") == plain


def test_a_differing_field_still_compares_unequal(plain, snapshot):
    other = GcpSnapshot.from_dict(dict(plain.to_dict(), captured_at="1999-01-01T00:00:00Z"))
    assert snapshot != other
    assert other != snapshot
    assert not (snapshot == other)


def test_comparing_against_a_non_snapshot_returns_notimplemented(snapshot):
    # NotImplemented, not False: returning False would claim the comparison was
    # decided and rob the other operand of its reflected chance.
    assert snapshot.__eq__(object()) is NotImplemented
    assert snapshot.__ne__(object()) is NotImplemented
    assert snapshot.__eq__({"captured_at": snapshot.captured_at}) is NotImplemented
    # Python's fallback from a NotImplemented pair is identity.
    assert snapshot != object()
    assert not snapshot == object()


def test_the_reconciled_snapshot_is_unhashable(snapshot):
    assert ReconciledSnapshot.__hash__ is None
    with pytest.raises(TypeError, match="unhashable"):
        hash(snapshot)


def test_the_subclass_adds_no_dataclass_field(snapshot):
    # The three provenance attributes are plain instance state, NOT fields: a
    # regenerated field list is exactly what would regenerate the __eq__ guard.
    assert dataclasses.fields(ReconciledSnapshot) == dataclasses.fields(GcpSnapshot)
    assert "__eq__" in ReconciledSnapshot.__dict__
    assert snapshot.ledger is None
    assert snapshot.disputes == ()
    assert snapshot.policy_name == ""


def test_it_is_a_gcpsnapshot_for_the_isinstance_check(snapshot):
    # gate.py does a real isinstance check; this is why it is a subclass.
    assert isinstance(snapshot, GcpSnapshot)


# -- transparency --------------------------------------------------------------


def test_to_dict_is_byte_equal_to_the_plain_snapshot(plain, snapshot):
    dumps = dict(indent=2, sort_keys=True)
    assert json.dumps(snapshot.to_dict(), **dumps) == json.dumps(plain.to_dict(), **dumps)
    # And it round-trips back through the parent's own parser.
    assert GcpSnapshot.from_dict(snapshot.to_dict()) == plain


def test_ground_policy_is_identical_with_the_reconciled_snapshot():
    # THE INERTNESS PIN. Whatever else this object carries, the engine's answer
    # for the same document must not move by one byte.
    vocab = GcpSnapshot.load(VOCAB_SNAPSHOT)
    merged = ReconciledSnapshot.from_snapshot(
        vocab, ledger=provenance.SourceLedger.unattributed(vocab),
        policy_name="highest-fidelity-wins")
    for name in ("iam_policy_good", "iam_policy_bad"):
        path = POLICIES / f"{name}.json"
        assert preflight.ground_policy(path, merged).to_dict() == \
            preflight.ground_policy(path, vocab).to_dict()


def test_truth_testing_an_uncaptured_category_still_raises(snapshot):
    # The one semantic the whole knowledge base exists to protect: a category
    # that was never captured refuses to be truth-tested into a false absence.
    # A tap that returned some helpful wrapper instead of the raw sentinel would
    # break it silently.
    vocab = ReconciledSnapshot.from_snapshot(GcpSnapshot.load(VOCAB_SNAPSHOT))
    assert vocab.network_exists("projects/p/global/networks/n") is UNKNOWN
    with pytest.raises(TypeError, match="UNKNOWN is neither True nor False"):
        bool(vocab.network_exists("projects/p/global/networks/n"))
    with reconciled.reads() as read_set:
        assert vocab.network_exists("projects/p/global/networks/n") is UNKNOWN
    assert ("networks", "projects/p/global/networks/n") in read_set


def test_no_lookup_result_is_ever_suppressed(plain, snapshot):
    # CONTRACT RULE 3. A tap is a tempting place to filter — hide the row whose
    # provenance is weak, hide the category nobody attributed. Both directions
    # are unsound. Every raw field comes back as the SAME object the plain
    # snapshot holds, tapped or not.
    for field in dataclasses.fields(GcpSnapshot):
        with reconciled.reads():
            tapped = getattr(snapshot, field.name)
        assert tapped is getattr(plain, field.name)

    # And the shape that makes suppression cost a verdict: a category captured
    # EMPTY. It proves absence — demoting it to "not captured" would turn an
    # earned False into an abstention, and dropping one row from a complete
    # category would let a check prove a non-existence it has not earned.
    empty = ReconciledSnapshot(captured_at="2024-01-01T00:00:00Z", roles={},
                               permissions=frozenset(),
                               networks=frozenset({"projects/p/global/networks/n"}))
    for inside_a_read_set in (False, True):
        with reconciled.reads() if inside_a_read_set else contextlib.nullcontext():
            assert empty.roles == {} and empty.roles is not None
            assert empty.permissions == frozenset()
            assert empty.role_exists("roles/nope") is False
            assert empty.permission_exists("compute.instances.get") is False
            assert empty.require_complete("roles") is None
            assert empty.network_exists("projects/p/global/networks/n") is True


def test_importing_reconciled_leaves_the_parent_class_untouched():
    # The wrappers are installed on the SUBCLASS. If the install loop ever
    # setattr'd the parent, tests/test_gcp_knowledge.py and
    # tests/test_gcp_reasoner.py would be pinning a tapped object without
    # knowing it — so a plain snapshot records nothing, ever.
    untapped = GcpSnapshot.load(ESTATE_SNAPSHOT)
    with reconciled.reads() as read_set:
        assert untapped.role_exists("roles/viewer") is True
        assert untapped.roles is not None
    assert read_set.reads == ()
    for name in reconciled.WRAPPED_ACCESSORS:
        assert GcpSnapshot.__dict__[name] is not ReconciledSnapshot.__dict__[name]


# -- the read tap --------------------------------------------------------------


def test_a_read_inside_reads_is_recorded_and_a_read_outside_is_not(snapshot):
    assert reconciled.active_reads() == ()
    with reconciled.reads("check-a") as read_set:
        assert snapshot.role_exists("roles/viewer") is True
    assert read_set.label == "check-a"
    assert ("roles", "roles/viewer") in read_set
    assert "roles" in read_set.categories()
    assert read_set.keys_of("roles") == ("roles/viewer",)

    before = read_set.reads
    snapshot.principal_exists("user:sre-oncall@acme.example")
    snapshot.roles
    assert read_set.reads == before
    assert reconciled.active_reads() == ()


def test_a_raw_field_access_records_the_whole_category(snapshot):
    with reconciled.reads() as read_set:
        assert snapshot.roles is not None
    # No key: the caller took the table itself, so the read is the category.
    assert read_set.reads == (("roles", ""),)
    assert read_set.keys_of("roles") == ()
    assert read_set.categories() == ("roles",)


def test_captured_at_is_not_tapped(snapshot):
    with reconciled.reads() as read_set:
        assert snapshot.captured_at
    assert read_set.reads == ()


def test_nested_read_sets_both_receive_every_read(snapshot):
    with reconciled.reads("outer") as outer:
        snapshot.role_exists("roles/viewer")
        with reconciled.reads("inner") as inner:
            assert reconciled.active_reads() == (outer, inner)
            snapshot.principal_exists("user:sre-oncall@acme.example")
        snapshot.resource_type_exists("compute.googleapis.com/Instance")

    # Every ACTIVE set receives every read, so the outer set is a superset: a
    # nested sidecar must not steal a read from the check that contains it.
    assert ("principals", "user:sre-oncall@acme.example") in inner
    assert ("principals", "user:sre-oncall@acme.example") in outer
    assert ("roles", "roles/viewer") in outer
    assert ("roles", "roles/viewer") not in inner
    assert ("resource_types", "compute.googleapis.com/Instance") in outer
    assert ("resource_types", "compute.googleapis.com/Instance") not in inner
    assert reconciled.active_reads() == ()


def test_the_read_stack_unwinds_after_an_exception(snapshot):
    assert reconciled.active_reads() == ()
    with pytest.raises(RuntimeError, match="the check exploded"):
        with reconciled.reads("outer") as outer:
            with reconciled.reads("inner"):
                snapshot.role_exists("roles/viewer")
                raise RuntimeError("the check exploded")
    # A leaked entry would go on collecting some later check's reads for the
    # rest of the process, and the taints it reported would be someone else's.
    assert reconciled.active_reads() == ()
    assert ("roles", "roles/viewer") in outer


def test_a_read_is_recorded_once(snapshot):
    with reconciled.reads() as read_set:
        snapshot.role_exists("roles/viewer")
        snapshot.role_exists("roles/viewer")
    assert read_set.reads.count(("roles", "roles/viewer")) == 1
    assert len(read_set) == len(set(read_set))


# -- the accessor wrappers -----------------------------------------------------


def test_the_org_policy_accessor_records_the_composite_key(snapshot):
    if not HAVE_ESTATE_TABLES:
        assert "org_policy" not in reconciled.WRAPPED_ACCESSORS
        return
    node, constraint = "projects/acme-prod", "constraints/compute.vmExternalIpAccess"
    with reconciled.reads() as read_set:
        record = snapshot.org_policy(node, constraint)
    assert record is not None and record is not UNKNOWN
    # The COMPOSITE key, because that is the key the ledger holds an origin
    # for; the node alone would name a key no origin lookup could resolve.
    assert (f"{node}|{constraint}") in read_set.keys_of("org_policies")
    assert node not in read_set.keys_of("org_policies")


def test_a_table_wide_accessor_records_the_whole_category(snapshot):
    if not HAVE_ESTATE_TABLES:
        assert "firewall_rules_for_network" not in reconciled.WRAPPED_ACCESSORS
        return
    network = "projects/acme-prod/global/networks/prod-vpc"
    with reconciled.reads() as read_set:
        found = snapshot.firewall_rules_for_network(network)
    assert found is not UNKNOWN
    # A sweep's answer depends on every row, so the read is the category and
    # the network is not a key: a missing row changes the answer just as much
    # as a matching one does.
    assert ("firewall_rules", "") in read_set
    assert read_set.keys_of("firewall_rules") == ()


def test_a_keyed_accessor_returns_exactly_what_the_parent_returns(plain, snapshot):
    probes = [("role_exists", ("roles/viewer",)),
              ("role_exists", ("roles/nope",)),
              ("permission_exists", ("compute.instances.get",)),
              ("constraint", ("constraints/compute.vmExternalIpAccess",)),
              ("network_tag_exists", ("nope",))]
    if HAVE_ESTATE_TABLES:
        probes += [("firewall_rule", ("projects/acme-prod/global/firewalls/nope",)),
                   ("hierarchy_node", ("projects/acme-prod",))]
    with reconciled.reads() as read_set:
        for name, args in probes:
            tapped = getattr(snapshot, name)(*args)
            untapped = getattr(plain, name)(*args)
            # The tap records BESIDE the answer, never in place of it: True,
            # False, None and the UNKNOWN singleton all come back untouched.
            assert tapped == untapped
            assert type(tapped) is type(untapped)
    assert len(read_set) >= len(probes)


def test_the_module_imports_where_a_keyed_accessor_does_not_exist(monkeypatch):
    # Simulates a tree where sx-kb-estate-tables has not landed: the accessor
    # is simply absent from the parent. Loaded as a FRESH module object rather
    # than reloading the installed one, so no other test ends up holding a
    # half-tapped class.
    monkeypatch.delattr(GcpSnapshot, "firewall_rule")
    monkeypatch.delattr(GcpSnapshot, "firewall_rules_for_network")
    probe = _load_probe("gcp_grounding._reconciled_probe")

    assert "firewall_rule" not in probe.WRAPPED_ACCESSORS
    assert "firewall_rules_for_network" not in probe.WRAPPED_ACCESSORS
    assert "role_exists" in probe.WRAPPED_ACCESSORS
    assert not hasattr(probe.ReconciledSnapshot, "firewall_rule")
    # And what DID land still works.
    built = probe.ReconciledSnapshot.from_snapshot(GcpSnapshot.load(VOCAB_SNAPSHOT))
    with probe.reads() as read_set:
        assert built.role_exists("roles/viewer") is True
    assert ("roles", "roles/viewer") in read_set


def _load_probe(name: str):
    spec = importlib.util.spec_from_file_location(name, Path(reconciled.__file__))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# -- the provenance surface ----------------------------------------------------


def _tainted_ledger(taint: str = "stale") -> provenance.SourceLedger:
    return provenance.SourceLedger(
        sources={"api": provenance.SourceRecord(source_id="api", kind="api",
                                                scope="complete")},
        categories={
            "roles": provenance.CategoryScope(scope="complete", taint=taint, keys=1,
                                              source_kinds=("api",)),
            "principals": provenance.CategoryScope(scope="complete", keys=1,
                                                   source_kinds=("api",)),
        })


def test_require_complete_delegates_to_provenance(plain):
    ledger = _tainted_ledger()
    merged = ReconciledSnapshot.from_snapshot(plain, ledger=ledger)
    for category in ("roles", "principals", "networks"):
        assert merged.require_complete(category, rule="R1") == \
            provenance.require_complete(ledger, category, rule="R1")
    assert "tainted 'stale'" in merged.require_complete("roles")
    assert merged.require_complete("principals") is None


def test_require_complete_with_no_ledger_reads_as_the_plain_snapshot(plain, snapshot):
    # Inertness again: with nothing to report, the snapshot IS the source, which
    # is the plain-GcpSnapshot semantics require_complete already defines.
    for category in ("roles", "firewall_rules", "networks"):
        assert snapshot.require_complete(category, rule="R1") == \
            provenance.require_complete(plain, category, rule="R1")
    assert snapshot.require_complete("roles") is None


def test_taints_for_reports_a_category_wide_taint_for_a_single_key(plain):
    merged = ReconciledSnapshot.from_snapshot(plain, ledger=_tainted_ledger())
    with reconciled.reads() as read_set:
        merged.role_exists("roles/viewer")
        merged.principal_exists("user:sre-oncall@acme.example")
    # DOCUMENTED COARSENESS: the key was read, the CATEGORY carries the taint,
    # and the key inherits it — over-reported doubt costs a re-capture, while
    # under-reported doubt costs a wrong verdict.
    assert ("roles", "roles/viewer", "stale") in merged.taints_for(read_set)
    assert ("roles", "", "stale") in merged.taints_for(read_set)
    assert not [t for t in merged.taints_for(read_set) if t[0] == "principals"]


def test_taints_for_is_empty_with_no_ledger(snapshot):
    with reconciled.reads() as read_set:
        snapshot.role_exists("roles/viewer")
    assert snapshot.taints_for(read_set) == ()


def test_disputes_are_reported_and_never_subtracted(plain):
    if not HAVE_ESTATE_TABLES:
        return
    key = "projects/acme-prod/global/firewalls/allow-internal"
    dispute = provenance.Dispute(category="firewall_rules", key=key,
                                 field="priority", left="1000", right="900",
                                 reason="tfstate and the api disagree")
    merged = ReconciledSnapshot.from_snapshot(plain, disputes=[dispute])
    assert merged.disputes_for("firewall_rules", key) == (dispute,)
    assert merged.disputes_for("firewall_rules", "projects/p/global/firewalls/x") == ()
    # The disputed record is STILL returned: hiding it would shrink a category
    # that licenses reasoning from absence, and let a check prove a
    # non-existence it has not earned.
    assert merged.firewall_rule(key) == plain.firewall_rule(key)
    assert merged == plain
