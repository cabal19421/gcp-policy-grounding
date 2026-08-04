"""Vocabulary grounding tests: :mod:`gcp_grounding.sec_vocab` over the shared
snapshot fixture.

A requirement's ``vocabulary`` is pushed through the same Datalog existence
reasoner a policy document is, so the marquee behaviour is that a requirement
naming ``roles/bigquery.reader`` is proved *ungrounded* and points at
``roles/bigquery.dataViewer``. These build :class:`Promise` objects directly —
no parser needed — and load the fixture snapshot exactly as
``tests/test_gcp_preflight.py`` does.
"""

from pathlib import Path

import pytest

from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.sec_artifact import Promise, Source, VocabRef
from gcp_grounding.sec_vocab import (VocabOutcome, ground_all,
                                     ground_promise_vocabulary)

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"

GHOST = "serviceAccount:ghost-runner@acme-prod.iam.gserviceaccount.com"


@pytest.fixture()
def snap() -> GcpSnapshot:
    return GcpSnapshot.load(FIXTURES / "snapshot.json")


def _promise(pid: str, *vocab: VocabRef) -> Promise:
    """A vocabulary-only promise: status/mode/etc. are irrelevant to grounding,
    so pick a benign non-``compiled`` status that needs no witnesses."""
    return Promise(
        id=pid,
        source=Source(text="a requirement sentence"),
        domain="iam",
        mode="refute",
        state="proposal",
        status="unverified",
        reason="vocabulary-only fixture",
        vocabulary=vocab,
    )


# -- grounded clean -----------------------------------------------------------


def test_real_role_grounds_clean(snap):
    outcome = ground_promise_vocabulary(
        _promise("p-dataviewer", VocabRef("role", "roles/bigquery.dataViewer")), snap)
    assert isinstance(outcome, VocabOutcome)
    assert outcome.ungrounded == ()
    assert outcome.unverified == ()
    assert outcome.suggestions == {}
    assert len(outcome.verdicts) == 1
    assert outcome.verdicts[0].status == "grounded"
    assert outcome.verdicts[0].kind == "role"


def test_empty_vocabulary_never_blocks(snap):
    outcome = ground_promise_vocabulary(_promise("p-empty"), snap)
    assert outcome == VocabOutcome()
    assert outcome.verdicts == ()
    assert outcome.ungrounded == ()


# -- ungrounded: the three planted hallucinations -----------------------------


def test_hallucinated_role_is_ungrounded_with_suggestion(snap):
    outcome = ground_promise_vocabulary(
        _promise("p-reader", VocabRef("role", "roles/bigquery.reader")), snap)
    assert outcome.ungrounded == ("roles/bigquery.reader",)
    assert outcome.unverified == ()
    assert len(outcome.verdicts) == 1
    v = outcome.verdicts[0]
    assert v.status == "ungrounded"
    assert "roles/bigquery.dataViewer" in v.suggestions
    assert "roles/bigquery.dataViewer" in outcome.suggestions["roles/bigquery.reader"]


def test_hallucinated_principal_is_ungrounded(snap):
    outcome = ground_promise_vocabulary(
        _promise("p-ghost", VocabRef("principal", GHOST)), snap)
    assert outcome.ungrounded == (GHOST,)
    assert outcome.unverified == ()
    assert outcome.verdicts[0].status == "ungrounded"
    assert outcome.verdicts[0].kind == "principal"


def test_hallucinated_constraint_is_ungrounded_with_suggestion(snap):
    typo = "constraints/compute.disableSerialPortAcces"  # missing final 's'
    outcome = ground_promise_vocabulary(
        _promise("p-constraint", VocabRef("constraint", typo)), snap)
    assert outcome.ungrounded == (typo,)
    assert "constraints/compute.disableSerialPortAccess" in outcome.suggestions[typo]
    assert outcome.verdicts[0].status == "ungrounded"
    assert outcome.verdicts[0].kind == "constraint"


# -- unverified: a category the snapshot never captured -----------------------


def test_uncaptured_principal_is_unverified_not_ungrounded():
    # A snapshot that never enumerated principals cannot prove absence, so a
    # principal vocab entry abstains (unverified) rather than rejecting.
    snap = GcpSnapshot(captured_at="2026-07-18T09:30:00Z")
    assert snap.principals is None
    outcome = ground_promise_vocabulary(
        _promise("p-ghost", VocabRef("principal", GHOST)), snap)
    assert outcome.ungrounded == ()
    assert GHOST not in outcome.ungrounded
    assert outcome.unverified == (GHOST,)
    assert outcome.verdicts[0].status == "unverified"


# -- ground_all: batched partitioning -----------------------------------------


def test_ground_all_keys_and_partitions_by_promise_id(snap):
    promises = [
        _promise("p-good", VocabRef("role", "roles/bigquery.dataViewer")),
        _promise("p-bad", VocabRef("role", "roles/bigquery.reader")),
        _promise("p-ghost", VocabRef("principal", GHOST)),
    ]
    outcomes = ground_all(promises, snap)

    assert set(outcomes) == {"p-good", "p-bad", "p-ghost"}
    assert outcomes["p-good"].ungrounded == ()
    assert outcomes["p-bad"].ungrounded == ("roles/bigquery.reader",)
    assert outcomes["p-ghost"].ungrounded == (GHOST,)

    # Each verdict's location carries its own promise id, and every location is
    # unique — so partitioning cannot cross-attribute one promise's verdict to
    # another.
    locations = []
    for pid, outcome in outcomes.items():
        for v in outcome.verdicts:
            location = v.message.split(": ", 1)[0]
            assert location == f"requirement:{pid}#vocabulary[0]"
            locations.append(location)
    assert len(locations) == len(set(locations)) == 3


def test_ground_all_honours_artifact_label(snap):
    outcomes = ground_all([_promise("p-bad", VocabRef("role", "roles/bigquery.reader"))],
                          snap, artifact_label="sec_requirements/iam.md")
    v = outcomes["p-bad"].verdicts[0]
    assert v.message.startswith("sec_requirements/iam.md:p-bad#vocabulary[0]:")
