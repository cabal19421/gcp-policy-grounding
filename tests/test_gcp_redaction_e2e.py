"""THE literal acceptance bar for the secrets invariant, across every output
stream at once.

Every other module asserts one half of the boundary in isolation: the tfstate
reader replaces an attribute, ``estate.py`` converts the object to its wire
string, ``explain_state`` refuses to ship a render carrying a vault plaintext.
None of them can say the thing an operator actually needs said, which is that a
value that entered the process never came back out — on stdout, on stderr, or in
a log record — no matter which of those layers was the one that touched it. That
sentence is only checkable end to end, so it is checked here.

TWO BARS, NOT ONE. "The secret never appears" is satisfied by a constant mask,
and a constant mask silently switches drift detection off for every sensitive
field: two redacted documents compare EQUAL, no dispute is raised, and nothing
ever learns that the two sources disagreed. So the second bar — two DIFFERENT
secrets must render differently, and the SAME secret must render identically
across sources — is asserted alongside the first, in
:func:`test_a_disagreement_on_a_sensitive_field_reports_two_different_digests`
and :func:`test_two_sources_agreeing_on_a_sensitive_field_produce_no_drift`.
Neither is meaningful without the other.

THE THIRD BAR IS THE OPPOSITE ONE. An implementation that redacted everything
would pass both of the above and be useless: it would redact the KMS key names
and resource paths that identity matching is BUILT on, turning every such fact
into a sole-source fact — which has nothing to disagree with, so drift detection
switches off for the whole category, silently. So
:func:`test_the_kms_key_name_survives_and_the_two_sources_match_one_fact` and
:func:`test_a_non_secret_of_the_same_shape_passes_through_unredacted` are the
over-redaction guards, and this module fails if the boundary gets greedy.

FIXTURES. ``tests/fixtures/gcp/sources/tf_secretful.json`` is a small v4 tfstate
carrying :data:`CANARY` in FOUR places, reached by BOTH detection routes:

- ``google_service_account.etl-runner.private_key.pem`` — a nested attribute
  under a private-key field, caught by the NAME heuristic (route 3);
- ``...credentials[1]`` — an element of a list under a credentials key, route 3
  again, and the route that matters most in practice because a tfstate stores
  sensitive values in PLAINTEXT and its ``sensitive_attributes`` list is only a
  display marker;
- ``...bootstrap_blob[0]`` — an innocuous key name no pattern catches, reachable
  only through the instance's declared cty path, in the tfstate
  get_attr-then-index shape (route 1);
- ``google_org_policy_policy.cmek-gate``'s
  ``spec[0].rules[0].condition[0].expression`` — route 1 again, through a six
  step cty path, and the one that lands INSIDE an estate record, which is what
  makes the drift pins below reachable at all.

The same fixture carries the two over-redaction guards: a KMS key name that must
survive verbatim, and :data:`CONTROL`, a non-secret of exactly the canary's
length and character class sitting in the sibling field of a value that IS
redacted.

NO SUBPROCESS IS SPAWNED. Every CLI assertion runs :func:`gcp_grounding.cli.main`
in process under ``capsys``, because a child process would only add spawn budget
to the same answer — and because a log record only exists inside the process
that made it.

EVERY ASSERTION NAMES ITS STREAM. A bare ``assert CANARY not in text`` that fires
tells a reader nothing about which of the four channels leaked, and this is
exactly the failure where knowing that is the whole job.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path

import pytest

from gcp_grounding import cli, redact, sources
from gcp_grounding.core import log as core_log

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
SECRETFUL = FIXTURES / "sources" / "tf_secretful.json"
#: The legacy vocabulary-only snapshot. It is the VOCABULARY, never a state
#: source, and it carries no estate record table — so nothing it contributes can
#: mask a leak coming out of the terraform side.
SNAPSHOT = FIXTURES / "snapshot.json"
GOOD = FIXTURES / "policies" / "iam_policy_good.json"

#: THE canary. One literal, in four places in the fixture, so a partial
#: implementation that closes one route shows up as a failure and not as a
#: narrower pass.
CANARY = "KNOWN-SECRET-VALUE-8f3a1c"
#: The second secret the drift pins disagree about. Never in the fixture — the
#: pair is derived from it — and asserted absent from every stream alongside the
#: canary, because "drift on a secret is reportable" is worth nothing if the
#: report prints the other side.
OTHER_SECRET = "OTHER-SECRET-VALUE-2b7e9d"
#: The two plaintexts ONLY the name heuristic reaches. They sit under
#: ``credentials`` and ``private_key``, which no cty path in the fixture names
#: and which no mapper carries into an estate record — so the vault, and the log
#: filter that reads it, is the only place their replacement is observable. They
#: are what keeps route 3 asserted: the canary alone cannot say which route
#: caught it, because it sits on both.
NAME_CAUGHT = ("SECOND-CREDENTIAL-e4b91d", "key-id-3f7a2b9c-not-itself-a-secret")
#: The NEGATIVE CONTROL: same length, same character class, not a secret, and it
#: sits in ``condition.title`` — the sibling field of the redacted
#: ``condition.expression``. An implementation that redacted the whole condition
#: block, or everything that looks like this, loses it.
CONTROL = "PLAIN-PUBLIC-VALUE-4d2e0b"
#: A REAL-LOOKING resource name that must SURVIVE. Redacting an identity-bearing
#: name is not a safe direction: it makes both sources' facts unmatchable, and a
#: sole-source fact has nothing to disagree with.
KMS_KEY_NAME = ("projects/acme-prod/locations/us-central1/keyRings/tf-state/"
                "cryptoKeys/estate-signing")
#: The one estate row the fixture's org policy lands on.
ORG_POLICY_KEY = "projects/acme-prod|constraints/gcp.restrictCmekCryptoKeyProjects"

#: Far past the default freshness ceiling, so a single-source load still
#: produces notes and the "no note carries it" assertion is not vacuous.
MUCH_LATER = "2027-07-18T10:00:00Z"

#: The shape both :data:`CANARY` and :data:`CONTROL` have. Asserted rather than
#: eyeballed: a control that is not the same shape as the canary controls for
#: nothing.
SHAPE = re.compile(r"^[A-Z]+-[A-Z]+-[A-Z]+-[0-9a-f]{6}$")


# -- process hygiene -----------------------------------------------------------


@pytest.fixture(autouse=True)
def _state_env_off(monkeypatch):
    """No test here inherits a developer's exported state configuration: an
    ambient ``$GCP_GROUNDING_TF_STATE`` would silently add a source, and an
    ambient ``$GCP_GROUNDING_REDACT_SALT`` would move every digest asserted
    below."""
    for name in list(os.environ):
        if name.startswith("GCP_GROUNDING"):
            monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _restore_harness_logging():
    """The ``harness`` logger is PROCESS-WIDE and so is the filter on its
    handlers. Restore the handler set, the level and the propagate flag exactly,
    so a test that runs ``setup_logging`` cannot leave the rest of the suite
    writing to a console handler it never asked for."""
    root = logging.getLogger(redact._HARNESS_ROOT)
    handlers, filters = list(root.handlers), list(root.filters)
    level, propagate = root.level, root.propagate
    try:
        yield
    finally:
        for handler in list(root.handlers):
            if handler not in handlers:
                root.removeHandler(handler)
        root.handlers[:] = handlers
        root.filters[:] = filters
        root.setLevel(level)
        root.propagate = propagate


class _Recorder(logging.Handler):
    """A handler that keeps the records it was HANDED — after the handler-level
    filters ran, which is the only place the scrub happens."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def text(self) -> str:
        return "\n".join(record_text(record) for record in self.records)


def record_text(record: logging.LogRecord) -> str:
    """One record's FORMATTED message plus every argument stringified.

    Both halves, deliberately. ``%``-formatting stringifies an argument on its
    way to the stream, so a scrub that rewrote ``record.msg`` and left
    ``record.args`` alone still leaks — and a reader who only looked at
    ``getMessage()`` would never see it.
    """
    args = record.args
    if isinstance(args, dict):
        rendered = [f"{key}={value!r}" for key, value in args.items()]
    elif isinstance(args, tuple):
        rendered = [repr(value) for value in args]
    elif args is None:
        rendered = []
    else:
        rendered = [repr(args)]
    return " ".join([record.getMessage(), *rendered])


@pytest.fixture
def harness_records():
    """A :class:`_Recorder` on the bare ``harness`` logger at DEBUG.

    ``caplog`` alone cannot see these records: ``core.log.setup_logging`` sets
    ``propagate = False`` on ``harness``, so nothing reaches the root logger
    that pytest's capture handler lives on. Attaching here is what makes the
    assertion measure the real handler set.
    """
    root = logging.getLogger(redact._HARNESS_ROOT)
    recorder = _Recorder()
    root.addHandler(recorder)
    root.setLevel(logging.DEBUG)
    try:
        yield recorder
    finally:
        root.removeHandler(recorder)


@pytest.fixture
def harness_caplog(caplog):
    """``caplog`` at DEBUG on the ``harness`` logger, wired so it actually
    receives records: its own handler is attached to ``harness`` directly, for
    the propagate reason above."""
    root = logging.getLogger(redact._HARNESS_ROOT)
    caplog.set_level(logging.DEBUG, logger=redact._HARNESS_ROOT)
    root.addHandler(caplog.handler)
    try:
        yield caplog
    finally:
        root.removeHandler(caplog.handler)


# -- helpers -------------------------------------------------------------------


def options(*state_paths: str, **overrides) -> sources.SourceOptions:
    settings = {"terraform_state": tuple(state_paths or (str(SECRETFUL),)),
                "max_age": "off", "now": MUCH_LATER}
    settings.update(overrides)
    return sources.SourceOptions(**settings)


def invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = cli.main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


def verify(*state_paths: str, extra: tuple[str, ...] = ()) -> list[str]:
    """The ``verify-policy`` command line these tests share."""
    argv = ["verify-policy", str(GOOD), "--snapshot", str(SNAPSHOT),
            "--max-age", "off", "--no-config"]
    for path in state_paths:
        argv += ["--terraform-state", path]
    return argv + list(extra)


def secret_pair(tmp_path, left: str, right: str) -> tuple[str, str]:
    """Two copies of the fixture whose org policy condition carries *left* and
    *right*, and which are otherwise byte-identical.

    Derived rather than committed: the ONLY difference between the two files is
    the one sensitive value, so a dispute that shows up can be about nothing
    else. The serial and lineage move too, because two state files claiming one
    lineage and one serial are the same file to the reader.
    """
    document = json.loads(SECRETFUL.read_text(encoding="utf-8"))
    written = []
    for index, secret in enumerate((left, right), start=1):
        copy = json.loads(json.dumps(document))
        copy["serial"] = 40 + index
        copy["lineage"] = f"7c2d90a1-4b6e-4f03-9d51-2a7e6b04c1{index:02d}"
        for resource in copy["resources"]:
            if resource["type"] == "google_org_policy_policy":
                rule = resource["instances"][0]["attributes"]["spec"][0]["rules"][0]
                rule["condition"][0]["expression"] = secret
        path = tmp_path / f"pair{index}.tfstate"
        path.write_text(json.dumps(copy), encoding="utf-8")
        written.append(str(path))
    return written[0], written[1]


def absent(canary: str, where: str, text: str) -> None:
    """One assertion, one stream NAMED. A bare boolean failure here is
    unreadable: 'False is not True' says nothing about which of four channels
    published the value."""
    assert canary not in text, (
        f"the withheld value {canary[:6]}... reached {where} - "
        f"{len(text)} characters were checked")


# -- 1: the reconciled estate --------------------------------------------------


def test_no_canary_reaches_the_snapshot_the_ledger_or_any_note():
    """The load itself, before anything renders: the three documents a caller
    holds after ``load_current`` are the snapshot, the ledger and the notes, and
    the canary is in none of them."""
    state = sources.load_current(options(max_age=None))

    assert state.ok and state.reconciled, state.problem
    absent(CANARY, "the serialized snapshot", json.dumps(state.snapshot.to_dict()))
    absent(CANARY, "the serialized ledger", json.dumps(state.ledger.to_dict()))
    assert state.notes, ("no note came back, so the per-note assertion below "
                         "would be vacuous")
    for note in state.notes:
        absent(CANARY, f"note[{note.kind}].message", note.message)
        absent(CANARY, f"note[{note.kind}].target", note.target)
        absent(CANARY, f"note[{note.kind}].suggestions",
               "\n".join(note.suggestions))


def test_the_snapshot_keeps_the_wire_spelling_so_a_reader_still_abstains():
    """The canary is not merely gone: what stands in its place is the wire form
    ``redacted:sha256:<digest>``, which ``has_redacted`` still recognises. A
    boundary that DROPPED the field would pass the test above and quietly turn
    'withheld' into 'absent'."""
    state = sources.load_current(options())
    record = state.snapshot.org_policies[ORG_POLICY_KEY]

    assert redact.has_redacted(record) is True
    assert record["rules"][0]["condition"]["expression"] == \
        redact.Redacted.of(CANARY).wire()
    # ``expression`` matches NO name pattern, so route 1 — the declared cty path
    # — is the only thing that could have replaced it.


def test_both_detection_routes_fed_the_process_vault():
    """The fixture exercises BOTH routes, and this is the test that says so.

    Route 1 is pinned by the wire spelling above; this pins route 3, whose
    catches live under ``credentials`` and ``private_key`` — attributes no cty
    path names and no mapper carries into an estate record, so the vault is
    where they are observable and the log filter is what makes that matter. A
    boundary running only route 1 leaves every unflagged attribute in a tfstate
    unscrubbed, which is the common case rather than the rare one: a tfstate
    stores sensitive values in PLAINTEXT and ``sensitive_attributes`` is only a
    display marker.
    """
    state = sources.load_current(options())
    assert state.ok, state.problem

    for secret in NAME_CAUGHT:
        assert secret in sources.vault(), (
            f"the name heuristic did not reach {secret[:6]}..., so nothing "
            f"scrubs it out of a message built by hand")


# -- 2 and 3: the CLI, every stream at once ------------------------------------


@pytest.mark.parametrize("fmt", ["json", "text"])
def test_no_canary_on_stdout_stderr_or_in_any_log_record(capsys, harness_caplog,
                                                         fmt):
    """The headline bar, run for BOTH output formats.

    ``--format json`` and ``--format text`` render through different code, and a
    scrub wired into only one of them passes half of this suite. The log channel
    is checked at the ``harness`` handler because that is where a record ends up
    — and both the formatted message AND the stringified arguments are checked,
    because ``%``-formatting turns an argument into stream bytes without ever
    touching ``record.msg``.
    """
    code, out, err = invoke(capsys, *verify(str(SECRETFUL), extra=("--format", fmt)))

    assert code == 0, err
    assert harness_caplog.records, (
        "no record reached the harness handler, so the log assertions below "
        "would be vacuous")
    absent(CANARY, f"stdout (--format {fmt})", out)
    absent(CANARY, f"stderr (--format {fmt})", err)
    for record in harness_caplog.records:
        absent(CANARY, f"log record {record.name} (--format {fmt})",
               record_text(record))


def test_no_canary_survives_the_explain_flag(capsys, harness_caplog):
    """``--explain`` opens a SECOND stderr stream — the solver block and the
    state block — built by a different renderer from the report itself, and it
    is the one that prints record VALUES rather than only counts."""
    code, out, err = invoke(
        capsys, *verify(str(SECRETFUL), extra=("--format", "json", "--explain")))

    assert code == 0, err
    assert err, "--explain wrote nothing to stderr, so this pins nothing"
    assert harness_caplog.records
    absent(CANARY, "stdout (--explain)", out)
    absent(CANARY, "stderr (--explain)", err)
    for record in harness_caplog.records:
        absent(CANARY, f"log record {record.name} (--explain)", record_text(record))


def test_no_canary_survives_the_state_explain_flag(capsys, harness_caplog):
    """``--state-explain`` is the surface that names every source, every setting
    and every derived counterpart. It is the most value-dense thing this CLI
    prints, so it is the most likely place for a plaintext to reappear."""
    code, out, err = invoke(
        capsys, *verify(str(SECRETFUL), extra=("--state-explain",)))

    assert code == 0, err
    assert "state used this run" in err
    absent(CANARY, "stdout (--state-explain)", out)
    absent(CANARY, "stderr (--state-explain)", err)
    for record in harness_caplog.records:
        absent(CANARY, f"log record {record.name} (--state-explain)",
               record_text(record))


# -- 4 and 5: the reason the digest exists -------------------------------------


def test_a_disagreement_on_a_sensitive_field_reports_two_different_digests(
        capsys, harness_caplog, tmp_path):
    """THE CASE THAT JUSTIFIES THE DIGEST EXISTING AT ALL.

    Two sources disagree about a value the loading boundary withheld. Under
    ``--drift-policy block`` that must be a reported, blocking
    ``drift:material`` — naming BOTH sides so an operator can see that the
    disagreement is real — and it must do that without printing either secret.
    A constant mask would make the two records compare EQUAL and no finding
    would exist at all.
    """
    left, right = secret_pair(tmp_path, CANARY, OTHER_SECRET)

    code, out, err = invoke(capsys, *verify(
        left, right, extra=("--drift-policy", "block", "--format", "json")))

    verdicts = json.loads(out)["verdicts"]
    material = [v for v in verdicts if v["kind"] == "drift:material"]
    assert code == 1 and len(material) == 1, verdicts
    message = material[0]["message"]

    left_digest = redact.Redacted.of(CANARY).wire()
    right_digest = redact.Redacted.of(OTHER_SECRET).wire()
    assert left_digest != right_digest
    assert left_digest in message and right_digest in message, message
    for stream, text in (("stdout", out), ("stderr", err),
                         ("the drift message", message)):
        absent(CANARY, stream, text)
        absent(OTHER_SECRET, stream, text)
    for record in harness_caplog.records:
        absent(CANARY, f"log record {record.name}", record_text(record))
        absent(OTHER_SECRET, f"log record {record.name}", record_text(record))


def test_two_sources_agreeing_on_a_sensitive_field_produce_no_drift(
        capsys, tmp_path):
    """The other half of the same bar: the SAME secret from two sources must
    compare EQUAL.

    A per-record nonce would satisfy every "the plaintext is absent" assertion
    in this module and report a phantom ``drift:material`` on every capture,
    every run, for every sensitive field. That is why the salt is fixed and
    documented and why the digest is over the value alone — not the path, not
    the source, not the record it was found in.
    """
    left, right = secret_pair(tmp_path, CANARY, CANARY)

    code, out, _err = invoke(capsys, *verify(
        left, right, extra=("--drift-policy", "block", "--format", "json")))

    drift_kinds = [v["kind"] for v in json.loads(out)["verdicts"]
                   if v["kind"].startswith("drift")]
    assert code == 0 and drift_kinds == [], drift_kinds


# -- 6 and 8: the over-redaction guards ----------------------------------------


def test_the_kms_key_name_survives_and_the_two_sources_match_one_fact(tmp_path):
    """THE OVER-REDACTION GUARD.

    A KMS key name is an ADDRESS, not a payload. Redacting one is not the safe
    direction: identity matching is built on these names, and a fact whose name
    was replaced matches nothing — which makes it a sole-source fact, and a
    sole-source fact has nothing to disagree with, so drift detection switches
    off for the whole category without saying so.
    """
    left, right = secret_pair(tmp_path, CANARY, CANARY)
    state = sources.load_current(options(left, right))

    assert state.ok and state.reconciled, state.problem
    assert list(state.snapshot.org_policies) == [ORG_POLICY_KEY], \
        "the two sources' policies matched as TWO facts, not one"
    rule = state.snapshot.org_policies[ORG_POLICY_KEY]["rules"][0]
    assert KMS_KEY_NAME in rule["allowed_values"], \
        "the KMS key name did not survive the boundary verbatim"
    assert state.ledger.categories["org_policies"].keys == 1


def test_a_non_secret_of_the_same_shape_passes_through_unredacted():
    """THE NEGATIVE CONTROL.

    :data:`CONTROL` is the canary's length and character class and lives in the
    sibling field of a value that IS withheld. An implementation that redacted
    the whole condition block, or everything that looks like a secret, passes
    every other test in this module and fails this one.
    """
    assert len(CONTROL) == len(CANARY)
    assert SHAPE.match(CONTROL) and SHAPE.match(CANARY)

    state = sources.load_current(options())
    condition = state.snapshot.org_policies[ORG_POLICY_KEY]["rules"][0]["condition"]

    assert condition["title"] == CONTROL, \
        "a non-secret sibling of a withheld value was redacted too"
    assert redact.is_wire(condition["expression"]), \
        "the withheld sibling stopped being withheld, so the control proves nothing"


# -- 7: the log filter ---------------------------------------------------------


def test_a_child_logger_record_after_the_load_is_filtered_at_the_handler(
        harness_records):
    """THE FILTER IS ON THE HANDLERS, AND THAT IS THE WHOLE POINT.

    Every module here logs through a ``harness.*`` CHILD logger from
    ``core.log.get_logger(__name__)``. A child's records reach the parent's
    HANDLERS without ever passing the parent's own filters, so a filter attached
    to the ``harness`` LOGGER passes a test written against the bare name and
    leaks every real record. This asserts at the handler, through a child
    logger, which is the combination that can tell the two apart.
    """
    state = sources.load_current(options())
    assert state.ok, state.problem
    assert CANARY in sources.vault(), (
        "the load did not teach the process vault the plaintext it read, so "
        "the filter below has nothing to scrub with")

    child = core_log.get_logger(__name__)
    assert child.name.startswith(f"{redact._HARNESS_ROOT}.") and \
        child.name != redact._HARNESS_ROOT
    harness_records.records.clear()
    # BOTH routes' plaintexts, because the vault is where route 3's catches are
    # observable at all and a filter fed by only one route is a filter that
    # scrubs half of what the run read.
    for secret in (CANARY, *NAME_CAUGHT):
        child.debug("the loaded value was %s", secret)

    assert len(harness_records.records) == 1 + len(NAME_CAUGHT), \
        "a child record never reached the handler"
    text = harness_records.text()
    absent(CANARY, "a harness handler record", text)
    for secret in NAME_CAUGHT:
        absent(secret, "a harness handler record", text)
    wires = {redact.Redacted.of(secret).wire() for secret in (CANARY, *NAME_CAUGHT)}
    assert len(wires) == 1 + len(NAME_CAUGHT), "two secrets rendered identically"
    assert all(wire in text for wire in wires), \
        "an argument was dropped rather than replaced by its own digest"


def test_the_filter_reattaches_to_handlers_setup_logging_created(harness_records):
    """The same assertion WITH ``setup_logging`` having run.

    ``setup_logging`` is idempotent-but-RECONFIGURING: it removes and re-adds
    its own handlers, so every handler it owns after a call carries no filter.
    ``ensure_log_filter`` — which every report and render boundary calls — is
    what heals that, and a fresh handler added afterwards is the honest stand-in
    for the console handler it just built.
    """
    state = sources.load_current(options())
    assert state.ok, state.problem

    core_log.setup_logging(verbose=2)
    fresh = _Recorder()
    logging.getLogger(redact._HARNESS_ROOT).addHandler(fresh)
    redact.ensure_log_filter(sources.vault())

    core_log.get_logger(__name__).debug("the bootstrap blob was %s", CANARY)

    assert fresh.records, "the record never reached the post-setup handler"
    absent(CANARY, "a handler created by setup_logging", fresh.text())
    absent(CANARY, "the pre-existing harness handler", harness_records.text())


def test_removing_the_filter_restores_the_previous_handler_state_exactly():
    """A boundary that cannot be taken back off cleanly is a boundary nothing
    can test around. ``remove_log_filter`` drops the filter from every handler
    carrying it AND removes the no-op handler the module added, leaving the
    handler set byte-identical to what it found."""
    root = logging.getLogger(redact._HARNESS_ROOT)

    def snapshot() -> list[tuple[int, tuple]]:
        return [(id(handler), tuple(handler.filters)) for handler in root.handlers]

    redact.remove_log_filter()
    before = snapshot()

    filt = redact.install_log_filter(sources.vault())
    assert root.handlers, "the install left no handler to carry the filter"
    assert all(filt in handler.filters for handler in root.handlers)
    assert filt not in root.filters, (
        "the filter went onto the LOGGER, where a child logger's records never "
        "pass it - that is the leak this whole arrangement exists to avoid")

    redact.remove_log_filter()

    assert snapshot() == before
    # Leave the process boundary as this module found it.
    redact.install_log_filter(sources.vault())
