"""Acceptance for :mod:`gcp_grounding.redact` — the one secret boundary.

Two bars, and the second is as load-bearing as the first:

1. a known secret never appears on stdout, on stderr, in any log record, in
   any verdict message or in any sidecar;
2. two DIFFERENT secrets never render identically — a constant mask passes bar
   one and silently suppresses every drift finding on a sensitive field.

Both are asserted here, plus the wire form that lets the type reach disk at
all, and the log filter asserted AT THE HANDLER rather than at the logger.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import sys

import pytest

from gcp_grounding import facts, fetch, redact
from gcp_grounding.core import log as core_log
from gcp_grounding.core.report import GroundingReport, Verdict
from gcp_grounding.knowledge import GcpSnapshot

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Grep-able sentinels. Same length and character class as the negative
#: control below, so a test that goes green cannot be going green because the
#: implementation redacts everything.
SECRET_A = "FIXTURE-SECRET-DO-NOT-LEAK"
SECRET_B = "FIXTURE-SECRET-BY-NAME-XXXX"
CANARY = "KNOWN-SECRET-VALUE-8f3a1c"

#: A real-looking KMS resource name. It must SURVIVE verbatim: it is an
#: identity key, and redacting it turns every fact keyed by it into a
#: sole-source fact, which switches drift detection off for the category.
KMS_KEY_NAME = "projects/acme-prod/locations/global/keyRings/tf/cryptoKeys/state"

#: Only the digest is printed, so the child needs nothing from this module.
_DIGEST_SCRIPT = (
    "import sys; sys.path.insert(0, sys.argv[1]);"
    "from gcp_grounding.redact import value_digest;"
    "sys.stdout.write(value_digest(sys.argv[2]))"
)


def _digest_in_child(value: str, *, salt: str | None) -> str:
    """The digest of *value* computed in a FRESH interpreter."""
    env = dict(os.environ)
    if salt is None:
        env.pop(redact.SALT_ENV, None)
    else:
        env[redact.SALT_ENV] = salt
    out = subprocess.run([sys.executable, "-c", _DIGEST_SCRIPT, REPO_ROOT, value],
                         check=True, capture_output=True, text=True, env=env)
    return out.stdout.strip()


# -- bar two: comparable digests ----------------------------------------------


def test_two_different_secrets_produce_different_digests():
    assert redact.value_digest(SECRET_A) != redact.value_digest(SECRET_B), (
        "a constant mask would satisfy 'the secret never appears' and silently "
        "make every drift finding on a sensitive field compare equal")


def test_same_secret_produces_the_same_digest_across_two_calls():
    assert redact.value_digest(SECRET_A) == redact.value_digest(SECRET_A)


def test_digest_is_stable_across_two_processes_with_a_fixed_salt(monkeypatch):
    monkeypatch.setenv(redact.SALT_ENV, "team-salt-for-the-test")
    here = redact.value_digest(SECRET_A)
    there = _digest_in_child(SECRET_A, salt="team-salt-for-the-test")
    assert here == there, "a fixed salt must give the same digest in every process"


def test_digest_is_stable_across_two_processes_with_the_salt_UNSET(monkeypatch):
    """The pin that DEFAULT_REDACT_SALT is a CONSTANT and not a per-process
    nonce. A per-process salt makes digests incomparable across runs, so every
    capture-then-verify round trip reports phantom drift on every sensitive
    field."""
    monkeypatch.delenv(redact.SALT_ENV, raising=False)
    here = redact.value_digest(SECRET_A)
    there = _digest_in_child(SECRET_A, salt=None)
    assert here == there
    assert redact.current_salt() == redact.DEFAULT_REDACT_SALT
    assert redact.DEFAULT_REDACT_SALT.isascii() and redact.DEFAULT_REDACT_SALT


def test_the_env_salt_actually_changes_the_digest(monkeypatch):
    monkeypatch.setenv(redact.SALT_ENV, "salt-one")
    one = redact.value_digest(SECRET_A)
    monkeypatch.setenv(redact.SALT_ENV, "salt-two")
    assert redact.value_digest(SECRET_A) != one


# -- the replacement type -----------------------------------------------------


def test_truth_testing_a_redacted_raises():
    marker = redact.Redacted.of(SECRET_A, "values.private_key")
    with pytest.raises(TypeError, match="neither True nor False"):
        bool(marker)
    with pytest.raises(TypeError):
        if marker:                      # the shape that must never compile away
            pass


def test_redacted_compares_by_digest_not_by_path():
    from_state = redact.Redacted.of(SECRET_A, "values.private_key")
    from_plan = redact.Redacted.of(SECRET_A, "after.private_key")
    other = redact.Redacted.of(SECRET_B, "values.private_key")
    assert from_state == from_plan, "the same secret from two sources must match"
    assert from_state != other, "two different secrets must stay different"
    assert len({from_state, from_plan}) == 1


def test_redacted_repr_carries_the_digest_and_never_the_value():
    marker = redact.Redacted.of(SECRET_A, "values.private_key")
    assert SECRET_A not in repr(marker)
    assert marker.digest in repr(marker)
    assert SECRET_A not in facts.safe_repr(marker)


def test_redacted_rejects_a_digest_that_is_not_one():
    with pytest.raises(ValueError, match="hex characters"):
        redact.Redacted("nope")


# -- the walkers --------------------------------------------------------------


def test_has_unresolved_does_not_fire_but_has_redacted_does_for_both_spellings():
    marker = redact.Redacted.of(SECRET_A, "values.private_key")
    document = {"values": {"private_key": marker, "network": "default"}}

    assert facts.has_unresolved(document) is False, (
        "a Redacted is NOT an Unresolved — it is deliberately kept and compared, "
        "not stripped")
    assert redact.has_redacted(document) is True

    on_the_wire = {"values": {"private_key": marker.wire(), "network": "default"}}
    assert facts.has_unresolved(on_the_wire) is False
    assert redact.has_redacted(on_the_wire) is True, (
        "past the estate.py boundary the value is a plain str, so has_redacted "
        "MUST recognise the wire string or the abstention path dies there")

    assert redact.has_redacted({"values": {"network": "default"}}) is False
    assert redact.has_redacted(marker.wire()) is True

    paths = dict(redact.redacted_in(document))
    assert list(paths) == ["values.private_key"]


# -- route 1: the tfstate cty encoding ----------------------------------------


def test_a_cty_path_list_redacts_exactly_the_named_attribute():
    values = {"private_key": SECRET_A, "email": "sa@acme-prod.iam.gserviceaccount.com",
              "keys": [{"blob": SECRET_B}]}
    sensitive_paths = [[{"type": "get_attr", "value": "private_key"}]]

    out, notes = redact.redact(values, sensitive_paths=sensitive_paths)

    assert isinstance(out["private_key"], redact.Redacted)
    assert out["private_key"].digest == redact.value_digest(SECRET_A)
    assert out["email"] == "sa@acme-prod.iam.gserviceaccount.com"
    assert notes == ()
    assert values["private_key"] == SECRET_A, "redact() must never mutate its input"


def test_the_digest_does_not_depend_on_which_route_caught_the_value():
    """The three routes run in sequence over the same document, so route 3
    meets what route 1 replaced. Re-digesting there would hash a repr, and the
    same secret would digest differently per source — phantom drift again."""
    by_path, _ = redact.redact({"private_key": SECRET_A},
                               sensitive_paths=[[{"type": "get_attr",
                                                  "value": "private_key"}]])
    by_name, _ = redact.redact({"private_key": SECRET_A})
    by_mirror, _ = redact.redact({"private_key": SECRET_A},
                                 mirror={"private_key": True})

    assert (by_path["private_key"].digest
            == by_name["private_key"].digest
            == by_mirror["private_key"].digest
            == redact.value_digest(SECRET_A))


def test_a_cty_path_with_an_index_step_redacts_one_element():
    values = {"blobs": ["public", SECRET_A]}
    sensitive_paths = [[{"type": "get_attr", "value": "blobs"},
                        {"type": "index", "value": {"number": 1}}]]

    out, notes = redact.redact(values, sensitive_paths=sensitive_paths)

    assert out["blobs"][0] == "public"
    assert isinstance(out["blobs"][1], redact.Redacted)
    assert notes == ()


def test_an_unrecognised_cty_step_redacts_the_whole_instance_and_notes_it():
    values = {"private_key": SECRET_A, "email": "sa@acme-prod.iam.gserviceaccount.com"}
    sensitive_paths = [[{"type": "attr_by_moonlight", "value": "private_key"}]]

    out, notes = redact.redact(values, sensitive_paths=sensitive_paths)

    assert isinstance(out, redact.Redacted), (
        "FAIL-SAFE: a step shape we do not decode must never silently reveal a value")
    assert notes and any("whole instance" in note for note in notes)
    assert SECRET_A not in " ".join(notes)


# -- route 2: the plan's sensitive mirror -------------------------------------


def test_a_plan_mirror_with_a_container_level_true_redacts_the_container():
    values = {"bootstrap": {"blob": SECRET_A, "shape": "pem"}, "name": "sa-ci"}
    mirror = {"bootstrap": True}

    out, notes = redact.redact(values, mirror=mirror)

    assert isinstance(out["bootstrap"], redact.Redacted), (
        "a true on a CONTAINER redacts the container whole — descending into it "
        "would publish its shape and its siblings")
    assert out["name"] == "sa-ci"
    assert notes == ()


def test_a_plan_mirror_marks_a_single_leaf():
    values = {"config": {"blob": SECRET_A, "region": "us-central1"}}
    out, _ = redact.redact(values, mirror={"config": {"blob": True}})
    assert isinstance(out["config"]["blob"], redact.Redacted)
    assert out["config"]["region"] == "us-central1"


# -- route 3: the name heuristic ----------------------------------------------


def test_a_kms_key_name_survives_while_a_private_key_sibling_does_not():
    values = {"private_key": SECRET_A, "kms_key_name": KMS_KEY_NAME}

    out, _ = redact.redact(values)

    assert out["kms_key_name"] == KMS_KEY_NAME, (
        "a KMS key NAME is a RESOURCE NAME used as an identity key; redacting it "
        "breaks canonical-key matching and switches drift detection off")
    assert isinstance(out["private_key"], redact.Redacted)


def test_camelcase_private_key_and_service_account_key_are_both_redacted():
    """The case-fold regression guard: a case-SENSITIVE implementation passes
    every snake_case case above and then leaks camelCase, which is the normal
    spelling in plan JSON and HCL JSON."""
    values = {
        "privateKey": SECRET_A,
        "PrivateKey": SECRET_A,
        "serviceAccountKey": SECRET_B,
        "kmsKeyName": KMS_KEY_NAME,          # never-sensitive, case-folded too
        "cryptoKeyVersion": "3",
    }

    out, _ = redact.redact(values)

    for key in ("privateKey", "PrivateKey", "serviceAccountKey"):
        assert isinstance(out[key], redact.Redacted), f"{key} leaked"
    assert out["kmsKeyName"] == KMS_KEY_NAME
    assert out["cryptoKeyVersion"] == "3"

    assert redact.is_sensitive_segment("privateKey")
    assert redact.is_sensitive_segment("SERVICE_ACCOUNT_KEY")
    assert not redact.is_sensitive_segment("kmsKeyName")
    assert not redact.is_sensitive_segment("crypto_key_version")
    assert not redact.is_sensitive_segment("secret_id")
    assert redact.is_sensitive_segment("secret_data")


def test_the_pattern_list_stays_over_broad():
    """The list is deliberately over-broad and must not be trimmed: over-
    redacting costs an abstention, under-redacting costs a leak."""
    for segment in ("password", "auth_token", "client_secret", "credentials",
                    "ssl_certificate", "api_key", "passphrase"):
        assert redact.is_sensitive_segment(segment), segment


def test_nested_sensitive_keys_are_reached():
    values = {"settings": [{"backup": {"password": SECRET_A}}]}
    out, _ = redact.redact(values)
    assert isinstance(out["settings"][0]["backup"]["password"], redact.Redacted)


def test_negative_control_same_length_and_character_class_passes_through():
    """If the implementation simply redacted everything, this would fail."""
    control = "FIXTURE-PUBLIC-VALUE-OKAY-"
    assert len(control) == len(SECRET_A)
    values = {"private_key": SECRET_A, "description": control,
              "display_name": "ci-deployer"}

    out, _ = redact.redact(values)

    assert out["description"] == control
    assert out["display_name"] == "ci-deployer"
    assert isinstance(out["private_key"], redact.Redacted)


# -- the vault and the scrubbers ----------------------------------------------


def test_the_vault_scrubs_longest_value_first():
    vault = redact.SecretVault()
    vault.add("abcdefgh")
    vault.add("abcdefghijkl")

    scrubbed = vault.scrub_text("here is abcdefghijkl in a line")

    assert "abcdefgh" not in scrubbed, (
        "a secret that is a PREFIX of another must not leave a tail behind")
    assert redact.WIRE_PREFIX + redact.value_digest("abcdefghijkl") in scrubbed


def test_the_vault_ignores_values_below_MIN_SECRET_LEN():
    vault = redact.SecretVault()
    assert vault.add("a" * (redact.MIN_SECRET_LEN - 1)) is False
    assert vault.add("a" * redact.MIN_SECRET_LEN) is True
    assert SECRET_A not in repr(vault)


def test_redact_feeds_the_vault_and_scrub_record_removes_the_plaintext():
    vault = redact.SecretVault()
    redact.redact({"private_key": SECRET_A}, vault=vault)

    record = {"message": f"binding uses {SECRET_A} as a key", "role": "roles/viewer"}
    scrubbed = redact.scrub_record(vault, record)

    assert SECRET_A not in json.dumps(scrubbed)
    assert scrubbed["role"] == "roles/viewer"


def test_scrub_verdicts_returns_the_identical_tuple_when_nothing_matched():
    vault = redact.SecretVault()
    vault.add(SECRET_A)
    clean = (Verdict("grounded", "roles", "roles/viewer", 0, "exists"),
             Verdict("unverified", "roles", "roles/editor", 0, "undecidable"))

    assert redact.scrub_verdicts(vault, clean) is clean, (
        "a no-op scrub over a clean report must allocate nothing — it runs on "
        "EVERY report")

    dirty = clean + (Verdict("ungrounded", "roles", SECRET_A, 0,
                             f"no such role {SECRET_A}"),)
    scrubbed = redact.scrub_verdicts(vault, dirty)

    assert scrubbed is not dirty
    assert scrubbed[0] is clean[0] and scrubbed[1] is clean[1], (
        "unchanged elements come back BY IDENTITY")
    assert SECRET_A not in scrubbed[2].message
    assert SECRET_A not in scrubbed[2].target
    assert redact.value_digest(SECRET_A) in scrubbed[2].message


def test_scrub_report_rewrites_the_report_in_place():
    vault = redact.SecretVault()
    vault.add(SECRET_A)
    report = GroundingReport()
    report.add(Verdict("ungrounded", "roles", "roles/x", 0, f"saw {SECRET_A}"))

    returned = redact.scrub_report(vault, report)

    assert returned is report
    assert SECRET_A not in json.dumps(report.to_dict()), (
        "a caller holding the report must not be able to render the unscrubbed "
        "one by forgetting a return value")


# -- the wire round trip ------------------------------------------------------


def test_wire_then_parse_recovers_the_digest():
    marker = redact.Redacted.of(SECRET_A, "values.private_key")
    text = marker.wire()

    assert text == f"redacted:sha256:{marker.digest}"
    assert redact.is_wire(text)
    assert not redact.is_wire("redacted:sha256:not-hex")
    assert not redact.is_wire(SECRET_A)

    back = redact.Redacted.parse(text)
    assert back is not None and back.digest == marker.digest and back == marker
    assert redact.Redacted.parse("plain string") is None


def test_two_different_secrets_stay_different_across_the_round_trip():
    a = redact.Redacted.of(SECRET_A, "values.private_key").wire()
    b = redact.Redacted.of(SECRET_B, "values.private_key").wire()

    assert a != b, (
        "two wire strings compare equal exactly when their digests do; equal "
        "strings here would suppress every drift finding on a sensitive field")
    assert redact.Redacted.parse(a) != redact.Redacted.parse(b)

    same_secret_other_source = redact.Redacted.of(SECRET_A, "after.private_key").wire()
    assert a == same_secret_other_source, (
        "the same secret from two sources must still compare equal, or capture-"
        "then-verify reports phantom drift")


def test_a_record_of_wire_strings_crosses_from_dict_and_json_dumps(tmp_path):
    """The two never-edit boundaries: GcpSnapshot.from_dict is the strict path
    and fetch.write_snapshot is json.dumps. A Redacted OBJECT crosses neither,
    which is what the wire form is for."""
    marker = redact.Redacted.of(SECRET_A, "values.private_key")

    with pytest.raises(TypeError):
        json.dumps({"private_key": marker})

    record = redact.to_wire({"roles": {"roles/custom.deployer": {
        "title": "deployer",
        "stage": "GA",
        "private_key": marker,
        "kms_key_name": KMS_KEY_NAME,
    }}})
    document = {"captured_at": "2026-01-01T00:00:00Z", **record}

    snapshot = GcpSnapshot.from_dict(document)          # strict path: no raise
    text = json.dumps(snapshot.to_dict())               # json.dumps: no raise
    assert SECRET_A not in text

    path = tmp_path / "snapshot.json"
    fetch.write_snapshot(snapshot, path)
    assert SECRET_A not in path.read_text(encoding="utf-8")

    reloaded = GcpSnapshot.load(path)
    field = reloaded.roles["roles/custom.deployer"]["private_key"]
    assert isinstance(field, str)
    parsed = redact.Redacted.parse(field)
    assert parsed is not None
    assert parsed.digest == marker.digest, (
        "reloading must yield a field whose digest equals the in-memory value's, "
        "or drift comparison breaks at the disk boundary")
    assert reloaded.roles["roles/custom.deployer"]["kms_key_name"] == KMS_KEY_NAME


def test_to_wire_is_the_single_conversion_and_leaves_everything_else_alone():
    marker = redact.Redacted.of(SECRET_A, "p")
    source = {"a": [1, marker, {"b": marker}], "c": "plain", "d": None}

    out = redact.to_wire(source)

    assert out == {"a": [1, marker.wire(), {"b": marker.wire()}],
                   "c": "plain", "d": None}
    assert isinstance(source["a"][1], redact.Redacted), "to_wire copies, never mutates"
    assert redact.has_redacted(out)


# -- the log filter, asserted AT THE HANDLER ----------------------------------


class _Capture(logging.Handler):
    """Records what actually reached a handler, message formatted at emit time
    (i.e. AFTER the handler's filters ran)."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)
        self.messages.append(record.getMessage())

    @property
    def text(self) -> str:
        return "\n".join(self.messages)


@pytest.fixture
def harness_root():
    """The ``harness`` logger, restored exactly on the way out — these tests
    call ``setup_logging`` and attach handlers, and neither may leak into the
    rest of the suite."""
    root = logging.getLogger(redact._HARNESS_ROOT)
    saved_handlers = list(root.handlers)
    saved_filters = list(root.filters)
    saved_level, saved_propagate = root.level, root.propagate
    try:
        yield root
    finally:
        redact.remove_log_filter()
        for handler in list(root.handlers):
            if handler not in saved_handlers:
                root.removeHandler(handler)
                if getattr(handler, "_harness_owned", False):
                    handler.close()
        root.handlers[:] = saved_handlers
        root.filters[:] = saved_filters
        root.setLevel(saved_level)
        root.propagate = saved_propagate


def _vault_with_canary() -> redact.SecretVault:
    vault = redact.SecretVault()
    assert vault.add(CANARY)
    return vault


def _child_logger():
    """A ``harness.*`` CHILD logger, exactly as every module in this package
    obtains one. Records created here NEVER pass the parent's own filters."""
    logger = core_log.get_logger("gcp_grounding.test")
    assert logger.name.startswith(redact._HARNESS_ROOT + "."), logger.name
    return logger


def test_the_filter_is_attached_to_every_handler_without_setup_logging(harness_root):
    harness_root.handlers[:] = []
    capture = _Capture()
    harness_root.addHandler(capture)
    harness_root.setLevel(logging.DEBUG)
    harness_root.propagate = False
    vault = _vault_with_canary()

    filt = redact.install_log_filter(vault)

    assert all(filt in handler.filters for handler in harness_root.handlers), (
        "the filter must sit on the HANDLERS: a child logger's records reach "
        "the parent's handlers without ever passing the parent's own filters")

    _child_logger().debug("loaded attribute %s from state", CANARY)

    assert capture.messages, "the canary record never reached the handler at all"
    assert CANARY not in capture.text, f"canary reached the handler: {capture.text!r}"
    assert redact.WIRE_PREFIX in capture.text


def test_the_naive_logger_level_attachment_would_have_leaked(harness_root):
    """The control that makes the assertion above mean something."""
    harness_root.handlers[:] = []
    capture = _Capture()
    harness_root.addHandler(capture)
    harness_root.setLevel(logging.DEBUG)
    harness_root.propagate = False
    vault = _vault_with_canary()

    naive = redact.SecretScrubFilter(vault)
    harness_root.addFilter(naive)               # the WRONG place, deliberately
    try:
        _child_logger().debug("loaded attribute %s from state", CANARY)
    finally:
        harness_root.removeFilter(naive)

    assert CANARY in capture.text, (
        "if this ever stops leaking, the handler-level assertion above has "
        "stopped proving anything")


def test_install_adds_a_noop_handler_when_the_logger_has_none(harness_root):
    harness_root.handlers[:] = []
    vault = _vault_with_canary()

    filt = redact.install_log_filter(vault)

    assert len(harness_root.handlers) == 1
    owned = harness_root.handlers[0]
    assert isinstance(owned, redact._NullHandler)
    assert owned.level == logging.NOTSET
    assert filt in owned.filters, (
        "the boundary must exist before setup_logging runs")


def test_the_filter_survives_setup_logging_via_ensure(harness_root):
    """THE ORDERING CASE. setup_logging is idempotent-but-RECONFIGURING: it
    removes and re-adds its own handlers, and the new ones carry no filter."""
    harness_root.handlers[:] = []
    vault = _vault_with_canary()
    filt = redact.install_log_filter(vault)

    core_log.setup_logging()                    # AFTER the install

    reconfigured = [h for h in harness_root.handlers
                    if getattr(h, "_harness_owned", False)]
    assert reconfigured, "setup_logging added no handler of its own"
    assert all(filt not in h.filters for h in reconfigured), (
        "this is the gap ensure_log_filter exists to close; if setup_logging "
        "ever starts preserving filters, this test should be revisited")

    capture = _Capture()
    harness_root.addHandler(capture)
    harness_root.setLevel(logging.DEBUG)
    harness_root.propagate = False

    same = redact.ensure_log_filter(vault)

    assert same is filt, "ensure must re-attach the SAME filter, not a second one"
    assert all(filt in h.filters for h in harness_root.handlers), (
        "every handler, including the ones setup_logging just built")

    _child_logger().debug("still holding %s", CANARY)

    assert capture.messages
    assert CANARY not in capture.text


def test_the_filter_works_with_setup_logging_having_run_first(harness_root):
    harness_root.handlers[:] = []
    core_log.setup_logging()
    capture = _Capture()
    harness_root.addHandler(capture)
    harness_root.setLevel(logging.DEBUG)
    harness_root.propagate = False
    vault = _vault_with_canary()

    filt = redact.install_log_filter(vault)

    assert all(filt in h.filters for h in harness_root.handlers)
    _child_logger().debug("value=%s", CANARY)
    assert capture.messages
    assert CANARY not in capture.text


def test_the_filter_also_scrubs_a_non_string_argument(harness_root):
    harness_root.handlers[:] = []
    capture = _Capture()
    harness_root.addHandler(capture)
    harness_root.setLevel(logging.DEBUG)
    harness_root.propagate = False
    vault = _vault_with_canary()
    redact.install_log_filter(vault)

    _child_logger().debug("record=%s", {"private_key": CANARY})

    assert capture.messages
    assert CANARY not in capture.text
    assert CANARY not in "".join(str(a) for r in capture.records
                                 for a in (r.args if isinstance(r.args, tuple)
                                           else (r.args,)))


def test_ensure_is_idempotent_and_the_no_change_path_adds_nothing(harness_root):
    harness_root.handlers[:] = []
    capture = _Capture()
    harness_root.addHandler(capture)
    vault = _vault_with_canary()

    filt = redact.install_log_filter(vault)
    before = list(capture.filters)
    for _ in range(3):
        assert redact.ensure_log_filter(vault) is filt
    assert capture.filters == before
    assert capture.filters.count(filt) == 1


def test_remove_log_filter_restores_the_exact_handler_list(harness_root):
    harness_root.handlers[:] = []
    capture = _Capture()
    harness_root.addHandler(capture)
    before = list(harness_root.handlers)
    vault = _vault_with_canary()

    redact.install_log_filter(vault)
    redact.remove_log_filter()

    assert harness_root.handlers == before
    assert capture.filters == [], "the filter must come off the handler too"

    # …including the no-op handler install added when there was none.
    harness_root.handlers[:] = []
    redact.install_log_filter(vault)
    assert len(harness_root.handlers) == 1
    redact.remove_log_filter()
    assert harness_root.handlers == []


def test_an_empty_vault_leaves_a_record_untouched(harness_root):
    harness_root.handlers[:] = []
    capture = _Capture()
    harness_root.addHandler(capture)
    harness_root.setLevel(logging.DEBUG)
    harness_root.propagate = False
    redact.install_log_filter(redact.SecretVault())

    message = "nothing sensitive here at all"
    _child_logger().debug(message)

    assert capture.messages == [message]
    assert capture.records[0].msg is message, "the no-op path must not allocate"
