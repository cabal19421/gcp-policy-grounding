"""Acceptance for ``gcp_grounding.tfsource.state``, THE terraform.tfstate v4
reader.

Driven from the committed ``tests/fixtures/gcp/tf/estate.tfstate``, which was
authored to carry every v4 shape this reader has to survive: a data-mode entry,
a deposed instance sitting in front of the live one at the same address, both
module-qualified address forms, both index-key types, a ``google-beta``
provider, and the three grep-able secret sentinels.

The load-bearing tests here are the ones that pin a SILENT failure:

- the provider hazard, asserted as a RELATIONSHIP — the naive
  ``rsplit("/", 1)[-1]`` over the real spelling is asserted to produce
  ``google"]`` in the same test that asserts the reader produces ``google``, so
  neither half can drift;
- the deposed hazard, where the failure mode is not a crash but the LIVE object
  vanishing behind a stale one, so the live instance's own attribute value is
  asserted rather than just its address;
- and every refusal, because a v4 reader that yields zero resources looks
  exactly like a clean empty estate.

Degenerate and hostile documents are built in ``tmp_path`` per the suite
convention; the positive corpus is the committed fixture. ``terraform`` is not
installed on this machine and nothing here needs it.
"""

import json
import logging
import re
from pathlib import Path

import pytest

from gcp_grounding import redact as redaction
from gcp_grounding.tfsource import discover, state

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
STATE_PATH = FIXTURES / "tf" / "estate.tfstate"
STATE_DOC = json.loads(STATE_PATH.read_text(encoding="utf-8"))

#: The three grep-able sentinels the fixture plants. None of them may appear in
#: an object, a note or a log line.
SENTINELS = ("FIXTURE-SECRET-DO-NOT-LEAK", "FIXTURE-SECRET-BY-NAME",
             "FIXTURE-PLAN-SECRET")

#: The KMS key NAME the redactor must leave alone: it is an identity key, and
#: redacting it turns every fact carrying it into a sole-source fact.
KMS_KEY_NAME = ("projects/acme-prod/locations/us-central1/keyRings/tf-state/"
                "cryptoKeys/service-account-keys")

#: The real v4 provider spelling, and the shape a naive split destroys.
BRACKETED = 'provider["registry.terraform.io/hashicorp/google"]'

#: A deterministic stamp, so a test that is not about the capture time does not
#: depend on a checkout's mtimes.
STAMP = "2026-01-05T00:00:00Z"


@pytest.fixture(scope="module")
def read():
    """The committed fixture, read once with a pinned capture time."""
    return state.read_state(STATE_PATH, captured_at=STAMP)


def _write(path: Path, document) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path


def _rendered(obj) -> str:
    """Every attribute value of one object as text, for a leak assertion.
    ``default=repr`` is what renders a ``Redacted``, whose repr is a digest."""
    return json.dumps(obj.values, default=repr, sort_keys=True)


def _v4(**overrides):
    document = {
        "version": 4,
        "terraform_version": "1.9.5",
        "serial": 3,
        "lineage": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
        "resources": [],
    }
    document.update(overrides)
    return document


def _entry(**overrides):
    entry = {
        "mode": "managed",
        "type": "google_compute_firewall",
        "name": "allow-ssh",
        "provider": BRACKETED,
        "instances": [{"schema_version": 1, "attributes": {"name": "allow-ssh"},
                       "sensitive_attributes": []}],
    }
    entry.update(overrides)
    return entry


# -- HAZARD 1: the provider string --------------------------------------------


def test_the_bracketed_spelling_parses_and_the_naive_split_is_pinned_beside_it():
    # THE HAZARD, as a relationship: the naive rsplit yields a token that
    # matches no allowlist, so every google resource would silently disappear
    # and the capture would report a clean empty estate. Both halves are
    # asserted here so neither can drift away from the other.
    assert BRACKETED.rsplit("/", 1)[-1] == 'google"]'

    ref = state.parse_provider(BRACKETED)
    assert ref.ok
    assert ref.source == "registry.terraform.io/hashicorp/google"
    assert ref.name == "google"
    assert ref.alias == ""
    assert ref.spelling == "google"
    assert not ref.inferred


def test_the_bracketed_spelling_with_an_alias_keeps_both_halves():
    ref = state.parse_provider(BRACKETED + ".eu")
    assert (ref.name, ref.alias, ref.spelling) == ("google", "eu", "google.eu")
    assert ref.source == "registry.terraform.io/hashicorp/google"


@pytest.mark.parametrize("raw, name", [
    ("google", "google"),
    ("provider.google", "google"),
    ("registry.terraform.io/hashicorp/google", "google"),
    ("registry.terraform.io/hashicorp/google-beta", "google-beta"),
])
def test_the_bare_unwrapped_spellings_parse(raw, name):
    # A dotted SOURCE ADDRESS must not be read as a name plus an alias, which
    # is why the alias group admits neither a dot nor a slash.
    ref = state.parse_provider(raw)
    assert (ref.ok, ref.name, ref.alias) == (True, name, "")


def test_an_entry_with_no_provider_information_falls_back_to_the_type_prefix():
    ref = state.parse_provider(None, resource_type="google_compute_firewall")
    assert (ref.ok, ref.name) == (True, "google")
    assert ref.inferred is True
    # The inference is recorded as an inference: google and google-beta write
    # the same `google_` types.
    assert "INFERRED" in ref.note and "google-beta" in ref.note


def test_a_non_google_type_with_no_provider_is_refused_rather_than_guessed():
    ref = state.parse_provider("", resource_type="aws_s3_bucket")
    assert not ref.ok
    assert ref.note


def test_a_malformed_provider_string_is_refused_with_a_note():
    ref = state.parse_provider('provider[registry.terraform.io/hashicorp/google')
    assert not ref.ok
    assert ref.name == ""
    assert ref.note and "decodes" in ref.note


def test_a_malformed_provider_resource_is_refused_loudly_not_dropped_silently(tmp_path):
    document = _v4(resources=[
        _entry(name="good"),
        _entry(name="mystery", provider='provider[registry.terraform.io/x/google'),
    ])
    read = state.read_state(_write(tmp_path / "terraform.tfstate", document))

    assert read.ok
    assert read.addresses == ("google_compute_firewall.good",)
    refusal = [note for note in read.notes
               if "google_compute_firewall.mystery" in note]
    assert len(refusal) == 1
    assert "REFUSED" in refusal[0]


def test_the_fixture_providers_reach_the_objects_including_google_beta(read):
    by_address = read.by_address()
    assert by_address["google_compute_firewall.allow-internal"].provider == "google"
    perimeter = by_address[
        "google_access_context_manager_service_perimeter.prod"]
    assert perimeter.provider == "google-beta"


# -- HAZARD 2: the missing address --------------------------------------------


def test_the_fixture_stores_no_address_key_anywhere():
    # The premise of the hazard: v4 has no `address`, so the reader composes it.
    for entry in STATE_DOC["resources"]:
        assert "address" not in entry
        for instance in entry["instances"]:
            assert "address" not in instance


def test_both_module_qualified_forms_and_both_index_types_are_pinned(read):
    addresses = read.addresses
    # A module-qualified resource with no index, and one with a STRING index.
    assert "module.net.google_compute_firewall.allow-health-checks" in addresses
    assert 'module.net.google_compute_firewall.allow-iap-ssh["prod"]' in addresses
    # An INTEGER index at the root, and an unindexed root resource.
    assert "google_compute_firewall.deny-ssh-external[0]" in addresses
    assert "google_service_account.etl-runner" in addresses


def test_compose_address_json_escapes_a_string_index_and_leaves_an_int_bare():
    assert state.compose_address("google_compute_firewall", "web") == \
        "google_compute_firewall.web"
    assert state.compose_address("t", "n", module="module.a", index_key=0) == \
        "module.a.t.n[0]"
    assert state.compose_address("t", "n", index_key='say "hi"') == \
        't.n["say \\"hi\\""]'
    # A bool is an int subclass in Python and terraform never writes one, so it
    # must not render as `[True]`.
    assert state.compose_address("t", "n", index_key=True) == 't.n["True"]'


# -- HAZARD 3: deposed --------------------------------------------------------


def test_the_deposed_instance_is_skipped_and_counted(read):
    assert read.deposed == 1
    note = [n for n in read.notes if "DEPOSED" in n]
    assert len(note) == 1
    assert "google_compute_firewall.allow-internal" in note[0]


def test_the_live_instance_behind_the_deposed_one_is_still_present(read):
    # THE FAILURE MODE this pins is not a crash: it is the live object
    # disappearing behind the stale generation in front of it. The fixture's
    # deposed instance carries 10.0.0.0/16 and the live one 10.0.0.0/8, so the
    # ranges — not just the address — are what prove which one survived.
    live = [obj for obj in read.objects
            if obj.address == "google_compute_firewall.allow-internal"]
    assert len(live) == 1
    assert live[0].values["source_ranges"] == ["10.0.0.0/8"]
    assert live[0].values["priority"] == 1000


# -- HAZARD 4: data mode ------------------------------------------------------


def test_the_data_mode_entry_is_skipped_and_counted(read):
    assert read.data_sources == 1
    assert not [obj for obj in read.objects if obj.type == "google_project"]
    assert not [address for address in read.addresses
                if address.startswith("data.")]
    note = [n for n in read.notes if "data-mode" in n and "SKIPPED" in n]
    assert len(note) == 1
    assert "data.google_project.this" in note[0]
    assert "NOT terraform-managed" in note[0]


# -- HAZARD 5: the backend stub, and the other refusals -----------------------


def test_a_backend_stub_yields_the_shared_remote_backend_message(tmp_path):
    stub = {
        "version": 3,
        "serial": 1,
        "lineage": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
        "backend": {"type": "gcs",
                    "config": {"bucket": "acme-tfstate", "prefix": "prod"}},
    }
    path = _write(tmp_path / ".terraform" / "terraform.tfstate", stub)
    read = state.read_state(path)

    assert read.ok is False
    assert read.objects == ()
    # THE SAME STRING the discoverer uses: two entry points must not say
    # different things about the same file.
    assert discover.REMOTE_BACKEND_STUB.format(path=str(path)) in read.notes
    assert "pull" in discover.REMOTE_BACKEND_STUB


def test_a_v3_state_file_is_refused_loudly_rather_than_read_as_empty(tmp_path):
    v3 = {
        "version": 3,
        "terraform_version": "0.11.14",
        "serial": 7,
        "lineage": "9a8b7c6d-5e4f-3021-1234-abcdefabcdef",
        "modules": [{"path": ["root"], "outputs": {},
                     "resources": {"google_compute_network.vpc": {}},
                     "depends_on": []}],
    }
    read = state.read_state(_write(tmp_path / "old.tfstate", v3))

    assert read.ok is False
    assert read.objects == ()
    refusal = " ".join(read.notes)
    assert "version 3" in refusal
    assert "REFUSED" in refusal
    assert "indistinguishable from a clean empty estate" in refusal
    # The header it could read is still reported, so a caller can say WHICH
    # file it was.
    assert read.version == 3
    assert read.lineage == "9a8b7c6d-5e4f-3021-1234-abcdefabcdef"


def test_an_empty_resources_list_is_a_legal_read_that_covers_nothing(tmp_path):
    read = state.read_state(_write(tmp_path / "empty.tfstate", _v4()))

    assert read.ok is True
    assert read.objects == ()
    assert any("EMPTY 'resources'" in note and "NOTHING" in note
               for note in read.notes)


def test_a_document_whose_entries_all_vanish_says_so_rather_than_passing_quietly(tmp_path):
    document = _v4(resources=[_entry(mode="data", type="google_project",
                                     name="this")])
    read = state.read_state(_write(tmp_path / "data-only.tfstate", document))

    assert read.ok is True
    assert read.objects == ()
    assert any("ZERO objects" in note for note in read.notes)


def test_a_flatmap_instance_is_skipped_with_a_note_not_half_parsed(tmp_path):
    document = _v4(resources=[_entry(instances=[{
        "schema_version": 0,
        "attributes_flat": {"name": "allow-ssh", "allow.#": "1",
                            "allow.0.ports.#": "1", "allow.0.ports.0": "22"},
    }])])
    read = state.read_state(_write(tmp_path / "flat.tfstate", document))

    assert read.ok is True
    assert read.objects == ()
    assert any("attributes_flat" in note and "SKIPPED" in note
               for note in read.notes)


def test_every_refusal_carries_a_note_and_no_objects(tmp_path):
    missing = state.read_state(tmp_path / "absent.tfstate")
    not_json = state.read_state(_broken(tmp_path))
    not_object = state.read_state_document([1, 2, 3])

    for read in (missing, not_json, not_object):
        assert read.ok is False
        assert read.objects == ()
        assert read.notes and all(read.notes)


def _broken(tmp_path: Path) -> Path:
    path = tmp_path / "broken.tfstate"
    path.write_text("{not json at all", encoding="utf-8")
    return path


def test_a_refused_state_read_cannot_be_constructed_with_objects(read):
    with pytest.raises(ValueError):
        state.StateRead(ok=False, objects=read.objects, notes=("why",))
    with pytest.raises(ValueError):
        state.StateRead(ok=False)


# -- redaction ----------------------------------------------------------------


def test_no_sentinel_reaches_any_object_or_any_note(read):
    for obj in read.objects:
        rendered = _rendered(obj)
        for sentinel in SENTINELS:
            assert sentinel not in rendered, obj.address
    for note in read.notes:
        for sentinel in SENTINELS:
            assert sentinel not in note


def test_the_declared_and_the_name_caught_secrets_are_both_withheld(read):
    account = read.by_address()["google_service_account.etl-runner"]
    # Route 1: the instance's own cty path.
    assert isinstance(account.values["private_key"], redaction.Redacted)
    # Route 3: `sensitive_attributes` never named it — a tfstate stores it in
    # plaintext and the flag is a display marker.
    assert isinstance(account.values["password"], redaction.Redacted)
    assert account.values["private_key"] != account.values["password"]
    assert account.sensitive_paths == ("private_key",)


def test_the_kms_key_name_survives_verbatim(read):
    account = read.by_address()["google_service_account.etl-runner"]
    # An identity key: redacting it would make every fact carrying it a
    # sole-source fact and switch drift detection off for the category.
    assert account.values["kms_key_name"] == KMS_KEY_NAME
    assert account.values["email"] == "etl-runner@acme-prod.iam.gserviceaccount.com"


def test_the_sentinel_never_reaches_the_log_at_debug(harness_log):
    state.read_state(STATE_PATH, captured_at=STAMP)
    text = harness_log()
    assert text  # the reader did log at DEBUG, so the assertion is not vacuous
    for sentinel in SENTINELS:
        assert sentinel not in text


def test_a_sensitive_output_is_noted_by_name_only_and_fed_to_the_vault(read):
    note = [n for n in read.notes if "output" in n]
    assert len(note) == 1
    assert "etl_runner_private_key" in note[0]
    assert "PLAINTEXT" in note[0]

    vault = redaction.SecretVault()
    state.read_state(STATE_PATH, captured_at=STAMP, vault=vault)
    assert "FIXTURE-SECRET-DO-NOT-LEAK" in vault
    assert vault.scrub_text("value=FIXTURE-SECRET-BY-NAME") != \
        "value=FIXTURE-SECRET-BY-NAME"


# -- the capture time ---------------------------------------------------------


def test_the_capture_time_is_the_file_mtime_and_says_so():
    read = state.read_state(STATE_PATH)
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", read.captured_at)
    assert read.captured_at == state.mtime_utc(STATE_PATH.stat().st_mtime)
    note = [n for n in read.notes if "modification time" in n]
    assert len(note) == 1
    assert "terraform state pull" in note[0]


def test_an_explicit_capture_time_wins_and_drops_the_mtime_note(read):
    assert read.captured_at == STAMP
    assert not [n for n in read.notes if "modification time" in n]


# -- the header, and the shape of a successful read ---------------------------


def test_the_state_read_carries_the_header_the_ledger_and_freshness_consume(read):
    assert read.ok is True
    assert read.version == 4
    assert read.terraform_version == "1.9.5"
    assert read.serial == 137
    assert read.lineage == "5b9a1f42-3c7d-4e18-9a06-2d81ff4c6b30"
    assert read.path == str(STATE_PATH)


def test_every_object_is_current_state_at_the_tfstate_source(read):
    assert read.objects
    for obj in read.objects:
        assert obj.source == state.SOURCE == "tfstate"
        assert obj.side == "current"
        assert obj.artifact == str(STATE_PATH)


def test_the_fixture_yields_every_managed_instance_and_nothing_else(read):
    # 20 entries, minus the one data source, minus the deposed instance.
    assert len(STATE_DOC["resources"]) == 20
    assert len(read.objects) == 19
    assert len(set(read.addresses)) == 19


def test_a_successful_read_still_says_terraform_can_never_be_complete(read):
    assert any("no category may be resolved absent" in note
               for note in read.notes)


def test_two_reads_of_the_same_file_agree(read):
    again = state.read_state(STATE_PATH, captured_at=STAMP)
    assert again.addresses == read.addresses
    assert again.notes == read.notes


# -- the DEBUG log capture ----------------------------------------------------


@pytest.fixture
def harness_log():
    """Capture every ``harness.*`` record at DEBUG AT THE HANDLER, and restore
    the logger exactly.

    Attaching to the handler rather than relying on propagation is deliberate:
    ``core.log.setup_logging`` sets ``propagate = False`` on the ``harness``
    logger, so a caplog-based test would capture nothing at all the moment any
    other test in the session configures logging — and a capture that captures
    nothing asserts nothing.
    """
    logger = logging.getLogger("harness")
    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Capture(level=logging.DEBUG)
    previous_level, previous_propagate = logger.level, logger.propagate
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    try:
        yield lambda: "\n".join(record.getMessage() for record in records)
    finally:
        logger.removeHandler(handler)
        logger.setLevel(previous_level)
        logger.propagate = previous_propagate
