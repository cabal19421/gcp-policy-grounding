"""The provider-schema loader and its per-run configuration, pinned.

:mod:`gcp_grounding.provider_schema` is the consumption-only half of the
capability: the operator captures ``terraform providers schema -json``
themselves (the gate never runs terraform) and this module loads it. Pinned
here:

* the TWO ACCEPTED SHAPES and the asymmetric strictness — the raw terraform
  output is read tolerantly (it is terraform's format to evolve) while the
  ``gcp-provider-schema/1`` wrapper's OWN keys are parsed strictly, an
  unrecognized key refused by name exactly as the config file's loader
  refuses one;
* VERSION HONESTY — a raw capture records no version and renders none; only a
  wrapper that truly recorded ``provider_versions`` ever puts a version in a
  message;
* the FRESHNESS STAMP — the wrapper's ``captured_at`` when recorded, else the
  file's own modification time, each labelled as what it is; and the
  staleness sentence that demotes a stale schema's findings, carrying the
  recapture command;
* the RUNTIME resolution — an activated runtime (the CLI's four-layer answer)
  wins; otherwise the ambient environment-over-config layers answer, and a
  broken config resolves to the environment alone rather than raising.
"""

import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from gcp_grounding import discovery, provider_schema

RAW = {
    "format_version": "1.0",
    "provider_schemas": {
        "registry.terraform.io/hashicorp/google": {
            "resource_schemas": {
                "google_compute_firewall": {
                    "version": 1,
                    "block": {
                        "attributes": {
                            "name": {"type": "string", "required": True},
                            "source_ranges": {"type": ["set", "string"],
                                              "optional": True},
                        },
                        "block_types": {
                            "allow": {"nesting_mode": "set", "block": {
                                "attributes": {
                                    "protocol": {"type": "string",
                                                 "required": True}}}},
                        },
                    },
                },
            },
        },
    },
}

STAMP = "2026-08-01T00:00:00+00:00"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    """No test inherits an exported grounding configuration, a cached schema
    or an activated runtime — and none leaks one."""
    for name in list(os.environ):
        if name.startswith("GCP_GROUNDING"):
            monkeypatch.delenv(name, raising=False)
    provider_schema.reset_cache()
    yield
    provider_schema.reset_cache()


def write(tmp_path, data, name="provider-schema.json"):
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def wrapper(**overrides):
    document = {"schema": provider_schema.WRAPPER_SCHEMA,
                "captured_at": STAMP, "raw": RAW}
    document.update(overrides)
    return document


# -- the raw shape --------------------------------------------------------------


def test_the_raw_terraform_output_is_accepted_as_is(tmp_path):
    schema, problems = provider_schema.load(write(tmp_path, RAW))
    assert problems == ()
    assert schema.resource_types() == ("google_compute_firewall",)
    assert schema.providers == ("registry.terraform.io/hashicorp/google",)
    blocks = schema.blocks_for("google_compute_firewall")
    assert set(blocks) == {"registry.terraform.io/hashicorp/google"}
    assert "source_ranges" in blocks[
        "registry.terraform.io/hashicorp/google"]["attributes"]


def test_a_raw_capture_records_no_version_and_renders_none(tmp_path):
    """The raw output carries no provider version, so NOTHING may render one:
    the honesty rule is that a version appears only where one was truly
    recorded."""
    schema, _problems = provider_schema.load(write(tmp_path, RAW))
    assert schema.provider_versions == {}
    assert schema.version_label() == ""


def test_a_raw_capture_freshness_keys_on_the_file_mtime(tmp_path):
    path = write(tmp_path, RAW)
    schema, _problems = provider_schema.load(path)
    assert schema.captured_at == ""
    assert schema.stamp_source == "file mtime"
    expected = datetime.fromtimestamp(os.path.getmtime(path), tz=timezone.utc)
    assert schema.stamp == expected


def test_a_bare_block_without_the_version_envelope_is_tolerated(tmp_path):
    """The raw side is terraform's format to evolve: a resource entry that IS
    the block (attributes at top level) still loads."""
    raw = {"provider_schemas": {"p": {"resource_schemas": {
        "google_thing": {"attributes": {"name": {"type": "string"}}}}}}}
    schema, problems = provider_schema.load(write(tmp_path, raw))
    assert problems == ()
    assert "name" in schema.blocks_for("google_thing")["p"]["attributes"]


# -- the wrapper, strictly -------------------------------------------------------


def test_the_wrapper_records_captured_at_and_versions(tmp_path):
    versions = {"registry.terraform.io/hashicorp/google": "6.8.0"}
    schema, problems = provider_schema.load(
        write(tmp_path, wrapper(provider_versions=versions)))
    assert problems == ()
    assert schema.captured_at == STAMP
    assert schema.stamp_source == "captured_at"
    assert schema.version_label() == "google 6.8.0"


def test_an_unrecognized_wrapper_key_is_refused_by_name(tmp_path):
    schema, problems = provider_schema.load(
        write(tmp_path, wrapper(cpatured_at="oops")))
    assert schema is None
    assert len(problems) == 1
    assert "cpatured_at" in problems[0]
    assert "typo must not silently disarm" in problems[0]


def test_a_naive_captured_at_is_refused_rather_than_assumed(tmp_path):
    schema, problems = provider_schema.load(
        write(tmp_path, wrapper(captured_at="2026-08-01T00:00:00")))
    assert schema is None
    assert any("AWARE ISO-8601" in problem for problem in problems)


def test_a_wrapper_without_the_raw_payload_is_refused(tmp_path):
    document = wrapper()
    del document["raw"]
    schema, problems = provider_schema.load(write(tmp_path, document))
    assert schema is None
    assert any("'raw' must hold the unmodified" in p for p in problems)


def test_malformed_provider_versions_are_refused(tmp_path):
    schema, problems = provider_schema.load(
        write(tmp_path, wrapper(provider_versions={"p": 6})))
    assert schema is None
    assert any("provider_versions" in problem for problem in problems)


def test_some_other_schema_string_is_refused_naming_both(tmp_path):
    schema, problems = provider_schema.load(
        write(tmp_path, {"schema": "not-this/9", "raw": RAW}))
    assert schema is None
    assert "not-this/9" in problems[0]
    assert provider_schema.WRAPPER_SCHEMA in problems[0]


# -- neither shape, and other refusals -------------------------------------------


def test_a_document_that_is_neither_shape_names_the_capture_command(tmp_path):
    schema, problems = provider_schema.load(write(tmp_path, {"resources": []}))
    assert schema is None
    assert provider_schema.CAPTURE_COMMAND in problems[0]


def test_a_schema_with_no_resource_types_at_all_is_refused(tmp_path):
    raw = {"provider_schemas": {"p": {"resource_schemas": {}}}}
    schema, problems = provider_schema.load(write(tmp_path, raw))
    assert schema is None
    assert any("no resource type at all" in problem for problem in problems)


def test_unreadable_and_unparseable_files_are_problems_not_raises(tmp_path):
    schema, problems = provider_schema.load(str(tmp_path / "absent.json"))
    assert schema is None and "could not be read" in problems[0]
    bad = tmp_path / "bad.json"
    bad.write_text("{", encoding="utf-8")
    schema, problems = provider_schema.load(str(bad))
    assert schema is None and "could not be read" in problems[0]


def test_the_cache_is_keyed_on_the_file_identity(tmp_path):
    path = write(tmp_path, RAW)
    first, _ = provider_schema.load_cached(path)
    again, _ = provider_schema.load_cached(path)
    assert again is first, "an unchanged file must not be re-parsed"
    grown = {**RAW, "format_version": "1.1"}
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(grown, handle, indent=2)     # different size → new signature
    reloaded, _ = provider_schema.load_cached(path)
    assert reloaded is not first, "an edited file must re-load"


# -- the runtime -----------------------------------------------------------------


def test_an_activated_runtime_wins_and_restores(tmp_path):
    installed = provider_schema.Runtime(paths=("/x.json",), policy="annotate")
    previous = provider_schema.activate(installed)
    try:
        assert provider_schema.runtime_for("anything") is installed
    finally:
        provider_schema.activate(previous)
    assert provider_schema.active() is previous


def test_the_ambient_environment_layer_answers_when_nothing_is_active(
        monkeypatch, tmp_path):
    monkeypatch.setenv(provider_schema.PROVIDER_SCHEMA_ENV,
                       os.pathsep.join(["/env/a.json", "/env/b.json"]))
    monkeypatch.setenv(provider_schema.SCHEMA_POLICY_ENV, "annotate")
    runtime = provider_schema.runtime_for(str(tmp_path / "main.tf.json"))
    assert runtime.paths == ("/env/a.json", "/env/b.json")
    assert runtime.policy == "annotate"


def test_the_config_layer_answers_beneath_the_environment(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    schema_path = write(repo, RAW)
    (repo / discovery.CONFIG_NAMES[0]).write_text(json.dumps({
        "schema": discovery.CONFIG_SCHEMA,
        "provider_schema": "provider-schema.json",
        "schema_policy": "annotate",
    }), encoding="utf-8")
    runtime = provider_schema.runtime_for(str(repo / "main.tf.json"))
    assert runtime.paths == (schema_path,)
    assert runtime.policy == "annotate"


def test_nothing_configured_resolves_to_an_unconfigured_runtime(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    runtime = provider_schema.runtime_for(str(repo / "main.tf.json"))
    assert not runtime.configured
    assert runtime.effective_policy == provider_schema.DEFAULT_SCHEMA_POLICY


def test_the_default_policy_is_block():
    """The design decision, pinned: terraform plan would hard-fail the same
    attribute, so blocking at write time matches actuation reality."""
    assert provider_schema.DEFAULT_SCHEMA_POLICY == "block"
    assert provider_schema.SCHEMA_POLICIES == ("block", "annotate", "off")


# -- staleness -------------------------------------------------------------------


def _loaded(tmp_path, captured_at=STAMP):
    schema, problems = provider_schema.load(
        write(tmp_path, wrapper(captured_at=captured_at)))
    assert problems == ()
    return schema


def test_a_fresh_schema_is_not_stale(tmp_path):
    schema = _loaded(tmp_path)
    runtime = provider_schema.Runtime(now="2026-08-02T00:00:00+00:00")
    assert provider_schema.staleness(schema, runtime) == ""


def test_a_stale_schema_names_age_provenance_and_the_recapture(tmp_path):
    schema = _loaded(tmp_path)
    runtime = provider_schema.Runtime(now="2026-09-01T00:00:00+00:00")
    reason = provider_schema.staleness(schema, runtime)
    assert "31 days old" in reason
    assert "captured_at" in reason
    assert "7 days ceiling" in reason
    assert provider_schema.CAPTURE_COMMAND in reason


def test_max_age_off_disables_the_ceiling(tmp_path):
    schema = _loaded(tmp_path)
    runtime = provider_schema.Runtime(now="2027-01-01T00:00:00+00:00",
                                      max_age="off")
    assert provider_schema.staleness(schema, runtime) == ""


def test_a_configured_ceiling_is_honoured(tmp_path):
    schema = _loaded(tmp_path)
    runtime = provider_schema.Runtime(now="2026-08-03T00:00:00+00:00",
                                      max_age="1d")
    assert "1 day ceiling" in provider_schema.staleness(schema, runtime)


def test_a_schema_with_no_stamp_is_not_called_stale(tmp_path):
    schema = _loaded(tmp_path)
    stripped = provider_schema.ProviderSchema(
        path=schema.path, resources=schema.resources, stamp=None)
    runtime = provider_schema.Runtime(now="2030-01-01T00:00:00+00:00")
    assert provider_schema.staleness(stripped, runtime) == ""


def test_mtime_freshness_uses_the_ambient_clock(tmp_path):
    """A raw capture written NOW is fresh now — the default demo path — and
    stale under a pinned far-future clock."""
    schema, _problems = provider_schema.load(write(tmp_path, RAW))
    assert provider_schema.staleness(schema, provider_schema.Runtime()) == ""
    future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
    reason = provider_schema.staleness(
        schema, provider_schema.Runtime(now=future))
    assert "file mtime" in reason


# -- the settings plumbing (the three layers end to end) -------------------------


def test_config_paths_resolve_against_the_config_directory(tmp_path):
    config, problems = discovery.parse_config(
        {"schema": discovery.CONFIG_SCHEMA,
         "provider_schema": ["estate/google.json", "estate/google-beta.json"],
         "schema_policy": "block"},
        path=str(tmp_path / discovery.CONFIG_NAMES[0]))
    assert problems == ()
    assert config.get("provider_schema") == (
        str(tmp_path / "estate" / "google.json"),
        str(tmp_path / "estate" / "google-beta.json"))
    assert config.get("schema_policy") == "block"


def test_a_bad_config_schema_policy_is_refused_by_name(tmp_path):
    config, problems = discovery.parse_config(
        {"schema": discovery.CONFIG_SCHEMA, "schema_policy": "blockk"},
        path=str(tmp_path / discovery.CONFIG_NAMES[0]))
    assert config is None
    assert any("'schema_policy' 'blockk'" in problem for problem in problems)


def test_settings_resolution_layers_the_new_fields(monkeypatch, tmp_path):
    monkeypatch.setenv(provider_schema.SCHEMA_POLICY_ENV, "off")
    settings = discovery.resolve_settings(
        cli={"provider_schema": ("/cli/schema.json",)}, env=None, config=None,
        auto=None)
    assert settings.options.provider_schema == ("/cli/schema.json",)
    assert settings.origins["provider_schema"] == "cli"
    assert settings.options.schema_policy == "off"
    assert settings.origins["schema_policy"] == "env"
    runtime = provider_schema.runtime_from_settings(settings)
    assert runtime.paths == ("/cli/schema.json",)
    assert runtime.policy == "off"
