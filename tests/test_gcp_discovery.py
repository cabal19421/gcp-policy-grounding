"""Acceptance for :mod:`gcp_grounding.discovery` — the config file, the walk,
and where every setting came from.

Temporary directory trees only: nothing here reads a committed fixture, because
what is under test is a SEARCH over a directory layout and a committed layout
would pin the search to one repo's shape.

The two load-bearing tests are :func:`test_relative_paths_resolve_against_the_config_directory`
and :func:`test_auto_detection_refuses_the_backend_stub`. The first is the pin
that a config travels with the repo rather than with whatever working directory
a hook happened to inherit; the second is the pin that a ``.terraform`` backend
stub — which holds no ``resources`` array and is byte-indistinguishable from a
clean empty estate — is never read as one.
"""

from __future__ import annotations

import dataclasses
import json
import os

import pytest

from gcp_grounding import discovery, freshness
from gcp_grounding.sources import SourceOptions

CONFIG = discovery.CONFIG_NAMES[0]


@pytest.fixture(autouse=True)
def clean_environment(monkeypatch):
    """No ambient ``GCP_GROUNDING_*`` variable reaches a test. The env layer is
    a real precedence tier here, so a variable exported in the developer's shell
    would silently outrank the config file under test."""
    for name in list(os.environ):
        if name.startswith("GCP_GROUNDING_"):
            monkeypatch.delenv(name, raising=False)


def write(path, payload):
    """*payload* as JSON at *path*, creating the tree. Returns the path."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    return path


def config_document(**keys):
    """A minimal valid config document plus *keys*."""
    return {"schema": discovery.CONFIG_SCHEMA, **keys}


def repo(tmp_path, name="repo"):
    """A directory carrying a ``.git`` entry, so the walk stops there."""
    root = os.path.join(str(tmp_path), name)
    os.makedirs(os.path.join(root, ".git"), exist_ok=True)
    return root


def auto_state(root):
    """The auto-detected layer, as :func:`discovery.auto_detect` builds it."""
    return discovery.Auto(terraform_state=(os.path.join(root, "terraform.tfstate"),))


# -- the walk -----------------------------------------------------------------


def test_a_config_two_directories_above_the_proposal_is_found(tmp_path):
    root = repo(tmp_path)
    written = write(os.path.join(root, CONFIG),
                    config_document(snapshot="estate.json"))
    proposal = os.path.join(root, "envs", "prod", "iam.policy.json")
    os.makedirs(os.path.dirname(proposal), exist_ok=True)

    config, problems = discovery.discover(proposal, env={})

    assert problems == ()
    assert config is not None
    assert config.path == written
    assert config.directory == root
    assert config.get("primary") == os.path.join(root, "estate.json")


def test_the_git_boundary_stops_the_walk_before_a_config_outside_the_repo(tmp_path):
    outer = str(tmp_path)
    write(os.path.join(outer, CONFIG), config_document(snapshot="outside.json"))
    root = repo(tmp_path)
    proposal = os.path.join(root, "iam.policy.json")
    os.makedirs(root, exist_ok=True)

    config, problems = discovery.discover(proposal, env={})

    # The config one directory above the checkout describes some other repo's
    # estate, so it is never picked up.
    assert (config, problems) == (None, ())

    # AFTER, not before: a config committed at the repo root — the directory
    # that carries the .git entry — is still found.
    inside = write(os.path.join(root, CONFIG), config_document())
    found, problems = discovery.discover(proposal, env={})
    assert problems == ()
    assert found is not None and found.path == inside


def test_the_walk_never_raises_on_a_path_that_does_not_exist(tmp_path):
    missing = os.path.join(str(tmp_path), "no", "such", "tree", "iam.json")
    assert discovery.discover(missing, env={}) == (None, ())
    assert discovery.auto_detect(missing) == (None, ())


def test_the_environment_override_wins_over_the_walk(tmp_path, monkeypatch):
    root = repo(tmp_path)
    write(os.path.join(root, CONFIG), config_document(snapshot="walked.json"))
    elsewhere = os.path.join(str(tmp_path), "ci", CONFIG)
    write(elsewhere, config_document(snapshot="pinned.json"))
    proposal = os.path.join(root, "iam.policy.json")

    config, problems = discovery.discover(
        proposal, env={discovery.CONFIG_ENV: elsewhere})
    assert problems == ()
    assert config is not None and config.path == elsewhere
    assert config.get("primary") == os.path.join(os.path.dirname(elsewhere),
                                                 "pinned.json")

    # And the same through the real environment, which is what a CI job sets.
    monkeypatch.setenv(discovery.CONFIG_ENV, elsewhere)
    from_environ, problems = discovery.discover(proposal)
    assert problems == ()
    assert from_environ is not None and from_environ.path == elsewhere


# -- strict parsing -----------------------------------------------------------


def test_an_unknown_top_level_key_is_rejected_naming_it(tmp_path):
    root = repo(tmp_path)
    path = write(os.path.join(root, CONFIG),
                 config_document(snapshto="estate.json"))

    config, problems = discovery.discover(os.path.join(root, "iam.json"), env={})

    assert config is None
    assert len(problems) == 1
    assert "snapshto" in problems[0]
    assert path in problems[0]


def test_an_unknown_key_inside_terraform_is_rejected_naming_it(tmp_path):
    root = repo(tmp_path)
    write(os.path.join(root, CONFIG),
          config_document(terraform={"state": ["terraform.tfstate"],
                                     "statefile": ["other.tfstate"]}))

    config, problems = discovery.discover(os.path.join(root, "iam.json"), env={})

    assert config is None
    assert any("statefile" in problem and "terraform" in problem
               for problem in problems)


def test_a_wrong_schema_names_both_strings(tmp_path):
    root = repo(tmp_path)
    write(os.path.join(root, CONFIG), {"schema": "gcp-grounding-config/99"})

    config, problems = discovery.discover(os.path.join(root, "iam.json"), env={})

    assert config is None
    assert any(discovery.CONFIG_SCHEMA in p and "gcp-grounding-config/99" in p
               for p in problems)


def test_a_malformed_setting_is_named_and_no_partial_config_comes_back(tmp_path):
    root = repo(tmp_path)
    write(os.path.join(root, CONFIG),
          config_document(snapshot="estate.json", precedence="nonsense-wins",
                          max_age="7dd", drift="silence"))

    config, problems = discovery.discover(os.path.join(root, "iam.json"), env={})

    # A typo that quietly restored the default would change what the gate
    # enforces with nothing saying so, so each one is its own problem and the
    # valid 'snapshot' key does NOT come back on its own.
    assert config is None
    assert any("nonsense-wins" in p for p in problems)
    assert any("7dd" in p for p in problems)
    assert any("silence" in p for p in problems)


def test_unreadable_json_is_a_problem_and_never_an_exception(tmp_path):
    root = repo(tmp_path)
    path = os.path.join(root, CONFIG)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("{not json")

    config, problems = discovery.discover(os.path.join(root, "iam.json"), env={})

    assert config is None
    assert len(problems) == 1 and path in problems[0]


def test_relative_paths_resolve_against_the_config_directory(tmp_path,
                                                             monkeypatch):
    """THE PIN: the config travels with the repo, so its paths resolve against
    ITS directory and never against whatever working directory the hook was
    invoked in."""
    root = repo(tmp_path)
    write(os.path.join(root, CONFIG),
          config_document(snapshot="state/estate.json",
                          requirements="sec_requirements/prod.md",
                          terraform={"state": ["tf/terraform.tfstate"],
                                     "plan": ["tf/plan.json"],
                                     "config_dir": ["tf"]},
                          targets={"policies/iam.json":
                                   "iam_bindings:projects/acme-prod"}))
    elsewhere = os.path.join(str(tmp_path), "elsewhere")
    # The same relative shape exists under the OTHER working directory, so a
    # cwd-relative resolution would produce a real, existing, wrong path.
    os.makedirs(os.path.join(elsewhere, "state"), exist_ok=True)
    write(os.path.join(elsewhere, "state", "estate.json"), {})
    monkeypatch.chdir(elsewhere)

    config, problems = discovery.discover(os.path.join(root, "policies",
                                                       "iam.json"), env={})

    assert problems == ()
    assert config is not None
    assert config.get("primary") == os.path.join(root, "state", "estate.json")
    assert config.get("requirements") == os.path.join(root, "sec_requirements",
                                                      "prod.md")
    assert config.get("terraform_state") == (os.path.join(root, "tf",
                                                          "terraform.tfstate"),)
    assert config.get("terraform_plan") == (os.path.join(root, "tf", "plan.json"),)
    assert config.get("terraform_dir") == (os.path.join(root, "tf"),)
    assert set(config.get("targets")) == {os.path.join(root, "policies",
                                                       "iam.json")}
    # The anti-assertion, which is the whole point: the cwd-relative answer is a
    # real, existing file, so a cwd resolution would have looked like a success.
    assert os.path.isfile(os.path.join(elsewhere, "state", "estate.json"))
    assert config.get("primary") != os.path.join(elsewhere, "state", "estate.json")


def test_a_config_target_becomes_a_config_map_target_ref(tmp_path):
    root = repo(tmp_path)
    write(os.path.join(root, CONFIG),
          config_document(targets={"policies/iam.json":
                                   "iam_bindings:projects/acme-prod"}))

    config, problems = discovery.discover(os.path.join(root, "iam.json"), env={})

    assert problems == ()
    assert config is not None
    target = config.get("targets")[os.path.join(root, "policies", "iam.json")]
    assert (target.category, target.key, target.how) == (
        "iam_bindings", "projects/acme-prod", "config-map")


def test_a_malformed_target_yields_a_problem_and_no_target(tmp_path):
    root = repo(tmp_path)
    write(os.path.join(root, CONFIG),
          config_document(snapshot="estate.json",
                          targets={"policies/iam.json": "projects/acme-prod",
                                   "policies/fw.json": "not_a_domain:allow-ssh"}))

    config, problems = discovery.discover(os.path.join(root, "iam.json"), env={})

    # No domain is guessed from the key and no key is guessed from the path, so
    # the answer is a problem and NO target — a near-miss target silently
    # redefines what the widening check compares against.
    assert config is None
    settings = discovery.resolve_settings(cli=None, env={}, config=config,
                                          auto=None)
    assert settings.targets == {}
    assert any("policies/iam.json" in p for p in problems)
    assert any("not_a_domain" in p for p in problems)


# -- auto-detection -----------------------------------------------------------


def test_auto_detection_finds_a_sibling_state_file(tmp_path):
    root = repo(tmp_path)
    state = write(os.path.join(root, "terraform.tfstate"), {"version": 4})
    proposal = os.path.join(root, "modules", "net", "main.tf")
    os.makedirs(os.path.dirname(proposal), exist_ok=True)

    auto, problems = discovery.auto_detect(proposal)

    assert problems == ()
    assert auto is not None and auto.terraform_state == (state,)


def test_auto_detection_refuses_the_backend_stub(tmp_path):
    """A gcs/s3 backend's ``.terraform/terraform.tfstate`` records the BACKEND
    and carries no ``resources`` array, which reads exactly like a clean empty
    estate."""
    root = repo(tmp_path)
    stub = write(os.path.join(root, ".terraform", "terraform.tfstate"),
                 {"version": 3, "backend": {"type": "gcs"}})

    auto, problems = discovery.auto_detect(os.path.join(root, "main.tf"))

    assert auto is None
    assert problems == (discovery.remote_backend_problem(stub),)
    assert ".terraform" in problems[0]
    assert "terraform state pull" in problems[0]

    # A real sibling state alongside it is taken, and the stub still is not.
    real = write(os.path.join(root, "terraform.tfstate"), {"version": 4})
    auto, problems = discovery.auto_detect(os.path.join(root, "main.tf"))
    assert problems == ()
    assert auto is not None and auto.terraform_state == (real,)


def test_auto_detection_never_returns_a_directory_or_a_plan(tmp_path):
    root = repo(tmp_path)
    os.makedirs(os.path.join(root, "tf"), exist_ok=True)
    with open(os.path.join(root, "tf", "main.tf"), "w", encoding="utf-8") as fh:
        fh.write('resource "google_compute_firewall" "a" {}\n')
    write(os.path.join(root, "tf", "plan.json"), {"format_version": "1.2"})
    write(os.path.join(root, "tf", "tfplan.json"), {"format_version": "1.2"})
    proposal = os.path.join(root, "tf", "main.tf")

    # HCL and a plan alone are never enough: scanning a tree for HCL is exactly
    # where a wrong guess becomes an authoritative-looking baseline.
    assert discovery.auto_detect(proposal) == (None, ())

    state = write(os.path.join(root, "tf", "terraform.tfstate"), {"version": 4})
    auto, problems = discovery.auto_detect(proposal)
    assert problems == ()
    assert auto is not None and auto.terraform_state == (state,)

    settings = discovery.resolve_settings(cli=None, env={}, config=None, auto=auto)
    assert settings.options.terraform_state == (state,)
    assert settings.options.terraform_plan == ()
    assert settings.options.terraform_dir == ()
    assert settings.origins["terraform_state"] == "auto"
    assert settings.origins["terraform_plan"] == "default"
    assert settings.origins["terraform_dir"] == "default"


def test_auto_detection_runs_only_when_no_config_file_was_found(tmp_path):
    root = repo(tmp_path)
    write(os.path.join(root, CONFIG), config_document(snapshot="estate.json"))
    write(os.path.join(root, "terraform.tfstate"), {"version": 4})

    settings, problems = discovery.settings_for(os.path.join(root, "iam.json"),
                                                env={})

    assert problems == ()
    assert settings.options.primary == os.path.join(root, "estate.json")
    # An operator who wrote a config has already said what the sources are.
    assert settings.options.terraform_state == ()


def test_a_refused_discovered_config_also_suppresses_auto_detection(tmp_path):
    """A DISCOVERED config whose parse was refused suppresses auto-detection
    exactly like a parsed one: the operator who wrote it has already said what
    the sources are, and grounding against a sibling ``terraform.tfstate`` the
    (broken) config never named is exactly what the config-presence rule
    exists to prevent. The refusal still surfaces as problems, and every
    setting falls to its default."""
    root = repo(tmp_path)
    write(os.path.join(root, CONFIG),
          config_document(precedence="bogus-token", max_age="not-a-duration"))
    write(os.path.join(root, "terraform.tfstate"), {"version": 4})

    settings, problems = discovery.settings_for(os.path.join(root, "iam.json"),
                                                env={})

    assert problems, "the refusal must stay on the record"
    assert any("bogus-token" in problem for problem in problems)
    # The load-bearing assertion: the refused config did NOT fall through to
    # the auto-detection layer.
    assert settings.options.terraform_state == ()
    assert settings.origins["terraform_state"] == "default"
    assert settings.origins["max_age"] == "default"


# -- precedence ---------------------------------------------------------------


def test_resolve_settings_origins_name_the_layer_that_supplied_each_field(tmp_path):
    root = repo(tmp_path)
    path = write(os.path.join(root, CONFIG),
                 config_document(snapshot="from-config.json",
                                 precedence="terraform-wins",
                                 requirements="sec_requirements/prod.md"))
    config, problems = discovery.discover(os.path.join(root, "iam.json"), env={})
    assert problems == () and config is not None

    settings = discovery.resolve_settings(
        cli={"primary": "/flag/estate.json"},
        env={"GCP_GROUNDING_MAX_AGE": "3d"},
        config=config, auto=auto_state(root))

    assert settings.options.primary == "/flag/estate.json"
    assert settings.origins["primary"] == "cli"
    assert settings.options.max_age == "3d"
    assert settings.origins["max_age"] == "env"
    assert settings.options.precedence == "terraform-wins"
    assert settings.origins["precedence"] == f"config {path}"
    assert settings.origins["requirements"] == f"config {path}"
    assert settings.origins["terraform_state"] == "auto"
    # Nobody set completeness — the licence to read an absence as a
    # non-existence is never acquired by accident.
    assert settings.options.completeness is None
    assert settings.origins["completeness"] == "default"
    assert settings.origin_of("extra") == "default"

    # The map is TOTAL, so the explain surface can print a line per input.
    assert set(settings.origins) == set(discovery.SETTINGS_FIELDS)


def test_env_supplied_requirements_report_the_env_origin(tmp_path):
    """``$GCP_GROUNDING_REQUIREMENTS`` is the ENVIRONMENT layer's contribution:
    an env-only value reports ``env`` (never ``cli``), the flag still beats it,
    and the environment still beats a config file's ``requirements`` — the same
    precedence and the same labels every other setting gets."""
    root = repo(tmp_path)
    path = write(os.path.join(root, CONFIG),
                 config_document(requirements="sec_requirements/prod.md"))
    config, problems = discovery.discover(os.path.join(root, "iam.json"), env={})
    assert problems == () and config is not None

    env = {discovery.REQUIREMENTS_ENV: "/env/reqs"}
    env_only = discovery.resolve_settings(cli={}, env=env, config=config)
    assert env_only.requirements == "/env/reqs"
    assert env_only.origins["requirements"] == "env"

    flagged = discovery.resolve_settings(cli={"requirements": "/flag/reqs"},
                                         env=env, config=config)
    assert flagged.requirements == "/flag/reqs"
    assert flagged.origins["requirements"] == "cli"

    from_config = discovery.resolve_settings(cli={}, env={}, config=config)
    assert from_config.origins["requirements"] == f"config {path}"

    # The CLI re-exports the name it has always exported; the OWNER moved.
    from gcp_grounding.cli import REQUIREMENTS_ENV
    assert REQUIREMENTS_ENV == discovery.REQUIREMENTS_ENV


def test_an_unknown_cli_setting_is_a_caller_bug():
    with pytest.raises(TypeError) as excinfo:
        discovery.resolve_settings(cli={"snapshto": "x"}, env={}, config=None,
                                   auto=None)
    assert "snapshto" in str(excinfo.value)


def test_the_env_layer_is_the_one_resolver_sources_already_owns(monkeypatch):
    monkeypatch.setenv("GCP_GROUNDING_SNAPSHOT", "/env/estate.json")
    monkeypatch.setenv("GCP_GROUNDING_TF_STATE",
                       os.pathsep.join(["/env/a.tfstate", "/env/b.tfstate"]))

    settings = discovery.resolve_settings(cli=None, env=None, config=None,
                                          auto=None)

    assert settings.options.primary == "/env/estate.json"
    assert settings.options.terraform_state == ("/env/a.tfstate", "/env/b.tfstate")
    assert settings.origins["primary"] == "env"


def test_to_source_options_round_trips_every_field(tmp_path):
    """A field added to ``SourceOptions`` later cannot be silently dropped here,
    because the assertion walks ``dataclasses.fields`` rather than a list."""
    options = SourceOptions(
        primary="/e/estate.json", origins="/e/estate.origins.json",
        extra=("/e/other.json",), terraform_state=("/e/terraform.tfstate",),
        terraform_plan=("/e/plan.json",), terraform_dir=("/e/tf",),
        precedence="terraform-wins", drift_policy="block", max_age="3d",
        now="2026-07-18T10:00:00+00:00", completeness="complete")
    settings = discovery.Settings(options=options, origins={},
                                  targets={}, requirements="/e/prod.md")

    unpinned = discovery.to_source_options(settings, as_of=None)
    for spec in dataclasses.fields(SourceOptions):
        assert getattr(unpinned, spec.name) == getattr(options, spec.name), spec.name

    as_of = freshness.resolve_now("2026-08-01T00:00:00Z")
    pinned = discovery.to_source_options(settings, as_of=as_of)
    for spec in dataclasses.fields(SourceOptions):
        if spec.name == "now":
            assert pinned.now == as_of.isoformat()
            continue
        assert getattr(pinned, spec.name) == getattr(options, spec.name), spec.name


def test_settings_wrap_source_options_rather_than_restating_them():
    """There is ONE definition of what a source option is: every field of
    ``SourceOptions`` is tracked, and the only settings-only fields are the two
    that have no place in a source options object."""
    option_names = {spec.name for spec in dataclasses.fields(SourceOptions)}
    assert set(discovery.OPTION_FIELDS) == option_names
    assert set(discovery.SETTINGS_FIELDS) - option_names == {"targets",
                                                            "requirements"}
    settings_names = {spec.name for spec in dataclasses.fields(discovery.Settings)}
    # The ONE shared spelling, and it is deliberate: the design names this field
    # `origins`, and here it is the per-field ORIGIN LABEL map while
    # `SourceOptions.origins` is the snapshot's sidecar PATH. Pinned so nobody
    # reads one as the other.
    assert settings_names & option_names == {"origins"}
    settings = discovery.resolve_settings(
        cli={"origins": "/e/estate.origins.json"}, env={}, config=None, auto=None)
    assert settings.options.origins == "/e/estate.origins.json"
    assert settings.origins["origins"] == "cli"
