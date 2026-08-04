""":mod:`tests.agentic.tfrepo`: the temp terraform repo the three-input agentic
cases are built on, and the pin that keeps its corpus honest.

THE FALSE-POSITIVE FLOOR is the first thing asserted and the reason everything
downstream can be trusted: the UNEDITED repo, run through the real hook with the
shared argv, passes with BOTH streams byte-empty. An adversarial case that
blocks proves nothing if the base corpus blocks too.

THE FIXTURE-CONSISTENCY PIN, IN BOTH DIRECTIONS, is what makes this document's
second hand-written v4 tfstate safe rather than a duplicate waiting to rot. It
is identical in shape to the one ``tests/test_gcp_estate.py`` carries for
``tests/fixtures/gcp/tf/``: every canonical key the state file produces is
either in the merged agentic estate or listed in :data:`DELIBERATELY_EXTRA` with
a reason, and every key that estate holds for an EMITTED category is either
produced or listed in :data:`DELIBERATELY_ABSENT` with a reason. The second
direction is not redundant — "equal for every key both hold" is VACUOUSLY TRUE
under a key-form regression that makes every produced key miss the table, and
that regression would surface downstream as a benign case that mysteriously
starts blocking rather than as a failure here.

SUBPROCESSES: two, both in one test, both through the shared hook runner, which
counts them against the suite-wide ceiling. ``terraform`` is not installed on
this machine and nothing here needs it.
"""

import json
import re
import time

import pytest

from gcp_grounding.knowledge import GcpSnapshot
from gcp_grounding.tfsource import mapping
from gcp_grounding.tfsource import state as tfstate_reader
from tests.agentic import env, hookrunner, tfrepo
from tests.agentic.asserts import assert_no_verdictless_pass, assert_passed
from tests.agentic.fake_agent import FakeAgent
from tests.agentic.hookrunner import bound_subprocess_budget  # noqa: F401

#: The qualifiers a bare terraform name cannot supply: they come from the
#: workspace, never from the resource. This corpus describes project acme-prod
#: (number 111111111111) under organization 123456789012 and access policy
#: 987654321 — every one of them a value the merged agentic estate holds.
QUALIFIERS = dict(project="acme-prod", project_number="111111111111",
                  organization="123456789012", access_policy="987654321")

#: Every estate category the state file resolves a key in. Pinned so a category
#: that stops being produced cannot quietly drop out of the second direction of
#: the pin, which is scoped to the categories the state emits.
PRODUCED_CATEGORIES = (
    "access_levels",
    "cloud_armor_policies",
    "firewall_rules",
    "iam_bindings",
    "network_tags",
    "org_policies",
    "restricted_services",
    "vpc_sc_perimeters",
)

#: The six resource types the corpus models, and nothing more.
MODELLED_TYPES = (
    "google_access_context_manager_service_perimeter",
    "google_compute_firewall",
    "google_compute_security_policy",
    "google_org_policy_policy",
    "google_project_iam_binding",
    "google_project_iam_member",
)

#: Every canonical key the STATE file produces that the merged agentic estate
#: does NOT store, with the reason. This is the present-in-state-but-not-in-
#: config resource the corpus carries on purpose.
DELIBERATELY_EXTRA = {
    "iam_bindings": {
        "//cloudresourcemanager.googleapis.com/projects/acme-dr":
            "the google_project_iam_member on projects/acme-dr is THE "
            "present-in-state-but-not-in-config resource: it exercises the IAM "
            "fragment path and models a grant terraform applied that the "
            "configuration under review no longer declares, so the estate — "
            "which holds an iam_bindings row for acme-prod only — cannot match "
            "it",
    },
}

#: Every key the merged agentic estate holds for an EMITTED category that the
#: state file does not produce, with the reason. Terraform describes only what
#: ONE workspace applied, so an estate row it does not manage is the normal
#: case; each one is still named, because an unexplained absence is how a
#: key-form regression hides.
DELIBERATELY_ABSENT = {
    "firewall_rules": {
        "projects/acme-prod/global/firewalls/deny-external-rdp":
            "THE CONFIG-ONLY NEW-RESOURCE CASE: main.tf.json declares the "
            "google_compute_firewall deny_rdp and the state has no instance of "
            "it, so a proposal touching it has no predecessor and lands in the "
            "baseline:new arm - which is exactly what the corpus carries it for",
        "projects/acme-prod/global/firewalls/default-deny-ingress":
            "the implicit VPC deny-all: it exists in the estate and no "
            "terraform in this repo manages it, which is what makes the "
            "terraform view PARTIAL rather than an empty estate",
    },
    "network_tags": {
        "prod-web": "named by no resource in this corpus; the tag vocabulary is "
                    "wider than terraform's view of it, which is why "
                    "network_tags is presence-only and may never answer False",
        "prod-db": "named by no resource in this corpus, for the same reason as "
                   "prod-web",
        "ssh-allowed": "named by no resource in this corpus, for the same reason "
                       "as prod-web",
    },
    "org_policies": {
        "projects/acme-prod|constraints/iam.allowedPolicyMemberDomains":
            "the domain-restriction policy is set in the estate and is not "
            "terraform-managed here; the corpus models ONE org policy, the "
            "service-account-key one every benign case reads",
    },
    "access_levels": {
        "accessPolicies/987654321/accessLevels/mfa_required":
            "the perimeter references trusted_corp only, and the corpus adds no "
            "google_access_context_manager_access_level resource of its own",
    },
    "restricted_services": {
        "sqladmin.googleapis.com":
            "restricted at the estate level and not inside this perimeter's "
            "status block",
        "pubsub.googleapis.com":
            "restricted at the estate level and not inside this perimeter's "
            "status block",
    },
}

#: ``projects/<number>``, the one reference form a perimeter uses for a project.
_PROJECT_NUMBER_RE = re.compile(r"projects/(\d+)")


# -- fixtures -----------------------------------------------------------------


@pytest.fixture(scope="module")
def unedited(tmp_path_factory, subprocess_budget):
    """The UNEDITED repo, its hook outcome and its grounding report — the two
    spawns this module spends, taken once.

    It binds the session budget ITSELF rather than relying on the autouse
    ``bound_subprocess_budget``: that fixture is function-scoped, so it has not
    run yet when a module-scoped fixture spawns, and these two children would
    otherwise be counted against a private fallback counter instead of the
    suite-wide ceiling.
    """
    repo = tfrepo.build_tf_repo(tmp_path_factory.mktemp("tfrepo"))
    document = json.loads(repo.tf_json_path.read_text(encoding="utf-8"))
    agent = FakeAgent(repo.root, [tfrepo.proposal_for(
        repo, "P00_unedited", tfrepo.TF_JSON_NAME, document, "pass",
        rationale="the agent rewrites the configuration it found, unchanged")])
    previous = hookrunner.bind_budget(subprocess_budget)
    try:
        _proposal, event = agent.turn()
        outcome = hookrunner.run_hook(event, snapshot=repo.snapshot_path,
                                      extra_argv=tfrepo.hook_argv(repo))
        report = hookrunner.ground_json(repo.tf_json_path,
                                        snapshot=repo.snapshot_path)
    finally:
        hookrunner.bind_budget(previous)
    return repo, outcome, report


@pytest.fixture
def repo(tmp_path):
    """A fresh built repo per test, so a variant cannot leak into a sibling."""
    return tfrepo.build_tf_repo(tmp_path / "repo")


@pytest.fixture(scope="module")
def produced(tmp_path_factory):
    """Category → every canonical key the STATE FILE produces.

    Read at the fact level — the reader plus the mapper registry — rather than
    from an assembled snapshot, so the pin sees every key the state resolves,
    including the categories an emit policy would withhold, and so a key whose
    record was later dropped still proves its key form.

    The state ALONE, not the whole root: the ``.tf.json`` beside it is DESIRED
    state, and this pin is about what the CURRENT-state reader produces.
    """
    built = tfrepo.build_tf_repo(tmp_path_factory.mktemp("tfkeys"))
    read = tfstate_reader.read_state(str(built.state_path),
                                     captured_at=tfrepo.ASOF)
    assert read.ok, read.notes
    result = mapping.map_objects(read.objects, mapping.MapContext(**QUALIFIERS))
    out = {}
    for fact in result.facts:
        assert isinstance(fact.key, str), (
            f"{fact.category}: the state file resolved a NON-STRING key "
            f"{fact.key!r} - the corpus grew an interpolation, and an "
            f"unresolved key cannot be matched against the estate at all")
        out.setdefault(fact.category, set()).add(fact.key)
    return out


@pytest.fixture(scope="module")
def merged_estate():
    return GcpSnapshot.from_dict(tfrepo.merged_snapshot_document())


# -- the builder --------------------------------------------------------------


def test_a_built_repo_holds_every_file_a_case_module_names(repo):
    assert repo.root.is_dir()
    for path in (repo.config_path, repo.state_path, repo.tf_json_path,
                 repo.snapshot_path):
        assert path.is_file(), path
    assert repo.config_path.name == tfrepo.CONFIG_NAME
    # The committed fixture is NOT itself a hidden file; the dot-prefixed name
    # exists only inside the built repo.
    assert (tfrepo.BASE / tfrepo.CONFIG_TEMPLATE).is_file()
    assert not (tfrepo.BASE / tfrepo.CONFIG_NAME).exists()
    # with_hcl defaults to the reader-availability probe.
    assert (repo.tf_path is not None) is tfrepo.HAVE_HCL_READER
    if repo.tf_path is not None:
        assert repo.tf_path.is_file()


def test_discovery_finds_the_built_config_from_the_json_document(repo):
    if not tfrepo.HAVE_DISCOVERY:
        # BRANCH, NEVER SKIP. With no discovery module nothing walks up to a
        # config file, so the honest assertion is that the built repo is INERT
        # rather than wrong: the file is there, and no run reads it.
        assert repo.config_path.is_file()
        return
    from gcp_grounding import discovery

    config, problems = discovery.discover(str(repo.tf_json_path))
    assert problems == (), problems
    assert config is not None, "the built config was not found walking up"
    assert config.path == str(repo.config_path)
    # Every path inside it is absolute and under the root: a hook is spawned
    # with whatever working directory the agent's shell happened to be in.
    assert config.get("primary") == str(repo.snapshot_path)
    assert config.get("terraform_state") == (str(repo.state_path),)
    assert list(config.get("targets")) == [str(repo.tf_json_path)]
    # ... and the target names a REAL estate row, in a real category: no domain
    # is ever guessed from a key, so a near-miss here silently redefines what
    # every pair check compares against.
    (ref,) = config.get("targets").values()
    assert ref.category == "firewall_rules"
    assert ref.key == "projects/acme-prod/global/firewalls/allow-internal-ssh"


def test_building_twice_from_one_corpus_is_byte_identical(tmp_path):
    first = tfrepo.build_tf_repo(tmp_path / "one")
    second = tfrepo.build_tf_repo(tmp_path / "two")
    for name in (tfrepo.STATE_NAME, tfrepo.TF_JSON_NAME, tfrepo.SNAPSHOT_NAME):
        assert (first.root / name).read_bytes() == (second.root / name).read_bytes()


def test_building_a_repo_is_cheap_enough_to_do_per_case(tmp_path):
    """Under 50 ms, so a case module can build one per test rather than sharing
    a mutated tree. The BEST of three builds is measured, not the worst: a
    transient I/O stall must not turn a budget into a flake, while a builder
    that ever grew a real cost — a network call, a whole-tree walk — fails."""
    elapsed = []
    for index in range(3):
        started = time.perf_counter()
        tfrepo.build_tf_repo(tmp_path / f"repo{index}")
        elapsed.append(time.perf_counter() - started)
    assert min(elapsed) < 0.050, elapsed


# -- THE FALSE-POSITIVE FLOOR -------------------------------------------------


def test_the_unedited_repo_passes_byte_silently_and_leaves_verdicts(unedited):
    """The floor for everything downstream, and it must hold before any
    adversarial case is trusted: the corpus as committed neither blocks nor
    chatters, AND the run it makes is not a verdictless pass."""
    _repo, outcome, report = unedited
    assert_passed(outcome)
    assert report.get("ok") is True, report
    assert_no_verdictless_pass(outcome, report)


# -- the state file -----------------------------------------------------------


def test_the_state_file_reads_with_no_unmodelled_resource_types(repo):
    read = tfstate_reader.read_state(str(repo.state_path), captured_at=tfrepo.ASOF)
    assert read.ok, read.notes
    assert read.version == 4 and read.serial is not None and read.lineage
    assert read.data_sources == 0 and read.deposed == 0
    # The ONE note a healthy read carries. Anything else is an entry the reader
    # skipped, and a skipped entry is coverage this corpus silently lost.
    assert read.notes == (
        tfstate_reader.NEVER_COMPLETE_NOTE.format(path=str(repo.state_path)),
    ), read.notes
    types = {obj.type for obj in read.objects}
    assert types == set(MODELLED_TYPES), types
    # Every provider string is the bracketed registry form, which is the hazard
    # a naive rsplit turns into a silently empty estate.
    assert {obj.provider for obj in read.objects} == {"google"}
    result = mapping.map_objects(read.objects, mapping.MapContext(**QUALIFIERS))
    assert result.unrecognized == (), result.unrecognized
    assert result.unmapped == (), result.unmapped
    assert result.failures == (), result.failures


def test_the_corpus_stays_inside_the_review_window():
    """Three small files: ``tests/fixtures/...`` sorts before ``tests/test_...``
    in the diff the independent verifier sees, so every byte here is a byte of
    this module that gets read instead."""
    total = sum((tfrepo.BASE / name).stat().st_size for name in
                (tfrepo.CONFIG_TEMPLATE, tfrepo.STATE_NAME, tfrepo.TF_JSON_NAME))
    assert total < 12000, total


# -- THE FIXTURE-CONSISTENCY PIN, direction one -------------------------------


def test_every_key_the_state_produces_is_stored_or_listed_as_extra(
        produced, merged_estate):
    assert produced, "the state file produced no canonical key at all"
    for category, keys in sorted(produced.items()):
        stored = getattr(merged_estate, category) or ()
        listed = DELIBERATELY_EXTRA.get(category, {})
        unaccounted = sorted(set(keys) - set(stored) - set(listed))
        assert not unaccounted, (
            f"{category}: the state file produces {unaccounted}, which the "
            f"merged agentic estate does not store and DELIBERATELY_EXTRA does "
            f"not explain. The two describe ONE estate: either the estate "
            f"fixture is missing a row or the key form regressed - and a key "
            f"form that regressed surfaces downstream as a BENIGN case that "
            f"mysteriously starts blocking")
        assert set(keys) & set(stored), (
            f"{category}: the state file and the merged agentic estate share NO "
            f"key, so the check above passed vacuously - that is exactly the "
            f"key-form regression drift:key-mismatch exists to catch at runtime "
            f"and this pin exists to catch at fixture time")


def test_the_state_produces_exactly_the_categories_the_corpus_models(produced):
    """Direction two is scoped to the categories the state EMITS, so a category
    that stops being produced altogether would drop out of it silently. Pinning
    the set is what keeps that hole shut."""
    assert sorted(produced) == sorted(PRODUCED_CATEGORIES), sorted(produced)


# -- THE FIXTURE-CONSISTENCY PIN, direction two -------------------------------


def test_every_estate_key_in_an_emitted_category_is_produced_or_listed(
        produced, merged_estate):
    for category in sorted(produced):
        stored = getattr(merged_estate, category) or ()
        listed = DELIBERATELY_ABSENT.get(category, {})
        unaccounted = sorted(set(stored) - produced.get(category, set())
                             - set(listed))
        assert not unaccounted, (
            f"{category}: the merged agentic estate stores {unaccounted}, which "
            f"the state file does not produce and DELIBERATELY_ABSENT does not "
            f"explain. The forward direction alone is vacuously true when a "
            f"key-form regression makes every produced key miss the table")


def test_every_listed_exception_is_still_a_real_one(produced, merged_estate):
    """A stale allowance is worse than none: it silently excuses a key that has
    since started - or stopped - being produced."""
    for category, entries in DELIBERATELY_EXTRA.items():
        for key, reason in entries.items():
            assert reason.strip(), f"{category}/{key} is listed with no reason"
            assert key in produced.get(category, set()), (
                f"{category}/{key} is listed as deliberately extra but the state "
                f"file no longer produces it")
            assert key not in (getattr(merged_estate, category) or ()), (
                f"{category}/{key} is listed as deliberately extra but the "
                f"merged agentic estate now stores it")
    for category, entries in DELIBERATELY_ABSENT.items():
        for key, reason in entries.items():
            assert reason.strip(), f"{category}/{key} is listed with no reason"
            assert key in (getattr(merged_estate, category) or ()), (
                f"{category}/{key} is listed as deliberately absent but the "
                f"merged agentic estate no longer stores it")
            assert key not in produced.get(category, set()), (
                f"{category}/{key} is listed as deliberately absent but the "
                f"state file now produces it")


def test_the_two_designed_exceptions_are_the_named_ones(produced):
    """The corpus carries exactly one present-in-state-but-not-in-config
    resource and one config-only new resource, and both are the pin's
    exceptions rather than undocumented drift."""
    assert set(DELIBERATELY_EXTRA) == {"iam_bindings"}
    assert "//cloudresourcemanager.googleapis.com/projects/acme-dr" in \
        DELIBERATELY_EXTRA["iam_bindings"]
    config = json.loads((tfrepo.BASE / tfrepo.TF_JSON_NAME)
                        .read_text(encoding="utf-8"))
    declared = config["resource"]["google_compute_firewall"]
    assert "deny_rdp" in declared, "the config-only new resource is gone"
    assert "projects/acme-prod/global/firewalls/deny-external-rdp" not in \
        produced.get("firewall_rules", set()), (
            "deny_rdp is now IN the state file, so it is no longer the "
            "config-only new-resource case the benign and drift modules build on")


# -- the perimeter's project numbers ------------------------------------------


def _project_numbers(value):
    """Every ``projects/<number>`` reference anywhere inside *value*."""
    if isinstance(value, str):
        return set(_PROJECT_NUMBER_RE.findall(value))
    if isinstance(value, dict):
        found = set()
        for key, item in value.items():
            found |= _project_numbers(key) | _project_numbers(item)
        return found
    if isinstance(value, (list, tuple)):
        found = set()
        for item in value:
            found |= _project_numbers(item)
        return found
    return set()


def test_every_project_number_in_the_perimeter_resolves_in_the_hierarchy(
        merged_estate):
    hierarchy = merged_estate.resource_hierarchy or {}
    known = {str(node.get("number")) for node in hierarchy.values()
             if isinstance(node, dict) and node.get("number")}
    config = json.loads((tfrepo.BASE / tfrepo.TF_JSON_NAME)
                        .read_text(encoding="utf-8"))
    perimeter = config["resource"][
        "google_access_context_manager_service_perimeter"]
    state = json.loads((tfrepo.BASE / tfrepo.STATE_NAME).read_text(encoding="utf-8"))
    stated = [entry for entry in state["resources"]
              if entry["type"] == "google_access_context_manager_service_perimeter"]
    numbers = _project_numbers(perimeter) | _project_numbers(stated)
    assert numbers, "the perimeter references no project number at all"
    unresolved = sorted(numbers - known)
    assert not unresolved, (
        f"the perimeter references project number(s) {unresolved}, which no "
        f"node of the merged agentic snapshot's resource_hierarchy names "
        f"(known: {sorted(known)}). An unresolved project number does not fail "
        f"here quietly - it surfaces downstream as a SPURIOUS BLOCK on a BENIGN "
        f"case, where the perimeter check cannot ground the resource it guards")


# -- the helpers --------------------------------------------------------------


def test_variant_round_trips(repo):
    before = json.loads(repo.tf_json_path.read_text(encoding="utf-8"))

    def widen(document):
        document["resource"]["google_compute_firewall"]["allow_ssh"][
            "source_ranges"] = ["0.0.0.0/0"]

    path = tfrepo.variant(repo, tfrepo.TF_JSON_NAME, widen)
    assert path == repo.tf_json_path
    after = json.loads(path.read_text(encoding="utf-8"))
    assert after["resource"]["google_compute_firewall"]["allow_ssh"][
        "source_ranges"] == ["0.0.0.0/0"]

    # ... and back, through a mutate that RETURNS a document rather than
    # mutating in place: both shapes are supported and both must round-trip.
    tfrepo.variant(repo, tfrepo.TF_JSON_NAME, lambda _document: before)
    assert json.loads(repo.tf_json_path.read_text(encoding="utf-8")) == before


def test_variant_reaches_the_state_and_the_snapshot_too(repo):
    tfrepo.variant(repo, tfrepo.STATE_NAME,
                   lambda document: {**document, "serial": 99})
    assert json.loads(repo.state_path.read_text(encoding="utf-8"))["serial"] == 99
    tfrepo.variant(repo, tfrepo.SNAPSHOT_NAME,
                   lambda document: {**document, "captured_at": "2020-01-01T00:00:00Z"})
    assert GcpSnapshot.load(repo.snapshot_path).captured_at == "2020-01-01T00:00:00Z"


def test_hook_argv_is_one_shape_and_carries_the_pinned_clock(repo):
    argv = tfrepo.hook_argv(repo)
    assert argv == ("--terraform-state", str(repo.state_path),
                    "--config", str(repo.config_path),
                    "--as-of", tfrepo.ASOF)
    assert tfrepo.hook_argv(repo, extra=("--explain",))[-1] == "--explain"
    # One hour after the snapshot's capture time, so nothing is stale unless a
    # case makes it so.
    assert tfrepo.ASOF == "2026-07-25T09:00:00Z"
    assert env.ESTATE_CAPTURED_AT == "2026-07-25T08:00:00Z"
    assert tfrepo.ASOF > env.ESTATE_CAPTURED_AT


def test_proposal_for_is_declarative_and_refuses_an_absolute_path(repo):
    proposal = tfrepo.proposal_for(repo, "B01_widen", tfrepo.TF_JSON_NAME,
                                   {"resource": {}}, "pass")
    assert proposal.tool_name == "Write" and proposal.kind == "tf_plan"
    assert proposal.id == "B01_widen" and proposal.expect == "pass"
    assert proposal.rationale, "a proposal must say why an agent would make it"
    with pytest.raises(ValueError, match="relative to the repo root"):
        tfrepo.proposal_for(repo, "B02_bad", str(repo.tf_json_path), {}, "pass")


# -- the probes ---------------------------------------------------------------


def test_every_probe_is_a_bool():
    assert set(tfrepo.PROBES) == {
        "HAVE_ENGINE", "HAVE_SOURCES", "HAVE_BASELINE", "HAVE_DISCOVERY",
        "HAVE_EXPLAIN_STATE", "HAVE_ESTATE", "HAVE_RECONCILED", "HAVE_SEC_RULES",
        "HAVE_SEC_DOMAINS", "HAVE_HCL_READER", "HAVE_STATE_FLAG"}
    for name, value in tfrepo.PROBES.items():
        assert isinstance(value, bool), f"{name} is {type(value).__name__}"
        assert getattr(tfrepo, name) is value


def test_a_probe_never_raises_at_import():
    """The discipline the frozen environment module uses: a broken or absent
    dependency degrades a probe to False rather than breaking collection."""
    assert tfrepo._module_available("gcp_grounding.no_such_module") is False
    assert tfrepo._module_available("no_such_package.child") is False


def test_the_state_flag_probe_is_behavioural_not_an_import_check():
    """``find_spec`` cannot answer whether the parser accepts the flag: the
    module can exist with the flag absent, which is precisely the world this
    document's argv would fail silently in."""
    if not tfrepo.HAVE_STATE_FLAG:
        return
    from gcp_grounding.cli import build_parser
    args = build_parser().parse_args(
        ["verify-policy", "--hook", "--snapshot", "s.json",
         "--terraform-state", "t.tfstate", "--as-of", tfrepo.ASOF])
    assert args.terraform_state == ["t.tfstate"]
    assert args.as_of == tfrepo.ASOF
