"""The one clock boundary, the one seven-day ceiling and tfstate supersession.

Every assertion here guards a way the gate could quietly stop being a gate: a
ceiling that only applies when somebody types a flag, a test clock that is set
and silently ignored, a naive timestamp assumed to be UTC and read as a day
fresher than it is, a superseded state file that still justifies a pass, or a
staleness demotion that also erases the findings the stale source supports.
"""

import builtins
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from gcp_grounding import freshness, provenance
from gcp_grounding.core.report import Verdict
from gcp_grounding.knowledge import GcpSnapshot

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
FULL_SNAPSHOT = FIXTURES / "estate_snapshot.json"

CAPTURED = "2026-07-18T09:30:00Z"
CAPTURED_AT = datetime(2026, 7, 18, 9, 30, tzinfo=timezone.utc)


def at(**offset) -> datetime:
    """A clock *offset* after the capture time every fixture ledger uses."""
    return CAPTURED_AT + timedelta(**offset)


def one_source_ledger(*, captured_at: str = CAPTURED,
                      categories=("roles",)) -> provenance.SourceLedger:
    """An API ledger with exactly one source supplying *categories*."""
    builder = provenance.LedgerBuilder()
    builder.source("api-capture", "api", origin="cloudasset.googleapis.com",
                   captured_at=captured_at, scope="complete")
    for category in categories:
        builder.declare(category, scope="complete", source_kinds=("api",))
        builder.fact(category, f"{category}-key", source_id="api-capture")
    return builder.build()


def state_ledger(origin: str, *, serial: int = 12,
                 lineage: str = "5f0b1f0e-0000-4000-8000-000000000001",
                 ) -> provenance.SourceLedger:
    builder = provenance.LedgerBuilder()
    builder.source("tf-state", "tfstate", origin=origin, captured_at=CAPTURED,
                   scope="partial", serial=serial, lineage=lineage)
    builder.declare("firewall_rules", scope="partial", source_kinds=("tfstate",))
    builder.fact("firewall_rules", "projects/p/global/firewalls/allow-ssh",
                 source_id="tf-state", locator="google_compute_firewall.ssh")
    return builder.build()


def write_state(path: Path, *, serial: int, lineage: str,
                with_resources: bool = False) -> Path:
    document = {"version": 4, "terraform_version": "1.7.5", "serial": serial,
                "lineage": lineage, "outputs": {}}
    if with_resources:
        document["resources"] = [{
            "mode": "managed", "type": "google_sql_user", "name": "app",
            "instances": [{"attributes": {"password": "hunter2-in-plaintext"}}],
        }]
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


# -- parse_timestamp ----------------------------------------------------------


def test_a_naive_timestamp_is_refused_and_a_z_suffixed_one_is_aware():
    # THE UNSAFE ASSUMPTION: reading a local-time stamp as UTC shifts the age by
    # up to a day, and towards "fresher" for every zone behind UTC. Refused.
    assert freshness.parse_timestamp("2026-07-18T09:30:00") is None
    assert freshness.parse_timestamp("2026-07-18 09:30:00") is None

    aware = freshness.parse_timestamp(CAPTURED)
    assert aware is not None
    assert aware.tzinfo is not None
    assert aware.utcoffset() == timedelta(0)
    assert aware == CAPTURED_AT
    # Lower case, and an explicit offset, land on the same instant.
    assert freshness.parse_timestamp("2026-07-18t09:30:00z") == CAPTURED_AT
    assert freshness.parse_timestamp("2026-07-18T11:30:00+02:00") == CAPTURED_AT


def test_parse_timestamp_answers_none_rather_than_raising_on_junk():
    for junk in ("", "   ", "yesterday", "2026-13-45T00:00:00Z", None, 17):
        assert freshness.parse_timestamp(junk) is None


# -- parse_duration -----------------------------------------------------------


def test_every_duration_suffix_and_the_bare_integer():
    assert freshness.parse_duration("90s") == timedelta(seconds=90)
    assert freshness.parse_duration("15m") == timedelta(minutes=15)
    assert freshness.parse_duration("36h") == timedelta(hours=36)
    assert freshness.parse_duration("7d") == timedelta(days=7)
    assert freshness.parse_duration("2w") == timedelta(weeks=2)
    # A bare integer is SECONDS.
    assert freshness.parse_duration("300") == timedelta(seconds=300)
    assert freshness.parse_duration("7D") == freshness.MAX_AGE_DEFAULT


def test_the_three_off_spellings_mean_no_limit():
    assert freshness.OFF_SPELLINGS == ("", "off", "none")
    for spelling in ("off", "none", "", "OFF", "None", "  "):
        assert freshness.parse_duration(spelling) is None


def test_an_unreadable_duration_raises_rather_than_meaning_off():
    # If a typo parsed as None it would spell the opt-out, so `--max-age 7dd`
    # would silently switch the on-by-default ceiling off.
    for junk in ("7dd", "a week", "-1d", "d", "7 d"):
        with pytest.raises(ValueError):
            freshness.parse_duration(junk)


# -- resolve_now --------------------------------------------------------------


def test_resolve_now_raises_naming_the_variable_when_it_is_garbage():
    with pytest.raises(ValueError, match="GCP_GROUNDING_NOW"):
        freshness.resolve_now(env={"GCP_GROUNDING_NOW": "half past four"})
    # A NAIVE stamp is garbage too — it is refused, not assumed UTC.
    with pytest.raises(ValueError, match="GCP_GROUNDING_NOW"):
        freshness.resolve_now(env={"GCP_GROUNDING_NOW": "2026-07-18T09:30:00"})


def test_resolve_now_returns_the_pinned_clock_when_it_parses():
    assert freshness.resolve_now(env={"GCP_GROUNDING_NOW": CAPTURED}) == CAPTURED_AT
    # explicit wins over the variable, and the variable over the wall clock.
    assert freshness.resolve_now(at(days=1), env={"GCP_GROUNDING_NOW": CAPTURED}) \
        == at(days=1)
    wall = freshness.resolve_now(env={})
    assert wall.tzinfo is not None and wall.utcoffset() == timedelta(0)


def test_resolve_now_reads_the_real_environment_by_default(monkeypatch):
    monkeypatch.setenv(freshness.NOW_ENV, CAPTURED)
    assert freshness.resolve_now() == CAPTURED_AT
    monkeypatch.setenv(freshness.NOW_ENV, "not-a-time")
    with pytest.raises(ValueError, match="GCP_GROUNDING_NOW"):
        freshness.resolve_now()
    # An exported-but-blank variable is unset, not an error.
    monkeypatch.setenv(freshness.NOW_ENV, "")
    assert freshness.resolve_now().tzinfo is not None


# -- the on-by-default ceiling ------------------------------------------------


def test_eight_days_is_stale_and_six_is_not_with_no_ceiling_argument():
    # THE ON-BY-DEFAULT PIN. Neither call passes max_age. A hook is invoked with
    # one fixed command line, so a ceiling that needs a flag never applies.
    ledger = one_source_ledger()

    stale = freshness.check_freshness(ledger, now=at(days=8))
    assert len(stale) == 1
    verdict = stale[0]
    assert verdict.status == "unverified"
    assert verdict.kind == "staleness"
    assert verdict.target == "api-capture"
    assert "8 days" in verdict.message            # the age, in whole days
    assert "7 days" in verdict.message            # the limit
    assert "api-capture" in verdict.message
    assert "cloudasset.googleapis.com" in verdict.message
    assert CAPTURED in verdict.message
    assert "uncaptured" in verdict.message

    assert freshness.check_freshness(ledger, now=at(days=6)) == ()
    assert freshness.MAX_AGE_DEFAULT == timedelta(days=7)


def test_an_explicit_none_ceiling_suppresses_both():
    ledger = one_source_ledger()
    assert freshness.check_freshness(ledger, now=at(days=8), max_age=None) == ()
    assert freshness.check_freshness(ledger, now=at(days=6), max_age=None) == ()
    demoted, verdicts = freshness.evaluate(ledger, now=at(days=8), max_age=None)
    assert verdicts == ()
    assert demoted is ledger


def test_the_verdict_is_one_per_source_never_one_per_category():
    ledger = one_source_ledger(categories=("roles", "networks", "firewall_rules"))
    verdicts = freshness.check_freshness(ledger, now=at(days=30))
    assert len(verdicts) == 1
    # ...and the ONE verdict still demotes all three.
    demoted = freshness.demote_stale(ledger, verdicts)
    for category in ("roles", "networks", "firewall_rules"):
        assert demoted.scope_of(category).scope == "uncaptured"


def test_an_undated_or_naive_capture_time_abstains_rather_than_passing():
    for stamp in ("", "2026-07-18T09:30:00"):
        ledger = one_source_ledger(captured_at=stamp)
        verdicts = freshness.check_freshness(ledger, now=at(hours=1))
        assert len(verdicts) == 1, stamp
        assert verdicts[0].kind == "staleness"
        assert "7 days" in verdicts[0].message


def test_an_hours_old_source_renders_hours_under_a_tight_ceiling():
    ledger = one_source_ledger()
    verdicts = freshness.check_freshness(ledger, now=at(hours=9),
                                         max_age=freshness.parse_duration("4h"))
    assert len(verdicts) == 1
    assert "9 hours" in verdicts[0].message
    assert "4 hours" in verdicts[0].message


def test_check_freshness_refuses_a_naive_clock():
    with pytest.raises(ValueError):
        freshness.check_freshness(one_source_ledger(),
                                  now=datetime(2026, 7, 26, 9, 30))


# -- the demotion, and what it deliberately leaves alone ----------------------


def test_demote_stale_changes_only_the_ledger_and_leaves_a_finding_standing():
    snapshot = GcpSnapshot.load(FULL_SNAPSHOT)
    ledger = provenance.SourceLedger.unattributed(snapshot,
                                                  origin=str(FULL_SNAPSHOT))
    before = json.dumps(snapshot.to_dict(), indent=2, sort_keys=True)

    # A finding the stale source supports. It must survive untouched: letting a
    # snapshot rot must not become a way to switch the gate off.
    finding = Verdict("contradicted", "drift:material", "roles/owner", 7,
                      "the estate grants roles/owner where the proposal does not")

    demoted, verdicts = freshness.evaluate(ledger, now=at(days=8))
    assert [v.kind for v in verdicts] == ["staleness"]
    survivors = freshness.demote_stale(ledger, tuple(verdicts) + (finding,))

    # THE DATA IS BYTE-IDENTICAL; only the ledger moved.
    assert json.dumps(snapshot.to_dict(), indent=2, sort_keys=True) == before
    assert demoted is not ledger
    assert demoted.facts == ledger.facts
    assert demoted.sources == ledger.sources
    assert demoted.artifacts == ledger.artifacts
    assert demoted.census == ledger.census

    scope = demoted.scope_of("roles")
    assert scope.scope == "uncaptured"
    assert scope.taint == "stale"
    assert not scope.can_license()
    assert "roles" in demoted.tainted_categories()
    assert "stale" in scope.note
    # The ORIGINAL ledger is untouched, so nothing mutated under a caller.
    assert ledger.scope_of("roles").scope == "complete"
    assert ledger.scope_of("roles").taint == ""

    # THE ASYMMETRY: the contradicted finding is not rewritten, downgraded or
    # dropped — demote_stale returns a ledger and never touches a verdict.
    assert finding.status == "contradicted"
    assert finding.message.startswith("the estate grants")
    assert survivors.scope_of("roles").scope == "uncaptured"

    # And the demotion is what every absence-reasoning rule actually reads.
    assert provenance.require_complete(ledger, "roles") is None
    reason = provenance.require_complete(demoted, "roles", rule="r1")
    assert reason is not None and "not captured" in reason


def test_demote_stale_returns_the_same_ledger_when_nothing_is_stale():
    ledger = one_source_ledger()
    other = Verdict("contradicted", "drift:material", "api-capture", 1, "unrelated")
    assert freshness.demote_stale(ledger, ()) is ledger
    assert freshness.demote_stale(ledger, (other,)) is ledger


def test_sourced_categories_covers_both_attribution_routes():
    ledger = one_source_ledger(categories=("roles", "networks"))
    assert freshness.sourced_categories(ledger, "api-capture") == ("networks", "roles")
    assert freshness.sourced_categories(ledger, "nobody") == ()

    # The unattributed path records no per-fact origins at all, and must still
    # fall under the ceiling.
    snapshot = GcpSnapshot.load(FULL_SNAPSHOT)
    bare = provenance.SourceLedger.unattributed(snapshot)
    assert bare.facts == {}
    assert "roles" in freshness.sourced_categories(bare, "unattributed")


# -- tfstate supersession -----------------------------------------------------


def test_a_serial_one_higher_on_the_same_lineage_names_both_numbers(tmp_path):
    path = write_state(tmp_path / "terraform.tfstate", serial=13,
                       lineage="5f0b1f0e-0000-4000-8000-000000000001")
    ledger = state_ledger(str(path), serial=12)

    verdicts = freshness.state_supersession(ledger)
    assert len(verdicts) == 1
    verdict = verdicts[0]
    assert verdict.status == "unverified"
    assert verdict.kind == "staleness:serial"
    assert verdict.target == "tf-state"
    assert "serial 12" in verdict.message
    assert "serial 13" in verdict.message
    assert "uncaptured" in verdict.message

    # ...and it demotes the categories that state supplied.
    assert freshness.demote_stale(ledger, verdicts).scope_of(
        "firewall_rules").taint == "stale"

    # An equal or lower serial on the same lineage is not supersession.
    assert freshness.state_supersession(state_ledger(str(path), serial=13)) == ()
    assert freshness.state_supersession(state_ledger(str(path), serial=99)) == ()


def test_a_differing_lineage_emits_the_lineage_verdict_and_not_the_serial_one(tmp_path):
    path = write_state(tmp_path / "terraform.tfstate", serial=99,
                       lineage="aaaaaaaa-0000-4000-8000-00000000ffff")
    ledger = state_ledger(str(path), serial=12,
                          lineage="5f0b1f0e-0000-4000-8000-000000000001")

    verdicts = freshness.state_supersession(ledger)
    assert len(verdicts) == 1
    message = verdicts[0].message
    assert verdicts[0].kind == "staleness:serial"
    assert "lineage" in message
    assert "5f0b1f0e-0000-4000-8000-000000000001" in message
    assert "aaaaaaaa-0000-4000-8000-00000000ffff" in message
    # A different lineage is a different number line: the serial comparison is
    # short-circuited rather than reported alongside it.
    assert "serial 99" not in message


def test_a_reader_returning_none_emits_nothing(tmp_path):
    ledger = state_ledger(str(tmp_path / "gone.tfstate"))
    assert freshness.state_supersession(ledger) == ()          # the file is absent
    assert freshness.state_supersession(ledger, reader=lambda path: None) == ()
    # A header with no serial says nothing about ours either.
    assert freshness.state_supersession(ledger, reader=lambda path: {}) == ()


def test_only_a_tfstate_source_is_compared(tmp_path):
    path = write_state(tmp_path / "terraform.tfstate", serial=13, lineage="l1")
    builder = provenance.LedgerBuilder()
    builder.source("api-capture", "api", origin=str(path), captured_at=CAPTURED,
                   scope="complete")
    builder.declare("roles", scope="complete", source_kinds=("api",))
    assert freshness.state_supersession(builder.build()) == ()


# -- the default header reader ------------------------------------------------


def test_the_default_reader_returns_only_the_header_never_the_resources(tmp_path):
    path = write_state(tmp_path / "terraform.tfstate", serial=12, lineage="l1",
                       with_resources=True)
    assert "hunter2-in-plaintext" in path.read_text(encoding="utf-8")

    header = freshness.read_state_header(path)
    assert header == {"version": 4, "serial": 12, "lineage": "l1"}
    assert "resources" not in header
    assert "terraform_version" not in header
    assert "hunter2-in-plaintext" not in json.dumps(header)
    assert freshness.STATE_HEADER_KEYS == ("version", "serial", "lineage")


def test_a_hundred_megabyte_state_file_is_refused_without_being_read(tmp_path, monkeypatch):
    path = tmp_path / "huge.tfstate"
    with open(path, "wb") as handle:
        handle.truncate(100 * 1024 * 1024)         # sparse: no bytes are written
    assert path.stat().st_size == 100 * 1024 * 1024
    assert freshness.MAX_STATE_BYTES < 100 * 1024 * 1024

    def refuse_to_open(*args, **kwargs):
        raise AssertionError("read_state_header opened a file it refused by size")

    monkeypatch.setattr(builtins, "open", refuse_to_open)
    header = freshness.read_state_header(path)
    monkeypatch.undo()
    assert header is None


def test_the_default_reader_refuses_a_non_regular_file_and_junk(tmp_path):
    assert freshness.read_state_header(tmp_path) is None            # a directory
    assert freshness.read_state_header(tmp_path / "absent.tfstate") is None

    not_json = tmp_path / "broken.tfstate"
    not_json.write_text("{ this is not json", encoding="utf-8")
    assert freshness.read_state_header(not_json) is None

    not_object = tmp_path / "list.tfstate"
    not_object.write_text("[1, 2, 3]", encoding="utf-8")
    assert freshness.read_state_header(not_object) is None


# -- evaluate -----------------------------------------------------------------


def test_evaluate_orders_age_before_supersession_and_demotes_both(tmp_path):
    path = write_state(tmp_path / "terraform.tfstate", serial=13, lineage="l1")
    ledger = state_ledger(str(path), serial=12, lineage="l1")

    demoted, verdicts = freshness.evaluate(ledger, now=at(days=8))
    assert [v.kind for v in verdicts] == ["staleness", "staleness:serial"]
    assert set(freshness.STALENESS_KINDS) == {v.kind for v in verdicts}
    scope = demoted.scope_of("firewall_rules")
    assert scope.scope == "uncaptured"
    assert scope.taint == "stale"
    assert ledger.scope_of("firewall_rules").scope == "partial"


def test_this_module_owns_the_only_ceiling_constant():
    # One implementation per rule: another module may READ this ceiling, but
    # nothing else may DEFINE one, because two ceilings are two answers to "is
    # this estate current" and the looser one is the one that lets a pass out.
    package = Path(freshness.__file__).parent
    owners = sorted(
        path.name for path in package.rglob("*.py")
        if any(line.split("=")[0].strip() in ("MAX_AGE_DEFAULT", "MAX_AGE")
               for line in path.read_text(encoding="utf-8").splitlines()
               if "=" in line))
    assert owners == ["freshness.py"]
