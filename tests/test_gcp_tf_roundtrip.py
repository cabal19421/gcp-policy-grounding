"""The loop: ``gcp-ground capture-terraform`` and then ``gcp-ground
verify-policy`` against the file it wrote.

Capture ends at a written file and reconciliation begins at a loaded one, so the
seam between them is tested from neither side. This module walks it: every test
runs IN PROCESS through :func:`gcp_grounding.cli.main` with ``capsys`` and
``tmp_path`` — no subprocess at all, so the session-wide spawn budget is
untouched — and every assertion reads the real bytes an operator would get.

Capability-honest like the rest of the suite: the capture pipeline's
availability is a module-level boolean and the tests BRANCH on it, asserting the
honest degradation on the way past rather than skipping.

TWO THINGS THE LOOP DOES NOT DO, ASSERTED HERE RATHER THAN ASSUMED, because
mis-reading either is how a partial view gets read back as a complete one:

* A BARE ``--snapshot`` DOES NOT PUT THE SIDECAR IN PLAY. ``primary`` is
  deliberately not a state option (``cli._STATE_OPTIONS``) so that a run naming
  only a snapshot keeps its byte-identical pre-existing output, and the
  no-state route never consults a ledger. The ledger reaches the engine when
  the operator names one — ``--origins`` — or configures any other state
  source, and that is the invocation every grounding test below uses.
* THE MISSING-SIDECAR NOTE FIRES ONLY WITH A SECOND SOURCE IN PLAY
  (``sources.load_source(..., multi=...)``). The SCOPE degrades in both
  positions, which is the part that decides answers; the note is suppressed for
  a lone source on purpose, and that asymmetry is pinned below so nobody
  "fixes" it into a channel every single-source run trains its user to ignore.
"""

import dataclasses
import importlib.util
import json
from pathlib import Path

import pytest

from gcp_grounding import (discovery, explain_state, freshness, gate,
                           provenance, sources)
from gcp_grounding.cli import main
from gcp_grounding.knowledge import GcpSnapshot

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
TF = FIXTURES / "tf"
STATE = TF / "estate.tfstate"
POLICIES = FIXTURES / "policies"
GOOD = POLICIES / "iam_policy_good.json"

#: The legacy, vocabulary-only snapshot: five platform categories and NO estate
#: record table. Its shape is what earns it the ``complete`` fallback.
LEGACY = FIXTURES / "snapshot.json"

#: The sentinel planted in the terraform fixtures. A loop that leaks it into a
#: durable artifact, onto a terminal or into a report has broken the redaction
#: boundary; every check is on the BYTES.
SECRET = "FIXTURE-SECRET-DO-NOT-LEAK"

#: The second planted secret, checked alongside it — a value masked in one
#: rendering and printed in another is not masked.
SECRET_BY_NAME = "FIXTURE-SECRET-BY-NAME"

#: An explicit capture stamp and a pinned clock: between them no assertion here
#: can drift with the wall clock, and the whole loop is reproducible.
STAMP = "2024-01-01T00:00:00Z"
NOW = "2024-01-01T06:00:00Z"

#: The category this corpus can actually fill under an existence-licensing
#: opt-in (``google_project_iam_custom_role`` has a mapper) AND the one the
#: reasoner mints existence verdicts for — the two conditions a downstream
#: ``EXISTENCE_LICENSING`` consequence test needs at once.
LICENSED = "roles"

#: Roles the estate has that terraform does not manage. Every one is in the
#: legacy snapshot and none is in the capture, which is what makes an
#: ``ungrounded`` over a terraform-only view a manufactured finding.
UNMANAGED_ROLES = ("roles/bigquery.dataViewer", "roles/bigquery.jobUser",
                   "roles/storage.objectViewer")

#: Names the state fixture carries. None may reach a report that refused to
#: grade it: a state file handed in as the document is not a proposal, and
#: grading it would report the whole estate as if an agent had just written it.
STATE_CONTENTS = ("roles/owner", "roles/iam.securityAdmin",
                  "serviceAccount:ci-deployer@acme-prod.iam.gserviceaccount.com")

#: The capture pipeline resolves ``estate`` and the ``tfsource`` readers LAZILY
#: inside the handler. Probed by spec — a bare name check reads True from an
#: already-imported parent package, which is the wrong question.
HAVE_CAPTURE = (
    importlib.util.find_spec("gcp_grounding.estate") is not None
    and importlib.util.find_spec("gcp_grounding.tfsource.discover") is not None)


# -- the environment this module measures in ----------------------------------


@pytest.fixture(autouse=True)
def pinned_environment(monkeypatch):
    """One pinned clock and NO ambient source configuration.

    Every source variable is cleared, so a developer with a populated
    environment measures the same loop CI does; the clock is pinned six hours
    after the capture stamp, which keeps every source inside the default
    freshness limit. Without that the staleness pass demotes each category to
    ``uncaptured`` and the coverage refusals below stop naming ``partial`` —
    they would still refuse, but for the wrong reason.
    """
    for variable in sources.ENV_FIELDS.values():
        if variable:
            monkeypatch.delenv(variable, raising=False)
    for variable in (discovery.CONFIG_ENV, "GCP_GROUNDING_REQUIREMENTS"):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setenv(sources.NOW_ENV, NOW)


@pytest.fixture(autouse=True)
def registered_mappers():
    """The domain mappers, put back before every test in this module.

    Registration is import-time and therefore PROCESS-GLOBAL: a sibling module
    that emptied the registry (``mapping.reset_cache``) cannot get the entries
    back by re-importing an already-imported module, so a capture running after
    one would silently map NOTHING and this module's answers would depend on
    collection order. ``test_gcp_tf_map_network`` states the same rule and
    solves it the same way; this is that idiom, applied at the far end of the
    loop. A checkout missing one mapper module is left as missing coverage,
    exactly as ``mapping._ensure_loaded`` leaves it.

    There is NO teardown reset, deliberately. Emptying the registry on the way
    out is what makes the leak travel; leaving it LOADED hands whatever runs
    next the state a fresh process would have given it, and no module in this
    suite depends on inheriting an empty one — the two that need an empty
    registry clear it in their own fixtures.
    """
    if not HAVE_CAPTURE:
        yield
        return
    from gcp_grounding.tfsource import mapping
    mapping.reset_cache()
    for name in mapping.MAP_MODULES:
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        register_all = getattr(module, "register_all", None)
        if callable(register_all):
            register_all()
    yield


# -- helpers -------------------------------------------------------------------


def invoke(capsys, *argv) -> tuple[int, str, str]:
    code = main([str(arg) for arg in argv])
    out, err = capsys.readouterr()
    return code, out, err


def capture(capsys, out, *extra) -> tuple[int, str, str]:
    """``capture-terraform`` over the terraform fixtures, clock pinned."""
    return invoke(capsys, "capture-terraform", TF, "--out", out,
                  "--captured-at", STAMP, *extra)


def captured(capsys, tmp_path, *extra, name="terraform-snapshot.json"
             ) -> tuple[Path, Path]:
    """The written pair: ``(snapshot, sidecar)``, asserted to exist."""
    out = tmp_path / name
    code, _stdout, stderr = capture(capsys, out, *extra)
    assert code == 0, stderr
    sidecar = Path(provenance.origins_path(out))
    assert out.exists() and sidecar.exists()
    return out, sidecar


def ground(capsys, snapshot, *extra) -> tuple[int, dict, str]:
    """``verify-policy`` over the good IAM policy, as one parsed json report."""
    code, stdout, stderr = invoke(capsys, "verify-policy", GOOD,
                                  "--snapshot", snapshot, "--no-config",
                                  "--format", "json", *extra)
    return code, json.loads(stdout), stderr


def role_verdicts(report) -> list[dict]:
    return [v for v in report["verdicts"] if v["kind"] == "role"]


def partial_refusal(category: str) -> str:
    """``require_complete``'s exact answer for a terraform-captured category
    with no known holes."""
    return (f"this check reasons from absence, but category '{category}' has "
            f"partial coverage from hcl, tfplan-prior, tfstate with no declared "
            f"boundary - absence within a partial capture is not absence")


def undeclared_refusal(category: str) -> str:
    """``require_complete``'s exact answer for a snapshot whose sidecar is
    gone: nobody said, so nothing is licensed."""
    return (f"this check reasons from absence, but category '{category}' has "
            f"undeclared coverage from unattributed with no declared boundary - "
            f"absence within a undeclared capture is not absence")


def degradation_is_honest(capsys) -> bool:
    """True when the capture pipeline is not part of this checkout — asserting
    the honest degradation on the way past, rather than skipping.

    The lazy import sits behind ``ImportError`` precisely so a checkout without
    the readers SAYS SO instead of tracebacking; an absent capability that is
    merely skipped is a capability nobody ever checks degrades correctly.
    """
    if HAVE_CAPTURE:
        return False
    code, _, err = invoke(capsys, "capture-terraform", TF)
    assert code == 2
    assert "not part of this checkout" in err and "nothing was captured" in err
    return True


# -- 1. the ledger survives the round trip, and its loss is safe ---------------


def test_the_written_sidecar_is_the_ledger_the_snapshot_loads_back_with(
        capsys, tmp_path):
    """THE HEADLINE OF THE SEAM. The snapshot written by ``capture-terraform``
    is loaded back by :func:`gcp_grounding.sources.load_source` with NO explicit
    origins flag, and the ledger that comes back is the one that was WRITTEN —
    not the ``unattributed`` fallback, which would silently hand a
    terraform-managed-only view coverage it never had.
    """
    if degradation_is_honest(capsys):
        return
    snapshot, sidecar = captured(capsys, tmp_path)

    loaded, notes = sources.load_source(snapshot)          # no origins= at all
    assert loaded is not None and notes == ()

    written = provenance.SourceLedger.load(sidecar)
    assert loaded.ledger.to_dict() == written.to_dict()
    # And demonstrably NOT the fallback: that one knows a single source (the
    # snapshot path) and spells its fidelity 'unattributed'.
    fallback = provenance.SourceLedger.unattributed(
        loaded.snapshot, source_id=str(snapshot), origin=str(snapshot))
    assert loaded.ledger.to_dict() != fallback.to_dict()
    assert loaded.fidelity() != "unattributed"
    assert set(loaded.ledger.sources) == {str(STATE), str(TF / "estate_plan.json"),
                                          str(TF / "hcl" / "main.tf"),
                                          str(TF / "hcl" / "perimeter.tf.json"),
                                          str(TF / "hcl" / "proposal.tf.json"),
                                          str(TF / "hcl" / "unresolvable.tf")}

    emitted = loaded.snapshot.captured_categories()
    assert emitted
    for category in emitted:
        scope = loaded.ledger.scope_of(category)
        assert scope.scope == "partial", category
        assert scope.existence_licensed is False, category
        reason = provenance.require_complete(loaded.ledger, category)
        # NEVER None: an absence inside a terraform capture is not an absence.
        assert reason is not None, category
        if scope.dropped:
            # Refused one arm EARLIER, and strictly more specifically: this
            # corpus's interpolated firewall rules are dropped by
            # ``drop_unresolved``, so the category has known holes on top of
            # being partial.
            assert reason.endswith("cannot license a negative"), category
            assert f"dropped {scope.dropped} record(s)" in reason, category
        else:
            assert reason == partial_refusal(category), category


def test_a_lost_sidecar_degrades_to_undeclared_in_both_positions(
        capsys, tmp_path):
    """DELETE the sidecar and the fallback fires at ``undeclared`` — never
    ``complete`` — whether the snapshot is one of several sources or the only
    one.

    Source COUNT is the wrong discriminator and this is where that matters: a
    terraform capture whose sidecar was lost, renamed or simply not copied is
    exactly ONE source, and a count-based fallback would read it as
    licensed-complete.
    """
    if degradation_is_honest(capsys):
        return
    snapshot, sidecar = captured(capsys, tmp_path)
    declared = provenance.SourceLedger.load(sidecar).declared_categories()
    sidecar.unlink()

    # AS THE ONLY SOURCE. No note — deliberately, see the module docstring —
    # but the scope degrades, which is the half that decides answers.
    alone, notes = sources.load_source(snapshot)
    assert notes == ()
    assert alone.fidelity() == "unattributed"
    for category in declared:
        assert alone.ledger.scope_of(category).scope == "undeclared", category
        assert provenance.require_complete(alone.ledger, category) == \
            undeclared_refusal(category), category

    # WITH A SECOND SOURCE IN PLAY. Same scope, plus the note that says so.
    multi, notes = sources.load_source(snapshot, multi=True)
    assert [note.kind for note in notes] == ["provenance"]
    message = notes[0].message
    assert "arrived with no source ledger" in message
    assert "is 'undeclared'" in message
    assert "NOT read as a licensed-complete view" in message
    for category in declared:
        assert multi.ledger.scope_of(category).scope == "undeclared", category

    # And through the real assembler, in both positions.
    for options in (sources.SourceOptions(primary=str(snapshot)),
                    sources.SourceOptions(primary=str(snapshot),
                                          extra=(str(LEGACY),))):
        state = sources.load_current(options)
        assert state.ok
        for category in declared:
            assert state.ledger.scope_of(category).scope != "complete", category


def test_the_single_source_arm_refuses_absence_and_only_complete_changes_it(
        capsys, tmp_path):
    """``verify-policy`` against a sidecar-less capture, single source: every
    emitted category refuses to license an absence, and ``--completeness
    complete`` is the ONE declaration that buys the licence back.

    This is the arm nothing else covers, and the one where a false ``complete``
    is most expensive: with the licence, every role the estate has but
    terraform does not manage is reported ``ungrounded`` and the run FAILS —
    a manufactured hallucination report over a view that never enumerated the
    category.
    """
    if degradation_is_honest(capsys):
        return
    snapshot, sidecar = captured(capsys, tmp_path, "--include", LICENSED)
    sidecar.unlink()

    loaded, _ = sources.load_source(snapshot)
    emitted = loaded.snapshot.captured_categories()
    assert LICENSED in emitted
    for category in emitted:
        assert provenance.require_complete(loaded.ledger, category) == \
            undeclared_refusal(category), category
    # THE OVERRIDE, and only it: an explicit, auditable declaration.
    licensed, _ = sources.load_source(snapshot, completeness="complete")
    for category in emitted:
        assert provenance.require_complete(licensed.ledger, category) is None

    # At the CLI, over the same file. ``--completeness`` is itself what turns
    # the current-state route on, so each arm is one flag away from the others.
    for declaration in ("undeclared", "partial"):
        code, report, _ = ground(capsys, snapshot, "--completeness", declaration)
        assert code == 0, declaration
        verdicts = role_verdicts(report)
        assert {v["target"] for v in verdicts} == set(UNMANAGED_ROLES)
        assert {v["status"] for v in verdicts} == {"unverified"}, declaration

    code, report, _ = ground(capsys, snapshot, "--completeness", "complete")
    assert code == 1
    verdicts = role_verdicts(report)
    assert {v["target"] for v in verdicts} == set(UNMANAGED_ROLES)
    assert {v["status"] for v in verdicts} == {"ungrounded"}

    # AND NOTHING ELSE DOES. The other state knobs decide which source wins,
    # what a disagreement costs and how old is too old; none of them is a
    # statement about coverage, so none of them may license an absence.
    code, report, _ = ground(capsys, snapshot, "--completeness", "undeclared",
                             "--precedence", "api-wins",
                             "--drift-policy", "abstain", "--max-age", "off")
    assert code == 0
    assert {v["status"] for v in role_verdicts(report)} == {"unverified"}


def test_the_legacy_vocabulary_only_snapshot_still_falls_back_to_complete(capsys):
    """THE EXEMPTION, on the record rather than assumed. A snapshot carrying no
    estate record table is the pre-existing artifact this tool has always read
    as an enumeration, and its fallback is unchanged: single source, no
    sidecar, ``complete``."""
    assert not Path(provenance.origins_path(LEGACY)).exists()
    loaded, notes = sources.load_source(LEGACY)
    assert notes == ()
    assert sources.has_estate_table(loaded.snapshot) is False
    assert sources.default_completeness(loaded.snapshot) == "complete"
    for category in loaded.ledger.declared_categories():
        assert loaded.ledger.scope_of(category).scope == "complete", category
        assert provenance.require_complete(loaded.ledger, category) is None, category


# -- 2. no source is complete by accident --------------------------------------


def test_no_domain_is_complete_by_accident(capsys, tmp_path):
    """THE BYTE-INDISTINGUISHABILITY GUARD, END TO END.

    The capture goes through the same writer and the same schema an API capture
    does — the snapshot document alone says nothing about terraform — so the
    provenance travelling beside it is the ONLY thing separating the two. With
    the sidecar: every covered domain ``partial``. Without it, and with another
    source configured: every domain ``undeclared``, never ``complete``.
    """
    if degradation_is_honest(capsys):
        return
    snapshot, sidecar = captured(capsys, tmp_path)

    # THE SAME SCHEMA AN API CAPTURE WRITES, and nothing added: no key names a
    # source, a fidelity or a scope, so the document itself cannot be told
    # apart from a fetched one. Only the SHAPE — carrying an estate record
    # table — drives the fallback, and it drives it DOWN.
    body = json.loads(snapshot.read_text(encoding="utf-8"))
    assert set(body) <= {f.name for f in dataclasses.fields(GcpSnapshot)}
    assert sources.has_estate_table(GcpSnapshot.load(snapshot)) is True
    assert sources.default_completeness(GcpSnapshot.load(snapshot)) == "undeclared"

    loaded, _ = sources.load_source(snapshot)     # no completeness option
    covered = loaded.ledger.declared_categories()
    assert covered
    for category in covered:
        assert loaded.ledger.scope_of(category).scope == "partial", category

    sidecar.unlink()
    state = sources.load_current(sources.SourceOptions(
        primary=str(snapshot), extra=(str(LEGACY),)))
    assert state.ok
    for category in covered:
        scope = state.ledger.scope_of(category).scope
        assert scope == "undeclared", (category, scope)


# -- 3. no false absence -------------------------------------------------------


def test_a_partial_capture_never_manufactures_a_false_absence(capsys, tmp_path):
    """A role the estate HAS and terraform does not manage answers
    ``unverified`` over a terraform capture — never ``ungrounded`` — and the
    licensing opt-in does not change that.

    THREE ARMS, all with the written sidecar in play:

    * the plain capture, where the category was never emitted at all;
    * ``--include networks``, the design's named opt-in — over this corpus no
      mapper builds a ``networks`` fact, so the category stays uncaptured and
      the arm measures that an opt-in alone changes nothing;
    * ``--include roles``, which is the arm that actually EXERCISES the
      downstream consequence: the category is emitted and POPULATED, so the
      snapshot on its own answers False for an unmanaged role and the reasoner
      does mint an ``ungrounded`` for it — which ``drift.postpass`` then
      downgrades because the ledger still says ``partial``. That pairing is
      what proves the loud ``--include`` warning is not the only thing standing
      between a user and a manufactured hallucination report.

    ``existence_licensed`` is False on every arm, including the opted-in one:
    the licence needs a ``complete`` scope and terraform coverage can never
    reach one. The opt-in buys POPULATION, and the ledger is what keeps the
    population from being read as an enumeration.
    """
    if degradation_is_honest(capsys):
        return
    for label, extra in (("plain", ()),
                         ("networks", ("--include", "networks")),
                         (LICENSED, ("--include", LICENSED))):
        snapshot, sidecar = captured(capsys, tmp_path, *extra,
                                     name=f"snap-{label}.json")
        code, report, _ = ground(capsys, snapshot, "--origins", sidecar)
        assert code == 0, extra
        assert report["summary"]["ungrounded"] == 0, extra
        verdicts = role_verdicts(report)
        assert {v["target"] for v in verdicts} == set(UNMANAGED_ROLES), extra
        assert {v["status"] for v in verdicts} == {"unverified"}, extra
        if LICENSED in extra:
            # THE DOWNGRADE, named: the message says which category, at which
            # scope, and from which source.
            for verdict in verdicts:
                assert "partial coverage" in verdict["message"]
                assert f"'{LICENSED}'" in verdict["message"]
                assert "a partial enumeration proves no absence" in \
                    verdict["message"]
            # AND THE COST THE OPT-IN REALLY BOUGHT, made concrete: the
            # snapshot ALONE now answers False for a role the estate has, which
            # is the ``ungrounded`` the reasoner mints and ``drift.postpass``
            # rewrites. The ledger is what stops it — the scope stays
            # ``partial``, so the licence is WITHHELD however loudly
            # ``--include`` was asked for.
            opted = GcpSnapshot.load(snapshot)
            assert opted.roles
            assert opted.role_exists(UNMANAGED_ROLES[0]) is False
            scope = provenance.SourceLedger.load(sidecar).scope_of(LICENSED)
            assert (scope.emitted, scope.scope) == (True, "partial")
            assert scope.existence_licensed is False
            assert scope.can_license() is False
        else:
            # Never emitted, so never even a candidate for an absence claim.
            assert GcpSnapshot.load(snapshot).roles is None
            for verdict in verdicts:
                assert "did not capture roles" in verdict["message"]


# -- 4. no secrets in the loop -------------------------------------------------


def test_no_planted_secret_survives_the_loop(capsys, tmp_path):
    """The redaction boundary across BOTH commands, asserted on bytes: neither
    written file, neither stream of the capture run, and neither stream nor the
    json report of the verify run may carry the sentinel."""
    if degradation_is_honest(capsys):
        return
    out = tmp_path / "snap.json"
    code, capture_out, capture_err = capture(capsys, out)
    assert code == 0
    sidecar = Path(provenance.origins_path(out))
    assert STATE.read_bytes().count(SECRET.encode()) > 0   # the input HAS it

    code, verify_out, verify_err = invoke(
        capsys, "verify-policy", GOOD, "--snapshot", out, "--origins", sidecar,
        "--no-config", "--format", "json")
    assert code == 0
    report = json.loads(verify_out)

    payloads = (out.read_bytes(), sidecar.read_bytes(),
                capture_out.encode("utf-8"), capture_err.encode("utf-8"),
                verify_out.encode("utf-8"), verify_err.encode("utf-8"),
                json.dumps(report, sort_keys=True).encode("utf-8"))
    for sentinel in (SECRET, SECRET_BY_NAME):
        for payload in payloads:
            assert sentinel.encode("utf-8") not in payload, sentinel


# -- 5. a state file is not a proposal, at the CLI -----------------------------


def test_a_state_file_handed_in_as_the_document_is_refused(capsys):
    """``verify-policy tests/fixtures/gcp/tf/estate.tfstate`` is NOT graded.

    ``preflight.detect_kind`` reads a tfstate as a PLAN — every tfstate carries
    ``terraform_version`` — and a zero-claim plan is indistinguishable from a
    clean pass, so the refusal has to happen first and has to be visible: one
    ungrounded verdict, exit 1, and not one role or member out of the state's
    contents anywhere in the report.
    """
    code, stdout, _ = invoke(capsys, "verify-policy", STATE,
                             "--snapshot", LEGACY, "--no-config",
                             "--format", "json")
    assert code == 1
    report = json.loads(stdout)
    # NOT a claim-free ok report: the run produced no grounding, which is not
    # a pass.
    assert report["ok"] is False
    assert report["summary"] == {"grounded": 0, "ungrounded": 1,
                                 "contradicted": 0, "unverified": 0}
    assert len(report["verdicts"]) == 1
    verdict = report["verdicts"][0]
    assert verdict["status"] == "ungrounded"
    assert verdict["kind"] == "state:not-a-proposal"
    assert verdict["target"] == str(STATE)
    assert "terraform-state flag" in verdict["message"]

    blob = json.dumps(report)
    for name in STATE_CONTENTS:
        assert name not in blob, name


# -- 6. determinism ------------------------------------------------------------


def test_the_whole_loop_is_byte_deterministic(capsys, tmp_path):
    """Capture then verify, twice, into the same paths: both artifacts and the
    json report body are byte-identical.

    The sidecar is additionally MULTI-LINE, KEY-SORTED and NEWLINE-TERMINATED,
    because the workflow this loop serves is committing a reconciled estate and
    reviewing drift by diff — and a byte-stable single line satisfies
    determinism while being undiffable.
    """
    if degradation_is_honest(capsys):
        return
    out = tmp_path / "snap.json"
    sidecar = Path(provenance.origins_path(out))

    def once() -> tuple[bytes, bytes, str]:
        assert capture(capsys, out)[0] == 0
        code, stdout, _ = invoke(capsys, "verify-policy", GOOD,
                                 "--snapshot", out, "--origins", sidecar,
                                 "--no-config", "--format", "json")
        assert code == 0
        return out.read_bytes(), sidecar.read_bytes(), stdout

    first = once()
    second = once()
    assert first == second

    raw = first[1]
    assert raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    assert raw.count(b"\n") > 1                      # multi-line, so diffable
    text = raw.decode("utf-8")
    assert text == json.dumps(json.loads(text), indent=2, sort_keys=True) + "\n"


# -- 7. the two surfaces agree about the `state` key ---------------------------


def test_the_cli_and_the_gate_agree_about_the_state_key(capsys, tmp_path):
    """CONFIGURED-BUT-NOT-LOADED is the discriminating case, and it is the one
    a reader would most reasonably get wrong in one of the two places.

    Each surface pins its own rule in its own task, in slightly different
    wording, and nothing checks that they match — this is the only test whose
    dependency closure holds both. With a state source configured and FAILING,
    both documents carry their ``state`` key; with nothing configured both omit
    it entirely, and both are byte-identical to the same invocation without the
    flags.

    ``state.sources == []`` — the ledger-less "every configured source failed"
    signal — is asserted where it is reachable: at
    :func:`gcp_grounding.sources.load_current`, which both surfaces call. From
    ``verify-policy`` it is not, because ``--snapshot`` is required and is
    itself a configured source, so a run that got past ``_load_snapshot`` always
    has the primary's own row; what IS asserted there is that the failed source
    contributes no row of its own.
    """
    missing = tmp_path / "not-a-file.tfstate"
    assert not missing.exists()

    # -- the CLI ---------------------------------------------------------------
    code, report, stderr = ground(capsys, LEGACY, "--terraform-state", missing)
    assert code == 0
    assert "state" in report
    rows = report["state"]["sources"]
    assert [row["source"] for row in rows] == [str(LEGACY)]
    assert str(missing) not in {row["source"] for row in rows}
    assert any(v["kind"] == "state:source" and v["target"] == str(missing)
               for v in report["verdicts"])
    assert "contributed nothing" in stderr

    plain_code, plain_out, _ = invoke(capsys, "verify-policy", GOOD,
                                      "--snapshot", LEGACY, "--no-config",
                                      "--format", "json")
    knobs_code, knobs_out, _ = invoke(
        capsys, "verify-policy", GOOD, "--snapshot", LEGACY, "--no-config",
        "--format", "json", "--precedence", "api-wins",
        "--drift-policy", "annotate", "--max-age", "off")
    assert (plain_code, plain_out) == (knobs_code, knobs_out)
    assert "state" not in json.loads(plain_out)

    # -- the gate --------------------------------------------------------------
    configured = gate.PolicyGroundingGate(
        LEGACY, options=sources.SourceOptions(terraform_state=(str(missing),)),
        resolve_sources=True)
    document = configured.check([GOOD]).to_dict()
    assert "state" in document
    assert {row["row"] for row in document["state"]} == {"sources"}
    assert str(missing) not in {row.get("source") for row in document["state"]}
    for entry in document["files"]:
        assert "state" in entry

    off = gate.PolicyGroundingGate(LEGACY).check([GOOD]).to_dict()
    empty = gate.PolicyGroundingGate(
        LEGACY, options=sources.SourceOptions()).check([GOOD]).to_dict()
    assert "state" not in off and "state" not in empty
    assert all("state" not in entry for entry in off["files"])
    assert json.dumps(off, sort_keys=True) == json.dumps(empty, sort_keys=True)

    # -- and the empty-sources signal, where it is reachable -------------------
    options = sources.SourceOptions(terraform_state=(str(missing),),
                                    now=NOW)
    state = sources.load_current(options)
    assert state.snapshot is None and state.ledger is None
    assert [note.kind for note in state.notes] == ["state:source"]
    settings = discovery.resolve_settings(cli=options, env={})
    assert explain_state.state_document(None, state.ledger,
                                        settings)["sources"] == []
    # The clock the whole module measures against really is the pinned one.
    assert freshness.resolve_now().isoformat().startswith("2024-01-01T06:00")
