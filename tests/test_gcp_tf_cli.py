"""``gcp-ground capture-terraform``: the subcommand that turns terraform
artifacts into a snapshot plus the sidecar that says the snapshot is partial.

Driven entirely IN PROCESS through :func:`gcp_grounding.cli.main` with ``capsys``
and ``tmp_path`` — no subprocess, so the session-wide spawn budget is untouched
and every assertion reads the real stdout/stderr the operator sees.

Environment-honest like the rest of the suite: the capture pipeline's
availability is a module-level boolean and the tests BRANCH on it rather than
skipping, so a checkout without ``gcp_grounding.estate`` is asserted to degrade
honestly instead of quietly reporting nothing.
"""

import importlib.util
import json
from pathlib import Path

from gcp_grounding import provenance
from gcp_grounding.cli import main
from gcp_grounding.knowledge import UNKNOWN, GcpSnapshot

FIXTURES = Path(__file__).parent / "fixtures" / "gcp"
TF = FIXTURES / "tf"
POLICIES = FIXTURES / "policies"
SNAPSHOT = FIXTURES / "snapshot.json"

GOOD = POLICIES / "iam_policy_good.json"
BAD = POLICIES / "iam_policy_bad.json"

#: The two secrets planted in the terraform fixtures. A capture that leaks
#: either one into a durable artifact — or onto a terminal — has broken the
#: redaction boundary, and the check is on the BYTES, not on a parsed value.
SECRETS = ("FIXTURE-SECRET-DO-NOT-LEAK", "FIXTURE-SECRET-BY-NAME")

#: A pinned stamp, so two captures of unchanged inputs are comparable and no
#: assertion here can drift with the wall clock.
STAMP = "2024-01-01T00:00:00Z"

#: The capture pipeline reaches ``estate`` and the ``tfsource`` readers, both
#: resolved LAZILY inside the handler. Probed by spec — a bare name check reads
#: True from an already-imported parent package, which is the wrong question.
HAVE_CAPTURE = (
    importlib.util.find_spec("gcp_grounding.estate") is not None
    and importlib.util.find_spec("gcp_grounding.tfsource.discover") is not None)


def invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = main([str(arg) for arg in argv])
    out, err = capsys.readouterr()
    return code, out, err


def capture_run(capsys, *argv, out=None) -> tuple[int, str, str]:
    """``capture-terraform`` with the clock pinned, which every durable-output
    assertion needs."""
    argv = ["capture-terraform", *argv, "--captured-at", STAMP]
    if out is not None:
        argv += ["--out", str(out)]
    return invoke(capsys, *argv)


def mixed_tree(tmp_path) -> tuple[Path, Path, Path]:
    """A directory holding ONE tfstate and ONE HCL file — the two-source shape
    a ``--source`` restriction has something to exclude from."""
    root = tmp_path / "mixed"
    root.mkdir()
    state = root / "estate.tfstate"
    state.write_bytes((TF / "estate.tfstate").read_bytes())
    hcl = root / "main.tf"
    hcl.write_bytes((TF / "hcl" / "main.tf").read_bytes())
    return root, state, hcl


def degradation_is_honest(capsys) -> bool:
    """True when the capture pipeline is not part of this checkout — asserting
    the honest degradation on the way past, rather than skipping.

    The lazy import is behind ``ImportError`` precisely so a checkout without the
    readers SAYS SO instead of tracebacking; an absent capability that is merely
    skipped is a capability nobody ever checks degrades correctly.
    """
    if HAVE_CAPTURE:
        return False
    code, _, err = invoke(capsys, "capture-terraform", str(TF))
    assert code == 2
    assert "not part of this checkout" in err and "nothing was captured" in err
    return True


# -- the happy path: two files, loadable, and honest about being partial -------


def test_capture_writes_both_files_and_exits_zero(capsys, tmp_path):
    """THE HEADLINE. A capture over the terraform fixtures writes the snapshot
    AND its sidecar, exits 0 even though every category is partial, and both
    files load back through their own strict readers.

    ``require_complete`` refuses every emitted category, which is the whole
    point of shipping the sidecar: a terraform view may not license an absence.
    """
    if degradation_is_honest(capsys):
        return
    out = tmp_path / "terraform-snapshot.json"
    code, stdout, _ = capture_run(capsys, TF, out=out)
    # PARTIAL IS NOT A FAILURE: 0 is the exit code for a written snapshot.
    assert code == 0
    sidecar = Path(provenance.origins_path(out))
    assert out.exists() and sidecar.exists()
    assert str(out) in stdout and str(sidecar) in stdout
    # The one line saying the sidecar is not optional.
    assert "MUST TRAVEL WITH THE SNAPSHOT" in stdout

    snapshot = GcpSnapshot.load(out)
    ledger = provenance.SourceLedger.load(sidecar)
    assert snapshot.captured_at == STAMP
    assert snapshot.captured_categories()  # something was actually captured

    partial_named = False
    for category in snapshot.captured_categories():
        scope = ledger.scope_of(category)
        assert scope.scope == "partial", category
        assert scope.existence_licensed is False, category
        refusal = provenance.require_complete(ledger, category)
        # NEVER None: an absence inside a terraform capture is not an absence.
        assert refusal is not None, category
        partial_named = partial_named or "partial coverage" in refusal
    # At least one category refuses on the SCOPE arm naming 'partial'. Not all
    # of them do: firewall_rules refuses one step earlier, on its known holes
    # (the fixtures carry interpolated rules that drop_unresolved kills), and
    # that arm is strictly more specific about the same refusal.
    assert partial_named


def test_two_captures_of_unchanged_inputs_are_byte_identical(capsys, tmp_path):
    """Deterministic writers, end to end: both files diff clean across runs, so
    a committed capture only ever changes when the estate did."""
    if degradation_is_honest(capsys):
        return
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    assert capture_run(capsys, TF, out=first)[0] == 0
    assert capture_run(capsys, TF, out=second)[0] == 0
    assert first.read_bytes() == second.read_bytes()
    assert Path(provenance.origins_path(first)).read_bytes() == \
        Path(provenance.origins_path(second)).read_bytes()


def test_no_fixture_secret_reaches_a_file_or_a_terminal(capsys, tmp_path):
    """The redaction boundary, asserted on BYTES in both formats.

    Neither planted secret may appear in the snapshot, in the sidecar, on stdout
    or on stderr — a value that is masked in one rendering and printed in
    another is not masked.
    """
    if degradation_is_honest(capsys):
        return
    for fmt in ("text", "json"):
        out = tmp_path / f"snap-{fmt}.json"
        code, stdout, stderr = capture_run(capsys, TF, "--format", fmt, out=out)
        assert code == 0, fmt
        payloads = (out.read_bytes(),
                    Path(provenance.origins_path(out)).read_bytes(),
                    stdout.encode("utf-8"), stderr.encode("utf-8"))
        for secret in SECRETS:
            for payload in payloads:
                assert secret.encode("utf-8") not in payload, (fmt, secret)


def test_the_json_format_prints_a_parseable_ledger_document(capsys, tmp_path):
    """``--format json`` puts the LEDGER on stdout and the human lines on
    stderr, so the summary is pipeable while the two files stay durable."""
    if degradation_is_honest(capsys):
        return
    out = tmp_path / "snap.json"
    code, stdout, stderr = capture_run(capsys, TF, "--format", "json", out=out)
    assert code == 0
    document = json.loads(stdout)
    assert document["schema"] == provenance.SCHEMA
    assert document["sources"] and document["categories"]
    # Round-trips through the strict reader, so what was printed is a real
    # ledger and not a lookalike.
    assert provenance.SourceLedger.from_dict(document).declared_categories()
    # The human block moved out of the way rather than disappearing.
    assert "PARTIAL, terraform-managed-only" in stderr


def test_origins_out_relocates_the_sidecar_and_still_writes_two_files(
        capsys, tmp_path):
    """``--origins-out`` names the sidecar; the count stays exactly two."""
    if degradation_is_honest(capsys):
        return
    out = tmp_path / "snap.json"
    side = tmp_path / "elsewhere.origins.json"
    code, stdout, _ = capture_run(capsys, TF, "--origins-out", side, out=out)
    assert code == 0
    assert str(side) in stdout
    assert sorted(p.name for p in tmp_path.iterdir()) == \
        ["elsewhere.origins.json", "snap.json"]
    assert provenance.SourceLedger.load(side).sources


def test_out_defaults_to_a_snapshot_in_the_current_directory(
        capsys, tmp_path, monkeypatch):
    """The default pair lands in the cwd, sidecar included."""
    if degradation_is_honest(capsys):
        return
    monkeypatch.chdir(tmp_path)
    code, _, _ = capture_run(capsys, TF)
    assert code == 0
    assert sorted(p.name for p in tmp_path.iterdir()) == \
        ["terraform-snapshot.json", "terraform-snapshot.origins.json"]


# -- restricting the sources ---------------------------------------------------


def test_a_source_restriction_still_names_the_excluded_artifact(capsys, tmp_path):
    """PRECEDENCE NEVER SUPPRESSES A FINDING, in the one place a capture could
    violate it.

    ``--source tfstate`` drops the HCL file BEFORE ``merge.resolve`` sees it, so
    no dispute can ever be computed for what it removed. The artifact is
    therefore still discovered, still classified, and named both in the summary
    and in the sidecar — dropped by CONFIGURATION, not absent from disk.
    """
    if degradation_is_honest(capsys):
        return
    root, _state, hcl = mixed_tree(tmp_path)
    out = tmp_path / "snap.json"
    code, stdout, _ = capture_run(capsys, root, "--source", "tfstate", out=out)
    assert code == 0
    assert "EXCLUDED" in stdout and str(hcl) in stdout

    ledger = provenance.SourceLedger.load(provenance.origins_path(out))
    excluded = ledger.sources[str(hcl)]
    assert excluded.kind == "hcl"
    assert excluded.scope == "uncaptured"
    assert "EXCLUDED" in excluded.note and "--source" in excluded.note
    # And it survives into the rendered coverage table the operator reads.
    assert str(hcl) in provenance.summarize(ledger)


def test_no_hcl_is_the_shorthand_and_contradicting_it_is_a_usage_error(
        capsys, tmp_path):
    """``--no-hcl`` drops the configuration reader; asking for it and dropping
    it in one command line is a usage error rather than a guess."""
    if degradation_is_honest(capsys):
        return
    root, _state, hcl = mixed_tree(tmp_path)
    out = tmp_path / "snap.json"
    code, stdout, _ = capture_run(capsys, root, "--no-hcl", out=out)
    assert code == 0
    assert str(hcl) in stdout and "EXCLUDED" in stdout

    code, _, err = capture_run(capsys, root, "--source", "hcl", "--no-hcl",
                               out=out)
    assert code == 2
    assert "--source hcl and --no-hcl" in err


# -- --include: opting a category into existence licensing ---------------------


def test_include_warns_loudly_about_the_ungrounded_consequence(capsys, tmp_path):
    """``--include networks`` earns the LOUD stderr warning, before anything is
    written, naming the consequence in full — including the word the operator
    will actually see in a report: ``ungrounded``.

    The category is declared in the sidecar either way. It stays UNCAPTURED over
    this corpus because no mapper in this checkout builds a ``networks`` fact
    (``google_compute_network`` lands in the unrecognized-type census), and
    NEVER EMIT AN EMPTY CATEGORY is what keeps that honest: an emitted empty
    table would answer False for every network in the estate.
    """
    if degradation_is_honest(capsys):
        return
    out = tmp_path / "snap.json"
    code, _, err = capture_run(capsys, TF, "--include", "networks", out=out)
    assert code == 0
    assert "WARNING" in err and "networks" in err
    assert "ungrounded" in err
    ledger = provenance.SourceLedger.load(provenance.origins_path(out))
    assert "networks" in ledger.declared_categories()
    assert ledger.scope_of("networks").emitted is False


def test_an_included_category_populates_while_an_omitted_one_stays_unknown(
        capsys, tmp_path):
    """The other half of the opt-in: a licensed category that terraform DOES
    manage is populated and answers concretely, and a category nobody included
    answers UNKNOWN rather than False.

    ``service_accounts`` is the category this corpus can actually fill —
    ``google_service_account`` has a mapper — so it is what measures "populates"
    here; ``networks`` measures the omitted side.
    """
    if degradation_is_honest(capsys):
        return
    plain = tmp_path / "plain.json"
    assert capture_run(capsys, TF, out=plain)[0] == 0
    bare = GcpSnapshot.load(plain)
    assert bare.service_accounts is None
    assert bare.service_account_exists("etl-runner@acme-prod.iam."
                                       "gserviceaccount.com") is UNKNOWN
    # The omitted network category answers UNKNOWN, not False.
    assert bare.network_exists("projects/acme-prod/global/networks/prod-vpc") \
        is UNKNOWN

    opted = tmp_path / "opted.json"
    code, _, err = capture_run(capsys, TF, "--include", "service_accounts",
                               out=opted)
    assert code == 0
    assert "ungrounded" in err  # the same loud warning, for the same reason
    snapshot = GcpSnapshot.load(opted)
    assert snapshot.service_accounts  # POPULATED, not omitted
    name = sorted(snapshot.service_accounts)[0]
    assert snapshot.service_account_exists(name) is True
    # THE COST OF THE LICENCE, made concrete: a name terraform does not manage
    # now answers False instead of UNKNOWN.
    assert snapshot.service_account_exists("clickops@acme-prod.iam."
                                           "gserviceaccount.com") is False
    # Still uncaptured for networks, which nobody asked for.
    assert snapshot.network_exists("projects/acme-prod/global/networks/"
                                   "prod-vpc") is UNKNOWN


def test_an_unknown_include_category_is_a_usage_error(capsys, tmp_path):
    """Exit 2, naming every valid category, and no file written."""
    if degradation_is_honest(capsys):
        return
    out = tmp_path / "snap.json"
    code, _, err = capture_run(capsys, TF, "--include", "netwroks", out=out)
    assert code == 2
    assert "netwroks" in err
    for category in ("networks", "firewall_rules", "iam_bindings",
                     "org_policies", "service_accounts"):
        assert category in err
    assert not out.exists()


# -- --dry-run -----------------------------------------------------------------


def test_dry_run_writes_nothing_and_still_prints_the_summary(capsys, tmp_path):
    """Exactly what WOULD be written, and nothing on disk."""
    if degradation_is_honest(capsys):
        return
    out = tmp_path / "snap.json"
    code, stdout, _ = capture_run(capsys, TF, "--dry-run", out=out)
    assert code == 0
    assert list(tmp_path.iterdir()) == []
    assert "--dry-run" in stdout and "NOTHING was written" in stdout
    # The full summary is still there: the artifact table, the coverage rows,
    # the unrecognized-type census and the dispute rows.
    assert "source coverage" in stdout
    assert "artifacts:" in stdout and str(TF / "estate.tfstate") in stdout
    assert "unrecognized terraform types:" in stdout
    assert "disputes:" in stdout


# -- the empty-capture path ----------------------------------------------------


def test_an_empty_directory_exits_one_and_writes_nothing(capsys, tmp_path):
    """Nothing captured is exit 1 — never 2, which is Claude Code's blocking
    code — with the examined paths named and the coverage summary still
    printed."""
    if degradation_is_honest(capsys):
        return
    empty = tmp_path / "empty"
    empty.mkdir()
    out = tmp_path / "snap.json"
    code, stdout, _ = capture_run(capsys, empty, out=out)
    assert code == 1
    assert not out.exists()
    assert not Path(provenance.origins_path(out)).exists()
    assert "NOTHING was captured" in stdout
    assert "paths examined" in stdout and str(empty) in stdout
    # THE SUMMARY IS PRINTED ANYWAY: every category is uncaptured, and saying so
    # is the difference between "nothing to report" and "nothing is covered".
    assert "source coverage" in stdout
    assert "uncaptured" in stdout


def test_a_policy_document_is_not_a_terraform_artifact(capsys, tmp_path):
    """A directory holding only an IAM policy captures NOTHING from it, exits 1,
    and says why the candidate was rejected — a proposal document belongs on the
    other side of the gate."""
    if degradation_is_honest(capsys):
        return
    root = tmp_path / "policies"
    root.mkdir()
    policy = root / "iam_policy_good.json"
    policy.write_bytes(GOOD.read_bytes())
    out = tmp_path / "snap.json"
    code, stdout, _ = capture_run(capsys, root, out=out)
    assert code == 1
    assert not out.exists()
    assert f"rejected {policy}" in stdout
    assert "no terraform artifact arm matched its content" in stdout


# -- --captured-at and --max-age -----------------------------------------------


def test_a_captured_at_that_is_not_a_date_is_a_usage_error(capsys, tmp_path):
    if degradation_is_honest(capsys):
        return
    out = tmp_path / "snap.json"
    code, _, err = invoke(capsys, "capture-terraform", str(TF), "--out",
                          str(out), "--captured-at", "last tuesday")
    assert code == 2
    assert "--captured-at" in err and "ISO-8601" in err
    assert not out.exists()


def test_without_captured_at_the_stamp_is_an_artifact_mtime_and_says_so(
        capsys, tmp_path):
    """No ``--captured-at``: the stamp is the oldest contributing artifact's
    file modification time, and the human output says that on its own line so
    nobody reads it as an estate capture time."""
    if degradation_is_honest(capsys):
        return
    out = tmp_path / "snap.json"
    code, stdout, _ = invoke(capsys, "capture-terraform", str(TF),
                             "--out", str(out))
    assert code == 0
    assert "FILE MODIFICATION TIME" in stdout
    assert "not an estate capture time" in stdout
    assert GcpSnapshot.load(out).captured_at != STAMP


def test_max_age_reports_staleness_and_never_changes_the_exit_code(
        capsys, tmp_path, monkeypatch):
    """``--max-age`` is ADVISORY here: the message fires, the files are written
    and the exit code stays 0. Grounding is where staleness must abstain."""
    if degradation_is_honest(capsys):
        return
    monkeypatch.delenv("GCP_GROUNDING_NOW", raising=False)
    out = tmp_path / "snap.json"
    code, stdout, _ = capture_run(capsys, TF, "--max-age", "0s", out=out)
    assert code == 0
    assert out.exists() and Path(provenance.origins_path(out)).exists()
    assert "STALE" in stdout
    assert "ADVISORY" in stdout and "verify-policy" in stdout


# -- verify-policy is untouched ------------------------------------------------


def test_verify_policy_behaviour_is_unchanged(capsys):
    """The other subcommand's contract, asserted from this module too: adding
    ``capture-terraform`` moved no exit code and no output on the path operators
    actually run."""
    code, out, _ = invoke(capsys, "verify-policy", str(GOOD),
                          "--snapshot", str(SNAPSHOT))
    assert code == 0 and "PASSED" in out
    code, out, _ = invoke(capsys, "verify-policy", str(BAD),
                          "--snapshot", str(SNAPSHOT))
    assert code == 1 and "FAILED" in out
    assert "roles/bigquery.reader" in out
