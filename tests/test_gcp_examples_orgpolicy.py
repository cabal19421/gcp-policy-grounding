"""Scenario five — the org-policy rollback — pinned in-process.

``examples/terraform-orgpolicy/`` is the README's fifth scenario and its widest:
``cmm_demo.md`` is an ELEVEN-promise corpus whose ids are catalogue names,
``snapshot.json`` is the captured estate, ``terraform.tfstate`` is the applied
state the proposals are judged against, ``base.tf.json`` restates that estate
compliantly, and each ``proposal_*.tf.json`` is that base with exactly one
rollback in it. Eight at-a-glance rows (``5`` and ``5a``–``5g``) ride on it —
one third of the whole table.

Until this module existed, seven of those eight were checked by ``run_demo.sh``
and by no test at all: the suite ran three arcs end to end (``3c``, ``4``, ``w``)
and reached this directory only through two ``--explain`` sentence pins on one of
its files. So README claims like row 5's "APPROVED — all eleven promises hold"
and row 5c's "DENIED — ``vpc-externally-peered-vpc-gcp`` +
``compute-disable-internet-neg`` VIOLATED" were asserted nowhere in the suite,
and a promise renamed on one side of that join would not have reddened anything.

What is pinned, in the shape of its sibling ``test_gcp_examples_*`` modules:

* the FIXTURES — each proposal is ``base.tf.json`` plus EXACTLY the blocks its
  row says it changes, so the story cannot drift from the committed files, and
  the corpus declares exactly the eleven ids;
* the JOIN to the README — the at-a-glance table is read here, and each row's
  documented verdict and every identifier its Expect cell names (promise ids and
  built-in ``[check_kind]``s alike) are asserted against that row's actual run.
  The table is the source of truth: rename a promise in the page without
  renaming it in the corpus and this module fails;
* the VIOLATED SET, exactly — a row that denies must deny on the promises its
  cell names and no others, which is what makes "two promises VIOLATED" a
  statement rather than a lower bound;
* CLOCK INDEPENDENCE — every row's exit is re-measured at a stated later clock,
  past the snapshot's freshness ceiling. That is why this scenario's README
  commands pin no clock while scenarios four and six pin theirs: here the
  estate reads are not what decides, so a reader running the page months after
  the fixtures were captured still gets the documented exits (with a loud
  ``? [staleness]`` beside them).

The promise verdicts ride the solver, so the rows are skipped without z3 rather
than asserted over a rule set that could not be admitted.
"""

import json
import os
import re
from copy import deepcopy
from pathlib import Path

import pytest

from gcp_grounding.cli import main
from gcp_grounding.core.solver import get_solver

REPO_ROOT = Path(__file__).resolve().parent.parent
README = REPO_ROOT / "README.md"
EXAMPLE = REPO_ROOT / "examples" / "terraform-orgpolicy"
BASE = EXAMPLE / "base.tf.json"
SNAPSHOT = EXAMPLE / "snapshot.json"
STATE = EXAMPLE / "terraform.tfstate"
CORPUS = EXAMPLE / "cmm_demo.md"

#: The clock the suite pins session-wide, restated because these runs must not
#: be decided by the calendar; :data:`LATER` is the same runs read well past the
#: snapshot's ceiling, which is what a reader of the page gets today.
PINNED_NOW = "2026-07-18T12:00:00Z"
LATER = "2026-09-01T12:00:00Z"

#: The eleven catalogue-named promises the corpus declares.
PROMISES = (
    "cloudrun-ingress-non-public",
    "compute-disable-internet-neg",
    "compute-disable-serialport-access",
    "deny-admin-roles",
    "egress-firewall-policy-high-strength-vpc-firewall",
    "iam-deny-service-account-impersonation",
    "public-access-prevention",
    "run-allowed-ingress-internal-loadbalancing",
    "security-contact-gcp",
    "vm-public-ip-gcp",
    "vpc-externally-peered-vpc-gcp",
)

#: label -> the (resource type, block) addresses that row's proposal changes or
#: adds relative to the base. Everything else in the file must be byte-equal to
#: the base, which is what keeps each row a single-variable experiment.
EDITS = {
    "5": (),
    "5a": (("google_org_policy_policy", "serial_port_disabled"),
           ("google_org_policy_policy", "vm_no_external_ip")),
    "5b": (("google_org_policy_policy", "run_ingress_internal"),),
    "5c": (("google_org_policy_policy", "neg_no_internet"),
           ("google_org_policy_policy", "vpc_peering_internal")),
    "5d": (("google_org_policy_policy", "security_contacts"),
           ("google_org_policy_policy", "storage_no_public")),
    "5e": (("google_project_iam_binding", "ci_impersonation"),
           ("google_project_iam_binding", "contractor_owner")),
    "5f": (("google_compute_firewall", "egress_vendor_sync"),),
    "5g": (("google_org_policy_policy", "run_ingress_internal"),),
}

#: A `| label | scenario | proposal | expect |` row of the at-a-glance table.
ROW = re.compile(r"^\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|\s*$")

HAVE_Z3 = get_solver().backend == "z3"

_needs_z3 = pytest.mark.skipif(
    not HAVE_Z3, reason="no z3: no rule is admitted on the builtin backend, so "
                        "no holds/VIOLATED line can pin")


def _load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def readme_rows():
    """The at-a-glance rows this scenario owns: ``{label: (proposal, expect)}``,
    parsed from the page so the page stays the source of truth."""
    rows, started = {}, False
    for line in README.read_text(encoding="utf-8").splitlines():
        if line.startswith("### The scenarios at a glance"):
            started = True
            continue
        if not started:
            continue
        cells = ROW.match(line)
        if cells is None:
            if rows:
                break
            continue
        label, proposal, expect = (cells.group(n).strip() for n in (1, 3, 4))
        if label.startswith("5"):
            rows[label] = (proposal.replace("`", "").strip(), expect)
    return rows


ROWS = sorted(EDITS)


def named_identifiers(expect: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """What an Expect cell names in backticks, split into the promise ids of
    this corpus and everything else — a built-in ``[check_kind]``, an attribute
    name, whatever a future row quotes. The ids are compared to the run's
    VIOLATED set; the rest only has to appear in the run's output."""
    quoted = re.findall(r"`([^`]+)`", expect)
    promises = tuple(q for q in quoted if q in PROMISES)
    return promises, tuple(q for q in quoted if q not in PROMISES)


@pytest.fixture(autouse=True)
def _pinned_env(monkeypatch):
    """No inherited grounding configuration, and a stated clock: every input
    this scenario uses is named by a flag on its own command line."""
    for name in list(os.environ):
        if name.startswith("GCP_GROUNDING"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GCP_GROUNDING_NOW", PINNED_NOW)


def invoke(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    out, err = capsys.readouterr()
    return code, out, err


@pytest.fixture
def compiled(tmp_path, capsys):
    """The scenario's eleven-promise corpus, compiled as README step 11 does.
    Exit 0: every promise grounds and admits."""
    out = tmp_path / "compiled-orgpolicy"
    assert main(["compile-requirements", str(EXAMPLE), "--snapshot",
                 str(SNAPSHOT), "--out", str(out)]) == 0
    capsys.readouterr()
    return out


def _verify(capsys, proposal: str, compiled) -> tuple[int, str, str]:
    """README step 11's invocation, which is also the runner's arc."""
    return invoke(capsys, "verify-policy",
                  "--proposal", str(EXAMPLE / proposal),
                  "--snapshot", str(SNAPSHOT),
                  "--terraform-state", str(STATE),
                  "--requirements", str(compiled),
                  "--explain")


# -- the fixtures themselves ---------------------------------------------------


def test_the_corpus_declares_exactly_the_eleven_catalogue_promises():
    text = CORPUS.read_text(encoding="utf-8")
    declared = tuple(sorted(re.findall(r"^id: (\S+)", text, re.M)))
    assert declared == PROMISES
    assert len(declared) == 11, "the row says eleven; the corpus must say eleven"


@pytest.mark.parametrize("label", ROWS)
def test_each_proposal_is_the_base_plus_exactly_its_stated_edit(label):
    proposal, _expect = readme_rows()[label]
    document = _load(REPO_ROOT / proposal)
    base = _load(BASE)
    if label == "5":
        assert document == base, "row 5 IS the base"
        return

    changed = set()
    for rtype in set(base["resource"]) | set(document["resource"]):
        mine = base["resource"].get(rtype, {})
        theirs = document["resource"].get(rtype, {})
        for block in set(mine) | set(theirs):
            if mine.get(block) != theirs.get(block):
                changed.add((rtype, block))
    assert changed == set(EDITS[label]), (
        f"{proposal} must differ from base.tf.json in exactly "
        f"{sorted(EDITS[label])} — nothing more, nothing less")

    # And the rest of the document is the base's, byte for byte in structure:
    # a second edit smuggled into an untouched block would make the row's story
    # a story about two things.
    trimmed, expected = deepcopy(document), deepcopy(base)
    for rtype, block in changed:
        trimmed["resource"].get(rtype, {}).pop(block, None)
        expected["resource"].get(rtype, {}).pop(block, None)
    assert trimmed == expected


def test_the_example_ships_no_config_file_or_origins_sidecar():
    """The documented route names the state file by flag. A config file or an
    origins sidecar here would be auto-discovered and change what every one of
    these eight rows is judged against."""
    assert not (EXAMPLE / ".gcp-grounding.json").exists()
    assert not list(EXAMPLE.glob("*.origins.json"))


# -- the join to the at-a-glance table -----------------------------------------


def test_the_table_names_these_eight_rows_and_their_proposals():
    rows = readme_rows()
    assert sorted(rows) == ROWS, "this module and the table must cover the same rows"
    for label, (proposal, _expect) in rows.items():
        assert proposal.startswith("examples/terraform-orgpolicy/"), proposal
        assert (REPO_ROOT / proposal).is_file(), proposal
        assert Path(proposal).name in {"base.tf.json"} | {
            p.name for p in EXAMPLE.glob("proposal_*.tf.json")}, label


@_needs_z3
@pytest.mark.parametrize("label", ROWS)
def test_each_row_decides_what_the_readme_says_it_decides(label, compiled,
                                                          capsys):
    """Every 5* row's documented verdict, and every identifier its Expect cell
    names, against the run the runner's arc performs."""
    proposal, expect = readme_rows()[label]
    promises, others = named_identifiers(expect)
    denied = expect.startswith("DENIED")

    code, out, err = _verify(capsys, Path(proposal).name, compiled)
    assert code == (1 if denied else 0), out + err
    assert ("FAILED" if denied else "PASSED") in out
    assert f"decision: {'DENIED (exit 1)' if denied else 'APPROVED (exit 0)'}" \
        in err
    assert "promises in force (11 enforcing, 0 not" in err

    violated = set(re.findall(r"^  VIOLATED  (\S+)", err, re.M))
    holding = set(re.findall(r"^  holds     (\S+)", err, re.M))
    assert violated | holding == set(PROMISES), \
        "all eleven promises are judged, every row, every time"
    if denied:
        assert violated == set(promises), (
            "a row denies on the promises its Expect cell names and no others")
    else:
        assert violated == set(), expect
        assert holding == set(PROMISES), "all eleven hold"
    for named in others:
        assert named in out, f"{label}'s Expect cell names {named}"


@_needs_z3
@pytest.mark.parametrize("label", ROWS)
def test_each_row_decides_the_same_past_the_freshness_ceiling(label, compiled,
                                                             capsys,
                                                             monkeypatch):
    """Why this scenario's README commands pin no clock: read a month after the
    fixtures were captured, every row still exits as the page documents — the
    rollbacks are refuted out of the proposal's own content — and the ceiling
    says out loud that the snapshot is stale."""
    monkeypatch.setenv("GCP_GROUNDING_NOW", LATER)
    proposal, expect = readme_rows()[label]
    code, out, err = _verify(capsys, Path(proposal).name, compiled)
    assert code == (1 if expect.startswith("DENIED") else 0), out + err
    assert "? [staleness]" in out, "the stale capture is named, never hidden"
