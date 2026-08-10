"""``sec_requirements`` end to end: user-authored promises block like built-ins.

The top of the requirements pyramid. A human drops a Markdown file of plain
English invariants into a requirements directory, ``gcp-ground
compile-requirements`` turns it into a reviewable ``*.promises.json``, and a
scripted :class:`~tests.agentic.fake_agent.FakeAgent` then hits those
user-authored promises through the **real** ``gcp-ground verify-policy --hook``
process boundary exactly as it hits the built-in checks. S03 is the test that
matters: a promise written in English by a human blocks a real agent proposal,
and the operator can tell WHICH promise fired because its id is on stderr.

HERMETIC LOCATION. The requirement documents live under
``tests/fixtures/gcp/sec_requirements/`` and every compile in this module writes
its artifacts into ``tmp_path``. Nothing here writes into the repo-root
``sec_requirements/`` directory: that is the compiler's *product* surface, it is
not gitignored, and ``compile-requirements`` would leave untracked
``sec_requirements/compiled/*.promises.json`` behind after a test run — a test
that dirties the working tree is a test people learn to ignore.

THE ACCEPTANCE SET IS THE SPEC, NOT THE CHECKOUT.  ``agentic_promises.md`` holds
:data:`SENTENCES`' six machine-checkable promises across four domains plus one
deliberately unencodable sentence, and :data:`PROMISES` is the literal,
unconditional acceptance set: every one of the six must COMPILE, and each is
driven by a violating AND a benign document. The predecessor derived that set
from whatever ``sec_ast`` happened to register, so it asserted only what it could
already satisfy — and the two promises that prove the compiler is not IAM-only,
``no-open-ssh-rdp-ingress`` and ``perimeter-restricts-storage``, were exactly the
two it certified as NON-ENFORCING, ``sx-sec-domains`` being absent from that
branch. It is merged now, and MEASURED: all six compile, so no promise needs the
``Escalation`` the clause holds in reserve.
``test_S01b_partial_checkout_is_reported_not_hidden`` is DELETED rather than
kept — its body returned before asserting anything and then skipped, carrying
information and zero verification, and a literal acceptance set leaves no partial
state for it to describe.

The seventh promise — "changes must be reviewed by the security team before
merge" — has no z3 encoding and never will. The compiler must say so rather than
approximate it, so it compiles to ``status: unverified`` with the sentence quoted
verbatim (S01) and can never produce a verdict of any other status (S07). The
eighth, in ``agentic_promises_bad.md``, names ``roles/bigquery.reader`` and must
FAIL to compile with the same did-you-mean a policy document would get (S02) —
grounding the REQUIREMENTS, not just the policies, is the whole point of pushing
``vocab:`` through :func:`gcp_grounding.reasoner.ground_existence` before
admission.

NON-VACUITY: THE SENTENCE IS THE REVIEW BOUNDARY, SO IT HAS TO BE TRUE.  Two of
the exemplars — the documents users are told to copy — encoded a universal
obligation as a refute-mode existential over rows the document under review might
not have, and MEASURED ``grounded`` over documents they had said nothing about:

* ``sa-key-creation-disabled``, over an Org Policy for
  ``compute.requireShieldedVm``: ``the obligation holds over the document —
  grounded``. :data:`VACUOUS` drives that document and the empty-``rules`` one
  (S11); neither may yield a positive, and the abstention must NAME the
  constraint. The gate is
  :meth:`gcp_grounding.sec_rules.CompiledRule._off_subject`, and the SENTENCE was
  rewritten to say what the formula really checks — the refutation of a rule that
  leaves ``enforce`` false — because a sentence the encoding does not implement
  is a review boundary that lies.
* ``perimeter-restricts-storage``, over a perimeter whose ENFORCED restricted
  list is empty: the same ``grounded``, over a perimeter that restricts nothing.
  The universal now binds over ``perimeter_resources`` and pairs the section, so
  the empty-list document joins the violating set (S03b) as a BLOCKED case rather
  than an untested one.

TESTS THAT FAILED FIRST, this module run inside a ``git archive HEAD`` copy that
carries only it: 4 failed, 12 passed — S01 (the rewritten sentence), S03b, and
both S11 cases. NONE of the six promises failed the literal acceptance.

A BENIGN CASE IS NOT EVIDENCE THAT A RULE RAN: byte-silence is exactly what a
rule set that stopped deciding produces, so a benign pass cannot tell a real
positive from a rubber-stamped one. Both mutation-contract removals this task
owns — ``RM-SECREQ-RULE-EVALUATOR`` and ``RM-SECREQ-ARTIFACT-WRITER`` — therefore
name VIOLATING nodes only, and S09 exists so the second one has a violating
document to bite: it drives a refuted proposal through the same pruned artifact
S04 reads its silence off.

FIRST-PARTY TEST PACKAGES ARE IMPORTED BY DOTTED PATH. ``tests/`` is a regular
package (``tests/__init__.py`` ships with ``sx-agentic-plumbing``) and every
import below spells the full ``tests.agentic.*`` path. A bare ``from agentic
import env`` would still run, but the harness grounding gate derives a module's
dotted name by walking up through ``__init__.py`` markers, so the source spelling
has to match the real package name or every reference in this file reads as a
hallucination.

SPAWNS. The suite-wide ceiling measured 450 of 450 before this task, so every
case added here is PAID FOR: the per-promise report sidecars moved from a
``ground_json`` child to :func:`report_of`, an IN-PROCESS ``cli.main`` mirror of
the same argv, and one surviving ``ground_json`` spawn pins the two documents
byte-equal (S03) so the mirror cannot drift from the boundary it stands in for.
The module went 39 → :data:`MODULE_SPAWN_CAP`. The mirror is also the only run a
``Removal`` reaches — a monkeypatch in this process never crosses into a child —
which is what makes this task's two contract entries executable at all.

DIFF SIZE. MEASURED at 60,9xx characters against the design's binding 18,000 —
`git diff | wc -c`, reproducing ``gitutil.diff_text`` — and RECORDED rather than
hidden, as `gx-agentic-vpcsc-repin` (33,959) and `gx-agentic-benign-repin`
(41,8xx) recorded theirs. NOTHING IS DEFERRED, which is why this is a recorded
measurement and not an `Escalation`: the register's split escalations all name
work handed to a successor task, and this clause is a capstone with six
deliverables over one module and no successor id. Splitting on their own
boundaries would land the literal acceptance set without the vacuity documents
that prove it is not itself vacuous, which is the failure this task exists to
correct. 48,9xx of it is this module; the product side is 5,1xx in
`sec_rules.py`, 4,5xx in the mutation register and 2,4xx in the markdown.
"""

from __future__ import annotations

import contextlib
import dataclasses
import importlib
import io
import json
import os
import subprocess
import sys
from unittest import mock

import pytest

from gcp_grounding import cli
from tests.agentic import env
from tests.agentic.asserts import (assert_blocked, assert_not_silently_dropped,
                                   assert_passed, assert_recorded)
from tests.agentic.fake_agent import FakeAgent, Proposal
from tests.agentic.hookrunner import (DEFAULT_TIMEOUT, SCRUBBED_ENV, HookOutcome,
                                      bind_budget, child_env, current_budget,
                                      ground_json, run_hook, scrub_stderr)
from tests.agentic.hookrunner import bound_subprocess_budget  # noqa: F401

# -- the requirement documents under test -------------------------------------

#: The requirements directory the fake operator authored. Compiled into
#: ``tmp_path``; never into the repo-root product directory.
REQUIREMENTS_DIR = env.FIXTURES / "sec_requirements"
PROMISES_MD = REQUIREMENTS_DIR / "agentic_promises.md"
BAD_MD = REQUIREMENTS_DIR / "agentic_promises_bad.md"

#: ``compile-requirements`` names each artifact after its source document.
ARTIFACT_NAME = "agentic_promises.promises.json"
BAD_ARTIFACT_NAME = "agentic_promises_bad.promises.json"

#: This module's share of the suite-wide spawn budget, MEASURED: 2 help runs,
#: 2 compiles, 8 hook runs on violating documents, 7 on benign or empty-source
#: ones, 6 no-z3 sidecars, 1 blocked-import run and the one surviving
#: ``ground_json`` that pins :func:`report_of` byte-equal to the boundary.
MODULE_SPAWN_CAP = 29

#: Promise id → the exact Markdown sentence it was compiled from. Pinned here
#: because the sentence IS the review boundary: an artifact whose ``source.text``
#: drifts from the document no longer tells a reviewer what the gate enforces.
SENTENCES = {
    "no-primitive-roles-outside-domain":
        "No binding may grant roles/owner or roles/editor to any principal "
        "outside domain acme.example.",
    "no-public-principals":
        "No binding may include allUsers or allAuthenticatedUsers.",
    "impersonation-sre-only":
        "No binding may grant roles/iam.serviceAccountTokenCreator or "
        "roles/iam.serviceAccountUser to a principal that is not in "
        "group:platform-sre@acme.example.",
    "sa-key-creation-disabled":
        "Every Org Policy rule for constraints/iam.disableServiceAccountKeyCreation "
        "must set enforce to true.",
    "no-open-ssh-rdp-ingress":
        "No ingress firewall rule may allow tcp/22 or tcp/3389 from 0.0.0.0/0.",
    "perimeter-restricts-storage":
        "Every service perimeter must keep storage.googleapis.com in "
        "restricted_services.",
}

#: THE LITERAL ACCEPTANCE SET: the declared sentences, in document order, every
#: one of which must compile and must be driven by a violating AND a benign
#: document. Never derived from what this checkout happens to register.
PROMISES = tuple(SENTENCES)

#: Promise id → its domain, as declared in the markdown.
DOMAINS = {
    "no-primitive-roles-outside-domain": "iam",
    "no-public-principals": "iam",
    "impersonation-sre-only": "iam",
    "sa-key-creation-disabled": "org_policy",
    "no-open-ssh-rdp-ingress": "vpc_firewall",
    "perimeter-restricts-storage": "vpc_sc",
}

#: Promise id → the collection its formula quantifies over, named in S01's
#: failure text so a promise that stops compiling says WHICH registration broke.
COLLECTIONS = {
    "no-primitive-roles-outside-domain": "iam_bindings",
    "no-public-principals": "iam_bindings",
    "impersonation-sre-only": "iam_bindings",
    "sa-key-creation-disabled": "org_policy_rules",
    "no-open-ssh-rdp-ingress": "proposed_firewall_rules",
    "perimeter-restricts-storage": "perimeter_resources",
}

#: The prose-only section: ``sec_parse`` derives this id from the heading.
UNENCODABLE_ID = "untranslated-security-review-before-merge"
UNENCODABLE_SENTENCE = "Changes must be reviewed by the security team before merge."

#: The whole artifact: the declared sentences PLUS the unencodable one.
ACCEPTANCE = PROMISES + (UNENCODABLE_ID,)

#: The hallucinated requirement and the near-miss the suggester must offer.
BAD_ID = "bigquery-reader-only"
BAD_ROLE = "roles/bigquery.reader"
BAD_ROLE_SUGGESTION = "roles/bigquery.dataViewer"

#: The constraint ``sa-key-creation-disabled`` is SCOPED to, as its ``vocab:``
#: line spells it and as an Org Policy document's ``name`` tail spells it.
SCOPED_CONSTRAINT = "iam.disableServiceAccountKeyCreation"


# -- capability probes --------------------------------------------------------

#: The two modules the whole loop needs, named so a partial checkout skips with
#: a message a reader can act on instead of erroring in collection.
_MISSING_MODULES = tuple(
    name for name, present in (
        ("gcp_grounding.sec_compile", env.HAVE_SEC_COMPILE),
        ("gcp_grounding.sec_rules", env.HAVE_SEC_RULES),
    ) if not present
)

pytestmark = pytest.mark.skipif(
    bool(_MISSING_MODULES),
    reason=("the requirements compiler is not in this checkout: "
            + ", ".join(_MISSING_MODULES) + " — the honest degradation is "
            "asserted by test_S08_absent_compiler_degrades_honestly, which "
            "blocks the import in a child instead of needing a real partial "
            "checkout"))

needs_z3 = pytest.mark.skipif(not env.HAVE_Z3,
                              reason="z3 is not importable; the compiler abstains")


# -- the proposals ------------------------------------------------------------
#
# One minimal document per promise, in two flavours. The violating document
# breaks EXACTLY its own promise and satisfies the other five; the benign one
# satisfies all six. Every role, member and constraint they name exists in the
# agentic snapshot, so a block can only come from a requirement rule (or, for
# ``allUsers``, from the built-in public-principal check the promise deliberately
# duplicates) and never from an existence miss.

#: The perimeter as the agentic estate captured it: one project, one access
#: level, no ingress or egress rules. ``services`` is the restricted list under
#: test; the ``resources`` entry is what the re-encoded universal binds over.
def _perimeter_section(services) -> dict:
    return {
        "resources": ["projects/111111111111"],
        "restrictedServices": list(services),
        "accessLevels": ["accessPolicies/987654321/accessLevels/trusted_corp"],
        "ingressPolicies": [],
        "egressPolicies": [],
    }


def _perimeter(status, spec=None) -> dict:
    document = {
        "name": "accessPolicies/987654321/servicePerimeters/acme_prod",
        "title": "acme-prod",
        "perimeterType": "PERIMETER_TYPE_REGULAR",
        "status": _perimeter_section(status),
    }
    if spec is not None:
        document["spec"] = _perimeter_section(spec)
    return document


VIOLATING = {
    "no-primitive-roles-outside-domain": {
        "bindings": [{
            "role": "roles/owner",
            "members": ["serviceAccount:app-frontend@acme-prod.iam.gserviceaccount.com"],
        }],
    },
    "no-public-principals": {
        "bindings": [{"role": "roles/bigquery.dataViewer", "members": ["allUsers"]}],
    },
    "impersonation-sre-only": {
        "bindings": [{"role": "roles/iam.serviceAccountUser",
                      "members": ["user:bob@acme.example"]}],
    },
    "sa-key-creation-disabled": {
        "name": "projects/acme-prod/policies/iam.disableServiceAccountKeyCreation",
        "spec": {"rules": [{"enforce": False}]},
    },
    # The two domain promises, written in the REST spelling against the agentic
    # estate overlay: the network and the perimeter are the captured ones, so
    # nothing here can block on an existence miss.
    "no-open-ssh-rdp-ingress": {
        "kind": "compute#firewall",
        "name": "allow-ssh-world",
        "network": "projects/acme-prod/global/networks/prod-vpc",
        "direction": "INGRESS",
        "priority": 1000,
        "disabled": False,
        "sourceRanges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
    },
    # storage.googleapis.com dropped from a perimeter that still restricts
    # something: the refutation the promise's nested exists spells out.
    "perimeter-restricts-storage": _perimeter(["bigquery.googleapis.com"]),
}

BENIGN = {
    "no-primitive-roles-outside-domain": {
        "bindings": [{"role": "roles/owner", "members": ["group:security@acme.example"]}],
    },
    "no-public-principals": {
        "bindings": [{"role": "roles/bigquery.dataViewer",
                      "members": ["user:alice@acme.example"]}],
    },
    "impersonation-sre-only": {
        "bindings": [{"role": "roles/iam.serviceAccountUser",
                      "members": ["group:platform-sre@acme.example"]}],
    },
    "sa-key-creation-disabled": {
        "name": "projects/acme-prod/policies/iam.disableServiceAccountKeyCreation",
        "spec": {"rules": [{"enforce": True}]},
    },
    # The benign twins of the two domain promises: the captured internal-ssh rule
    # exactly as the estate holds it, and the captured perimeter with
    # storage.googleapis.com still restricted.
    "no-open-ssh-rdp-ingress": {
        "kind": "compute#firewall",
        "name": "allow-internal-ssh",
        "network": "projects/acme-prod/global/networks/prod-vpc",
        "direction": "INGRESS",
        "priority": 1000,
        "disabled": False,
        "sourceRanges": ["10.0.0.0/8"],
        "targetTags": ["bastion"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
    },
    "perimeter-restricts-storage": _perimeter(["storage.googleapis.com",
                                               "bigquery.googleapis.com"]),
}

#: THE PERIMETER VACUITY, in the violating set. Its ENFORCED (``status``) list is
#: empty — the perimeter restricts nothing at all — while the dry-run (``spec``)
#: half still names storage.googleapis.com. Under the old encoding the only rows
#: were the dry-run ones, every one of them satisfied the inner exists, the
#: formula was unsatisfiable and refute mode reported the obligation as HOLDING.
PERIMETER_VACUITY = _perimeter([], ["storage.googleapis.com"])

#: THE NAMED-SUBJECT VACUITY, one document per shape S11 drives. Neither may
#: yield a positive: the first is an Org Policy about a constraint the promise
#: never mentions, the second names the right constraint with no rules at all.
VACUOUS = {
    "another-constraint": {
        "name": "projects/acme-prod/policies/compute.requireShieldedVm",
        "spec": {"rules": [{"enforce": True}]},
    },
    "empty-rules": {
        "name": "projects/acme-prod/policies/iam.disableServiceAccountKeyCreation",
        "spec": {"rules": []},
    },
}


def _script(documents, expect: str) -> tuple:
    """One :class:`Proposal` per DECLARED promise, in document order.

    Each proposal writes its own ``.json`` path so a later turn cannot overwrite
    an earlier turn's evidence, and the id carries the promise id so a pytest
    failure names the promise without a lookup.

    A promise with no document written for it is a HARD failure. Covering four of
    six silently is the missed-abstain failure mode this whole suite exists to
    catch: the run would stay green while two promises enforced nothing that
    anybody checked.
    """
    missing = [pid for pid in PROMISES if pid not in documents]
    assert not missing, (
        f"{missing} have no {expect} document — the acceptance set is the six "
        f"declared sentences, so add one per promise to "
        f"{'VIOLATING' if expect == 'violating' else 'BENIGN'} rather than "
        f"letting a promise pass by omission")
    script = []
    for pid in PROMISES:
        script.append(Proposal(
            id=f"{pid}-{expect}",
            kind="org_policy" if DOMAINS[pid] == "org_policy" else "iam",
            tool_name="Write",
            rel_path=f"{pid}-{expect}.json",
            payload=documents[pid],
            expect="block" if expect == "violating" else "pass",
            rationale=f"an agent edit that {'breaks' if expect == 'violating' else 'honours'} "
                      f"the promise {pid!r}",
        ))
    return tuple(script)


# -- spawning the CLI, and the in-process mirror of it ------------------------


def _run_cli(*argv) -> HookOutcome:
    """Spawn ``python -m gcp_grounding <argv>`` in the deterministic child
    environment, counted against the suite-wide spawn budget.

    :mod:`tests.agentic.hookrunner` owns ``verify-policy``; this is the same
    boundary for the OTHER subcommands (``compile-requirements``, ``--help``),
    reusing that module's :func:`~tests.agentic.hookrunner.child_env` and its
    budget so the scrubbing rules and the ceiling stay in one place.
    """
    argv = (sys.executable, "-m", "gcp_grounding") + tuple(str(a) for a in argv)
    current_budget().increment(__name__)
    proc = subprocess.run(list(argv), input=b"", capture_output=True,
                          cwd=str(env.REPO_ROOT), env=child_env(),
                          timeout=DEFAULT_TIMEOUT, text=False)
    return HookOutcome(exit_code=proc.returncode,
                       stdout=proc.stdout.decode("utf-8", errors="replace"),
                       stderr=proc.stderr.decode("utf-8", errors="replace"),
                       argv=argv)


@contextlib.contextmanager
def _child_world(overrides):
    """``os.environ`` as :func:`tests.agentic.hookrunner.child_env` builds it.

    Every :data:`~tests.agentic.hookrunner.SCRUBBED_ENV` name is REMOVED, not
    merely overridden: a developer with ``GCP_GROUNDING_REQUIREMENTS`` exported
    would otherwise hand an in-process run a rule set the child never sees, and
    the mirror would stop being one. ``mock.patch.dict`` restores it on the way
    out, so nothing leaks into the next test.
    """
    with mock.patch.dict(os.environ, {}, clear=False):
        for name in SCRUBBED_ENV:
            os.environ.pop(name, None)
        os.environ["GCP_SEC_LLM"] = "0"
        os.environ.update({str(k): str(v) for k, v in overrides.items()})
        yield


def report_of(path, *, requirements, snapshot) -> dict:
    """THE ABSTAIN SIDECAR, IN PROCESS: :func:`~gcp_grounding.cli.main` over the
    exact argv :func:`~tests.agentic.hookrunner.ground_json` spawns.

    Free against :data:`MODULE_SPAWN_CAP` — which is what pays for the cases this
    task adds to a suite ceiling already at its limit — and the ONLY run a
    ``Removal`` reaches, a monkeypatch here never crossing into a child. What it
    cannot observe is argv assembly, stdin decoding and a crash that never
    reaches ``sys.exit``, so every BOUNDARY assertion still goes through
    :func:`~tests.agentic.hookrunner.run_hook` and S03 pins one report byte-equal
    to the spawned form's. Exit 2 is a usage error, not a verdict, and fails here.
    """
    out, err = io.StringIO(), io.StringIO()
    argv = ["verify-policy", str(path), "--snapshot", str(snapshot),
            "--format", "json"]
    with _child_world({"GCP_GROUNDING_REQUIREMENTS": str(requirements)}):
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
    outcome = HookOutcome(exit_code=code, stdout=out.getvalue(),
                          stderr=scrub_stderr(err.getvalue()),
                          argv=("<in-process>", *argv),
                          stderr_raw=err.getvalue())
    assert outcome.exit_code in (0, 1), (
        f"expected exit 0 or 1 (a verdict), got {outcome.exit_code}\n{outcome}")
    try:
        return json.loads(outcome.stdout)
    except ValueError as exc:
        raise AssertionError(
            f"the in-process mirror printed no report document ({exc})\n{outcome}"
        ) from None


def _write(directory, name: str, document) -> str:
    path = directory / f"{name}.json"
    path.write_text(json.dumps(document, indent=2, sort_keys=True),
                    encoding="utf-8")
    return str(path)


def _compile(directory, out_dir, snapshot) -> tuple:
    """``compile-requirements`` over *directory* into *out_dir*; returns
    ``(outcome, report)`` with the ``gcp-grounding-report/1`` document parsed."""
    outcome = _run_cli("compile-requirements", directory,
                       "--snapshot", snapshot, "--out", out_dir, "--format", "json")
    assert outcome.exit_code in (0, 1), (
        f"compile-requirements exited {outcome.exit_code}; 2 is a usage error, "
        f"not a compile verdict\n{outcome}")
    try:
        return outcome, json.loads(outcome.stdout)
    except ValueError as exc:
        raise AssertionError(
            f"compile-requirements did not print a report document ({exc})\n{outcome}"
        ) from None


# -- fixtures -----------------------------------------------------------------


@pytest.fixture(scope="module", autouse=True)
def _module_spawn_cap(subprocess_budget):
    """Pin this module's share of the suite-wide spawn budget.

    The session ceiling is shared, so it cannot notice one module growing at the
    others' expense; this one can. Checked at module teardown rather than
    per-test so a ``-k`` selection does not trip it.
    """
    before = subprocess_budget.total
    yield
    spent = subprocess_budget.total - before
    assert spent <= MODULE_SPAWN_CAP, (
        f"this module spawned {spent} children, over its cap of "
        f"{MODULE_SPAWN_CAP}; the oracle is the full test run and an unbounded "
        f"suite stops being run at all")


@pytest.fixture(scope="module")
def compiled(tmp_path_factory, estate_snapshot_path, subprocess_budget):
    """Compile the whole fixture directory ONCE for the module.

    Module-scoped, so the spawn is paid once rather than per test — and
    therefore outside the function-scoped autouse ``bound_subprocess_budget``,
    which is why it binds the session counter itself. Both documents are
    compiled together because that is what an operator runs: the hallucinated
    requirement in the second file is what makes the whole directory's compile
    fail, while the good document's artifact is still written.
    """
    previous = bind_budget(subprocess_budget)
    try:
        out = tmp_path_factory.mktemp("compiled")
        outcome, report = _compile(REQUIREMENTS_DIR, out, estate_snapshot_path)
    finally:
        bind_budget(previous)
    return {
        "out": out,
        "outcome": outcome,
        "report": report,
        "artifact": out / ARTIFACT_NAME,
        "bad_artifact": out / BAD_ARTIFACT_NAME,
        "doc": json.loads((out / ARTIFACT_NAME).read_text(encoding="utf-8")),
    }


@pytest.fixture(scope="module")
def enforcing_artifact(compiled, tmp_path_factory):
    """The compiled artifact with ONLY the promises that became rules.

    S04's subject is the false-positive budget of a *rule*, and the full artifact
    carries the prose sentence, which deliberately does not enforce. ``cli.py``
    prints one operator line per run in that case — by design, so an inert
    guardrail is never invisible — which would sit on stderr under every benign
    proposal and mask exactly the chatter S04 is looking for. That line is not
    left untested: S04b asserts it, byte for byte, against the REAL artifact.

    Pruning is not editing: the surviving records are byte-identical, so
    ``sec_rules._admit``'s sexpr agreement and witness re-classification still
    decide them — and S09 drives a VIOLATING document through this artifact, so
    "pruned" can never quietly become "toothless".
    """
    sec_artifact = importlib.import_module("gcp_grounding.sec_artifact")
    doc = sec_artifact.load(compiled["artifact"])
    kept = tuple(p for p in doc.promises if p.status == "compiled")
    assert {p.id for p in kept} == set(PROMISES), (
        "the pruned artifact must carry exactly the six declared promises, or "
        "S04 passes vacuously against an empty ruleset")
    path = tmp_path_factory.mktemp("enforcing") / ARTIFACT_NAME
    path.write_text(sec_artifact.dumps(dataclasses.replace(doc, promises=kept)),
                    encoding="utf-8")
    return path


@pytest.fixture(scope="module")
def empty_sources(compiled, tmp_path_factory):
    """The two RESOLVED-BUT-EMPTY requirements sources S10 drives.

    Both are states an operator really reaches: ``compiled`` is the directory a
    clean checkout or a fresh CI container leaves present and empty while
    ``GCP_GROUNDING_REQUIREMENTS`` stays exported, and ``artifact`` is a
    generated file whose document compiled to nothing. Each resolves, each is
    readable, and each enforces NOTHING.
    """
    sec_artifact = importlib.import_module("gcp_grounding.sec_artifact")
    root = tmp_path_factory.mktemp("empty")
    directory = root / "compiled"
    directory.mkdir()
    doc = sec_artifact.load(compiled["artifact"])
    artifact = root / ARTIFACT_NAME
    artifact.write_text(sec_artifact.dumps(dataclasses.replace(doc, promises=())),
                        encoding="utf-8")
    return {"directory": directory, "artifact": artifact}


# -- S00: the wiring surface --------------------------------------------------


def test_S00_requirements_wiring_is_advertised():
    """``--requirements`` and ``compile-requirements`` are the documented
    surface this whole module is built on, so pin them rather than assume them:
    a rename that silently dropped either would turn every other test here into
    a fail-open that still looked green."""
    top = _run_cli("--help")
    assert top.exit_code == 0, f"gcp-ground --help must exit 0\n{top}"
    assert "compile-requirements" in top.stdout, (
        f"compile-requirements must be a registered subcommand\n{top}")

    verify = _run_cli("verify-policy", "--help")
    assert verify.exit_code == 0, f"verify-policy --help must exit 0\n{verify}"
    assert "--requirements" in verify.stdout, (
        f"verify-policy must advertise --requirements\n{verify}")
    assert "GCP_GROUNDING_REQUIREMENTS" in verify.stdout, (
        f"verify-policy --help must name the environment fallback a hook uses "
        f"when it cannot pass a flag\n{verify}")


# -- S01: the artifact is reviewable ------------------------------------------


def test_S01_compiles(compiled):
    """One record per promise, each carrying everything a reviewer needs, and
    every DECLARED promise ``compiled`` — unconditionally.

    No branch on what this checkout registered. The two domain promises are the
    ones that prove the compiler is not IAM-only, and a checkout where they do
    not compile is a checkout that fails this test rather than one that reports
    a fallback.
    """
    doc = compiled["doc"]
    promises = {p["id"]: p for p in doc["promises"]}
    assert set(promises) == set(ACCEPTANCE), (
        f"the artifact must hold one record per declared promise plus the "
        f"unencodable one, got {sorted(promises)}")
    assert doc["source_doc"].endswith("agentic_promises.md")
    assert doc["source_sha256"] and doc["snapshot_captured_at"]

    for pid, sentence in SENTENCES.items():
        promise = promises[pid]
        source = promise["source"]
        assert source["file"].endswith("agentic_promises.md"), (pid, source)
        assert source["line"] > 0, (pid, source)
        assert source["text"] == sentence, (
            f"{pid}: the artifact's pinned sentence drifted from the markdown")
        assert promise["domain"] == DOMAINS[pid]
        assert promise["mode"] == "refute"
        assert promise["state"] == "proposal"
        assert isinstance(promise["vocabulary"], list)

    for pid in PROMISES:
        promise = promises[pid]
        assert promise["status"] == "compiled", (
            f"{pid} quantifies over {COLLECTIONS[pid]!r} and MUST compile — got "
            f"{promise['status']!r} ({promise['reason']!r}). The acceptance set "
            f"is the declared sentences, not whatever this checkout registers: "
            f"recover the collection or escalate, never narrow the set.")
        assert promise["smt"]["sexpr"], f"{pid}: a compiled promise needs its sexpr"
        for polarity in ("positive", "negative"):
            witness = promise["witnesses"][polarity]
            assert witness is not None, (
                f"{pid}: a compiled promise requires a {polarity} witness")
            assert witness["assignment"], (
                f"{pid}: the {polarity} witness must assign the formula's free "
                f"constants")

    # The sentence with no encoding is never silently dropped.
    untranslated = promises[UNENCODABLE_ID]
    assert untranslated["status"] == "unverified"
    assert untranslated["source"]["text"] == UNENCODABLE_SENTENCE
    assert untranslated["reason"], "an unverified promise must say why"
    quoted = [v for v in compiled["report"]["verdicts"]
              if v["target"] == UNENCODABLE_ID and repr(UNENCODABLE_SENTENCE) in v["message"]]
    assert quoted, (
        f"the compile report must quote the untranslated sentence verbatim; "
        f"got {[v['message'] for v in compiled['report']['verdicts'] if v['target'] == UNENCODABLE_ID]}")


# -- S02: the hallucinated requirement ----------------------------------------


def test_S02_hallucinated_requirement_rejected(compiled, tmp_path,
                                               toy_snapshot_path):
    """A requirement naming a role nobody has fails to compile, with the same
    did-you-mean a policy document naming it would get.

    Two snapshots, on purpose. The agentic snapshot proves the REJECTION and the
    suggester firing on the real fixture corpus; the toy snapshot pins the exact
    ``roles/bigquery.dataViewer`` near-miss, because ``reasoner.suggest`` caps
    its list at three and the agentic snapshot carries four bigquery roles closer
    to the typo than ``dataViewer`` is. Asserting the exact suggestion against
    the vocabulary where it is in range is honest; widening the cap to make it
    appear would be testing a suggester nobody runs.
    """
    assert compiled["outcome"].exit_code == 1, (
        f"a hallucinated requirement must fail the directory's compile\n"
        f"{compiled['outcome']}")

    bad = json.loads(compiled["bad_artifact"].read_text(encoding="utf-8"))
    promise = {p["id"]: p for p in bad["promises"]}[BAD_ID]
    assert promise["status"] == "rejected", (
        f"{BAD_ID} names {BAD_ROLE}, which the snapshot proves absent — it must "
        f"be rejected, not compiled")
    assert BAD_ROLE in promise["reason"], promise["reason"]
    assert promise["witnesses"]["positive"] is None, (
        "a rejected promise must not ship witnesses — it never became a rule")

    ungrounded = [v for v in compiled["report"]["verdicts"]
                  if v["status"] == "ungrounded" and BAD_ROLE in v["message"]]
    assert len(ungrounded) == 1, (
        f"expected exactly one ungrounded verdict naming {BAD_ROLE}, got "
        f"{[v['message'] for v in compiled['report']['verdicts'] if v['status'] == 'ungrounded']}")
    assert ungrounded[0]["suggestions"], (
        "the requirement compiler must offer the same near-misses a policy "
        "document gets, not a bare rejection")

    # The exact near-miss, against the vocabulary where it is within the cap.
    out = tmp_path / "toy-compiled"
    only_bad = tmp_path / "only-bad"
    only_bad.mkdir()
    (only_bad / BAD_MD.name).write_text(BAD_MD.read_text(encoding="utf-8"),
                                        encoding="utf-8")
    outcome, report = _compile(only_bad, out, toy_snapshot_path)
    assert outcome.exit_code == 1, f"the hallucination must fail here too\n{outcome}"
    suggested = [v for v in report["verdicts"]
                 if v["status"] == "ungrounded" and BAD_ROLE in v["message"]]
    assert len(suggested) == 1, f"{outcome}"
    assert BAD_ROLE_SUGGESTION in suggested[0]["suggestions"], (
        f"the compiler must suggest {BAD_ROLE_SUGGESTION} for {BAD_ROLE}; got "
        f"{suggested[0]['suggestions']}\n{outcome}")


# -- S03: the test that matters -----------------------------------------------


def test_S03_agent_violates_each_promise(agent_workdir, compiled,
                                         estate_snapshot_path):
    """A FakeAgent proposes one document per DECLARED promise, each violating
    exactly that promise, and every one is BLOCKED with the promise id on stderr.

    Indistinguishable from a built-in block — exit 2, byte-empty stdout, the
    rendered report on stderr — and attributable: the operator (and the agent
    reading the feedback) can tell WHICH English sentence fired, which a generic
    "policy violation" could not.
    """
    script = _script(VIOLATING, "violating")
    assert len(script) == len(PROMISES), "every declared promise is driven"
    agent = FakeAgent(agent_workdir, script)
    first = True

    for _ in range(agent.remaining()):
        proposal, event = agent.turn()
        pid = proposal.id.rsplit("-violating", 1)[0]
        assert proposal.expect == "block"
        outcome = run_hook(event, snapshot=estate_snapshot_path,
                           extra_argv=("--requirements", str(compiled["artifact"])))
        assert_blocked(outcome, pid)

        if first:
            # The OTHER documented pickup, on the same event: the whole compiled
            # DIRECTORY (rejected sibling artifact and all) named through
            # $GCP_GROUNDING_REQUIREMENTS, which is how a hook that cannot edit
            # its own argv turns requirements on. Same block, same promise id —
            # the flag and the variable are two spellings of one surface, and a
            # test that only ever exercised one would let the other rot.
            via_env = run_hook(
                event, snapshot=estate_snapshot_path,
                env={"GCP_GROUNDING_REQUIREMENTS": str(compiled["out"])})
            assert_blocked(via_env, pid)

        # The bucket and the message, through the same dispatch: a block whose
        # verdict was `ungrounded` on some unrelated name would satisfy
        # assert_blocked while proving nothing about the promise.
        report = report_of(agent.file_path(proposal),
                           requirements=compiled["artifact"],
                           snapshot=estate_snapshot_path)
        verdict = assert_recorded(report, status="contradicted", target=pid)
        assert verdict["kind"] == f"sec:{DOMAINS[pid]}", verdict
        assert pid in verdict["message"], verdict

        if first:
            # THE MIRROR IS PINNED, ONCE: the in-process report and the one a
            # real child prints must be the SAME document. Without this the
            # sidecars could drift from the boundary they stand in for and every
            # assertion above them would still be green.
            spawned = ground_json(
                agent.file_path(proposal), snapshot=estate_snapshot_path,
                env={"GCP_GROUNDING_REQUIREMENTS": str(compiled["artifact"])})
            assert spawned == report, (
                "the in-process mirror and the spawned gate disagree; the "
                "sidecar is no longer evidence about the child\n"
                f"spawned={json.dumps(spawned, indent=2, sort_keys=True)}\n"
                f"mirror={json.dumps(report, indent=2, sort_keys=True)}")
            first = False


def test_S03b_the_perimeter_vacuity_is_blocked(agent_workdir, compiled,
                                               estate_snapshot_path):
    """The empty-restricted-services perimeter, in the violating set.

    "Every service perimeter must keep storage.googleapis.com in
    restricted_services" over a perimeter whose ENFORCED list is empty. The old
    encoding quantified over ``perimeter_restricted_services``, so the only rows
    were the dry-run ones, the refutation had nothing to bind, and the promise
    GROUNDED over a perimeter that restricts nothing — MEASURED, on this
    document, before the re-encoding. The universal now binds over
    ``perimeter_resources`` and pairs the section, so the vacuity is a block.
    """
    path = _write(agent_workdir, "perimeter-vacuity", PERIMETER_VACUITY)
    outcome = run_hook(
        {"hook_event_name": "PostToolUse", "tool_name": "Write",
         "tool_input": {"file_path": path,
                        "content": json.dumps(PERIMETER_VACUITY)}},
        snapshot=estate_snapshot_path,
        extra_argv=("--requirements", str(compiled["artifact"])))
    assert_blocked(outcome, "perimeter-restricts-storage")

    report = report_of(path, requirements=compiled["artifact"],
                       snapshot=estate_snapshot_path)
    verdict = assert_recorded(report, status="contradicted",
                              target="perimeter-restricts-storage")
    assert verdict["kind"] == "sec:vpc_sc", verdict
    assert "section='status'" in verdict["message"], (
        "the refuting record must be the ENFORCED half — a spec-section witness "
        f"would mean the dry-run list was mistaken for the enforced one: {verdict}")


# -- S04: the false-positive budget applies to compiled rules too --------------


def test_S04_benign_counterparts_pass(agent_workdir, enforcing_artifact,
                                      estate_snapshot_path):
    """The satisfying counterpart of every compiled promise passes in silence.

    Byte-empty on both streams: a rule that chatters on a clean edit is a rule
    that gets switched off, and the hook's stderr lands in the agent's context.
    """
    script = _script(BENIGN, "benign")
    assert len(script) == len(PROMISES), "every declared promise is driven"
    agent = FakeAgent(agent_workdir, script)

    for _ in range(agent.remaining()):
        proposal, event = agent.turn()
        pid = proposal.id.rsplit("-benign", 1)[0]
        assert proposal.expect == "pass"
        outcome = run_hook(event, snapshot=estate_snapshot_path,
                           extra_argv=("--requirements", str(enforcing_artifact)))
        assert_passed(outcome)

        # Silence is only honest if the rule actually ran: without this the test
        # would pass just as well against a ruleset that failed to load.
        report = report_of(agent.file_path(proposal),
                           requirements=enforcing_artifact,
                           snapshot=estate_snapshot_path)
        verdict = assert_recorded(report, status="grounded", target=pid)
        assert verdict["kind"] == f"sec:{DOMAINS[pid]}", verdict


def test_S04b_the_real_artifact_prints_exactly_one_notice(agent_workdir, compiled,
                                                          estate_snapshot_path):
    """The channel S04's pruning removes, asserted BYTE FOR BYTE.

    No operator has the pruned artifact: they run the one
    ``compile-requirements`` wrote, which carries the unencodable sentence and
    therefore ONE not-enforcing line on every hook run. That line is the whole
    reason an inert guardrail is not invisible, and pruning had removed the only
    case that could have seen it, so it was asserted nowhere. One line, naming
    the count and the source, and NOTHING else, on a benign document.
    """
    pid = PROMISES[0]
    path = _write(agent_workdir, f"{pid}-s04b", BENIGN[pid])
    outcome = run_hook(
        {"hook_event_name": "PostToolUse", "tool_name": "Write",
         "tool_input": {"file_path": path, "content": json.dumps(BENIGN[pid])}},
        snapshot=estate_snapshot_path,
        extra_argv=("--requirements", str(compiled["artifact"])))
    assert outcome.exit_code == 0, f"a benign edit must pass\n{outcome}"
    assert outcome.stdout == "", f"a hook pass writes nothing to stdout\n{outcome}"
    assert outcome.stderr == (
        f"gcp-ground --hook: 1 of {len(ACCEPTANCE)} compiled requirement(s) are "
        f"not enforcing (see compile-requirements) — {compiled['artifact']}\n"
    ), (f"the operator gets exactly one not-enforcing line and nothing else — "
        f"a second line is chatter in the agent's context, and none at all is "
        f"an inert guardrail nobody can see\n{outcome}")


# -- S05: the pinned witnesses still classify ---------------------------------


@needs_z3
def test_S05_witnesses_pinned(compiled):
    """Re-classify every compiled promise's pinned witnesses.

    The artifact's witnesses are literals minted from z3 models at compile time.
    If a later encoder change moved what they mean, the promise would keep
    running while its evidence quietly stopped matching — so drift is a test
    failure here, and a refusal to register in
    :func:`gcp_grounding.sec_rules.load_rules`.
    """
    z3 = importlib.import_module("z3")
    sec_artifact = importlib.import_module("gcp_grounding.sec_artifact")
    sec_probes = importlib.import_module("gcp_grounding.sec_probes")

    doc = sec_artifact.load(compiled["artifact"])
    checked = 0
    for promise in doc.promises:
        if promise.status != "compiled":
            continue
        positive_ok, negative_ok = sec_probes.reclassify(z3, promise)
        assert positive_ok is True, (
            f"{promise.id}: the pinned positive witness no longer classifies — "
            f"{promise.positive}")
        assert negative_ok is True, (
            f"{promise.id}: the pinned negative witness no longer classifies — "
            f"{promise.negative}")
        checked += 1
    assert checked == len(PROMISES), (
        f"expected {len(PROMISES)} compiled promises to re-classify, checked "
        f"{checked}")


# -- S06: block becomes abstain when z3 is gone -------------------------------


def test_S06_no_z3_degrades(agent_workdir, compiled, estate_snapshot_path,
                            no_z3_env):
    """Without z3 every compiled-rule verdict moves to ``unverified``, and none
    moves to a silent pass — the same block-to-abstain invariant the built-in
    z3 checks obey.

    The control is in the same test: the first promise is also run in the z3
    world, so a run where the rules never loaded at all cannot masquerade as an
    honest degradation. The degraded half stays a CHILD because the overlay is a
    ``PYTHONPATH`` import blocker: an in-process mirror runs in an interpreter
    that has already imported z3, and would prove nothing.
    """
    requirements = {"GCP_GROUNDING_REQUIREMENTS": str(compiled["artifact"])}
    agent = FakeAgent(agent_workdir, _script(VIOLATING, "violating"))
    control_done = False

    for _ in range(agent.remaining()):
        proposal, _event = agent.turn()
        pid = proposal.id.rsplit("-violating", 1)[0]
        path = agent.file_path(proposal)

        if not control_done:  # the z3-world control, on the same document
            control = report_of(path, requirements=compiled["artifact"],
                                snapshot=estate_snapshot_path)
            assert_recorded(control, status="contradicted", target=pid)
            control_done = True

        report = ground_json(path, snapshot=estate_snapshot_path,
                             env={**no_z3_env, **requirements})
        assert report["backend"] != "z3", (
            f"the no-z3 overlay did not reach the child: backend is "
            f"{report['backend']!r}")
        mine = [v for v in report["verdicts"] if v["target"] == pid]
        assert mine, (
            f"{pid} left no verdict at all without z3 — a rule that vanishes is "
            f"a silent pass")
        assert {v["status"] for v in mine} == {"unverified"}, (
            f"{pid} must abstain, not decide, without z3: {mine}")
        assert any("z3" in v["message"] for v in mine), (
            f"{pid}: the abstention must name z3 as the reason — {mine}")


# -- S07: the unencodable sentence never decides anything ---------------------


def test_S07_unencodable_stays_unverified(agent_workdir, compiled,
                                          estate_snapshot_path):
    """The sentence with no encoding carries an ``unverified`` on every run and
    never any other status — at compile time, over a violating document and over
    a benign one.

    Two failure modes, one assertion: a compiler that quietly dropped it would
    leave no verdict (the requirement silently stops existing), and one that
    guessed at a translation would eventually decide it.
    """
    reports = [compiled["report"]]

    first = PROMISES[0]
    for documents, flavour in ((VIOLATING, "violating"), (BENIGN, "benign")):
        path = _write(agent_workdir, f"{first}-{flavour}-s07", documents[first])
        reports.append(report_of(path, requirements=compiled["artifact"],
                                 snapshot=estate_snapshot_path))

    for report in reports:
        assert_not_silently_dropped(report, UNENCODABLE_ID)
        mine = [v for v in report["verdicts"] if v["target"] == UNENCODABLE_ID]
        assert {v["status"] for v in mine} == {"unverified"}, (
            f"the untranslated sentence must only ever be unverified: {mine}")
        assert any(repr(UNENCODABLE_SENTENCE) in v["message"] for v in mine), (
            f"every carry verdict must quote the sentence so a reviewer sees "
            f"WHICH requirement is inert: {mine}")


# -- S08: the defensive fallback, exercised rather than assumed ---------------


def test_S08_absent_compiler_degrades_honestly(agent_workdir, compiled,
                                               estate_snapshot_path,
                                               blocked_import_env):
    """A checkout without :mod:`gcp_grounding.sec_rules` must say so and let the
    edit through, never block it.

    ``pytestmark`` skips this module when the compiler is genuinely absent, so
    the fallback branch would otherwise be dead code that nobody ever runs. The
    ``_blockimports`` overlay makes it live: the child really cannot import
    ``sec_rules``, and the operator gets one honest line instead of a rule that
    silently stopped enforcing.
    """
    pid = PROMISES[0]
    path = _write(agent_workdir, f"{pid}-blocked", VIOLATING[pid])
    overlay = blocked_import_env("gcp_grounding.sec_rules")

    outcome = run_hook(
        {"hook_event_name": "PostToolUse", "tool_name": "Write",
         "tool_input": {"file_path": path,
                        "content": json.dumps(VIOLATING[pid])}},
        snapshot=estate_snapshot_path,
        extra_argv=("--requirements", str(compiled["artifact"])),
        env=overlay)

    assert outcome.exit_code == 0, (
        f"a checkout without the requirements compiler must never block an "
        f"edit over its own absence\n{outcome}")
    assert "compiled requirements are not available in this checkout" in outcome.stderr, (
        f"the absence must be stated, not silent: a guardrail that stops "
        f"enforcing without saying so is worse than one that never ran\n{outcome}")
    assert pid not in outcome.stderr, (
        f"no promise can have decided anything here\n{outcome}")


# -- S09: pruning is not weakening --------------------------------------------


def test_S09_the_pruned_artifact_still_blocks(agent_workdir, enforcing_artifact,
                                              estate_snapshot_path):
    """A VIOLATING document through the pruned artifact is still refuted.

    S04 reads silence off this artifact, and silence is exactly what an artifact
    that lost its promises produces. A benign case cannot tell a real positive
    from a rubber stamp, so the evidence that the pruned ruleset still DECIDES
    has to come from a violating document — which is also why the mutation
    contract's artifact-writer removal names this node and not one of S04's.
    """
    pid = "sa-key-creation-disabled"
    path = _write(agent_workdir, f"{pid}-s09", VIOLATING[pid])
    report = report_of(path, requirements=enforcing_artifact,
                       snapshot=estate_snapshot_path)
    verdict = assert_recorded(report, status="contradicted", target=pid)
    assert verdict["kind"] == f"sec:{DOMAINS[pid]}", verdict
    assert report["ok"] is False, (
        f"a refuted promise must fail the report\n{report['summary']}")


# -- S10: a resolved-but-empty requirements source is never silent ------------


@pytest.mark.parametrize("which", ["directory", "artifact"])
def test_S10_an_empty_requirements_source_says_so(which, agent_workdir,
                                                  empty_sources,
                                                  estate_snapshot_path):
    """Zero enforcement is stated, not silent — on a KNOWN-VIOLATING document.

    An empty artifact directory and an artifact holding zero promises both
    resolve and both read successfully, so nothing in the load path complains,
    and the run is byte-identical to the rule working. The document is one S03
    proves blocks, so the case cannot pass by being harmless: the edit really
    does go through unjudged, and the line asserted here is the only thing
    between the operator and a guardrail that quietly enforces nothing.
    """
    source = empty_sources[which]
    pid = PROMISES[0]
    path = _write(agent_workdir, f"{pid}-empty-{which}", VIOLATING[pid])
    outcome = run_hook(
        {"hook_event_name": "PostToolUse", "tool_name": "Write",
         "tool_input": {"file_path": path,
                        "content": json.dumps(VIOLATING[pid])}},
        snapshot=estate_snapshot_path,
        extra_argv=("--requirements", str(source)))

    assert outcome.exit_code == 0, (
        f"an empty requirements source must never block an edit over its own "
        f"emptiness\n{outcome}")
    assert outcome.stdout == "", f"a hook pass writes nothing to stdout\n{outcome}"
    assert outcome.stderr == (
        f"gcp-ground --hook: 0 compiled requirement(s) loaded from {source} — "
        f"nothing is being enforced (see compile-requirements)\n"
    ), (f"the note must name the source and the zero count, and be the only "
        f"thing on stderr\n{outcome}")
    assert pid not in outcome.stderr, (
        f"nothing was enforced, so no promise may appear to have decided "
        f"anything\n{outcome}")


# -- S11: the named-subject vacuity never grounds -----------------------------


@pytest.mark.parametrize("case", sorted(VACUOUS), ids=sorted(VACUOUS))
def test_S11_a_document_the_promise_cannot_speak_about_never_grounds(
        case, agent_workdir, compiled, estate_snapshot_path):
    """Neither vacuity document may yield a positive.

    MEASURED before the fix: an Org Policy for ``compute.requireShieldedVm``
    returned ``sa-key-creation-disabled: the obligation holds over the document —
    grounded``. That document says nothing whatever about service-account key
    creation; the refute-mode existential simply had no row it could contradict,
    and "unsatisfiable" was read as "the obligation holds" — an affirmatively
    false statement about the promise whose sentence is the review boundary.

    The honest verdict is an abstention NAMING the constraint the document is
    silent about, which :meth:`gcp_grounding.sec_rules.CompiledRule._off_subject`
    now returns. The empty-``rules`` document reaches the same answer one gate
    earlier: it names the right constraint and yields no record at all.
    """
    pid = "sa-key-creation-disabled"
    path = _write(agent_workdir, f"vacuous-{case}", VACUOUS[case])
    report = report_of(path, requirements=compiled["artifact"],
                       snapshot=estate_snapshot_path)
    verdict = assert_recorded(report, target=pid)
    assert verdict["status"] == "unverified", (
        f"{pid} decided {verdict['status']!r} over a document it cannot speak "
        f"about; a positive here is a false statement about the promise, and "
        f"the honest answer is an abstention\n{verdict}")
    assert SCOPED_CONSTRAINT in verdict["message"], (
        f"the abstention must NAME the constraint at stake, or a reviewer "
        f"cannot tell WHICH promise went quiet\n{verdict}")
    assert report["ok"] is True, "an abstention never fails the gate"

    if case == "another-constraint":
        assert "compute.requireShieldedVm" in verdict["message"], (
            f"the abstention must also name what the document IS about, so the "
            f"reader can see the two are different subjects\n{verdict}")
