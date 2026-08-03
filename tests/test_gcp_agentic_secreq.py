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

WHAT COMPILES HERE, AND WHAT THAT PROVES.  ``agentic_promises.md`` holds six
machine-checkable promises across four domains plus one deliberately unencodable
sentence.  Three of the six quantify over ``iam_bindings`` and one over
``org_policy_rules`` — the collections :mod:`gcp_grounding.sec_rules` ships — so
they compile and enforce in any checkout that has the compiler. The remaining
two name ``proposed_firewall_rules`` and ``perimeter_restricted_services``, which
``sx-sec-domains`` registers; in a checkout without that module the compiler
emits the honest ``unverified`` naming the collection, which is the FALLBACK
branch here (:data:`_REGISTERED_COLLECTIONS` decides per promise), never the
expected outcome. Both bodies are type-correct against the domain layer's
published field lists, so they move from the fallback branch to the enforcing one
the moment ``sec_domains`` lands, with no edit to this module or to the markdown.

The seventh promise — "changes must be reviewed by the security team before
merge" — has no z3 encoding and never will. The compiler must say so rather than
approximate it, so it compiles to ``status: unverified`` with the sentence quoted
verbatim (S01) and can never produce a verdict of any other status (S07). The
eighth, in ``agentic_promises_bad.md``, names ``roles/bigquery.reader`` and must
FAIL to compile with the same did-you-mean a policy document would get (S02) —
grounding the REQUIREMENTS, not just the policies, is the whole point of pushing
``vocab:`` through :func:`gcp_grounding.reasoner.ground_existence` before
admission.

FIRST-PARTY TEST PACKAGES ARE IMPORTED BY DOTTED PATH. ``tests/`` is a regular
package (``tests/__init__.py`` ships with ``sx-agentic-plumbing``) and every
import below spells the full ``tests.agentic.*`` path. A bare ``from agentic
import env`` would still run, but the harness grounding gate derives a module's
dotted name by walking up through ``__init__.py`` markers, so the source spelling
has to match the real package name or every reference in this file reads as a
hallucination.
"""

from __future__ import annotations

import dataclasses
import importlib
import json
import subprocess
import sys

import pytest

from tests.agentic import env
from tests.agentic.asserts import (assert_blocked, assert_not_silently_dropped,
                                   assert_passed, assert_recorded)
from tests.agentic.fake_agent import FakeAgent, Proposal
from tests.agentic.hookrunner import (DEFAULT_TIMEOUT, HookOutcome, bind_budget,
                                      child_env, current_budget, ground_json,
                                      run_hook)
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
        "constraints/iam.disableServiceAccountKeyCreation must be enforced.",
    "no-open-ssh-rdp-ingress":
        "No ingress firewall rule may allow tcp/22 or tcp/3389 from 0.0.0.0/0.",
    "perimeter-restricts-storage":
        "Every service perimeter must keep storage.googleapis.com in "
        "restricted_services.",
}

#: Promise id → its domain, as declared in the markdown.
DOMAINS = {
    "no-primitive-roles-outside-domain": "iam",
    "no-public-principals": "iam",
    "impersonation-sre-only": "iam",
    "sa-key-creation-disabled": "org_policy",
    "no-open-ssh-rdp-ingress": "vpc_firewall",
    "perimeter-restricts-storage": "vpc_sc",
}

#: Promise id → the collection its formula quantifies over. This is what decides
#: whether a promise is executable in THIS checkout: an unregistered collection
#: is the honest-``unverified`` fallback branch, not a failure.
COLLECTIONS = {
    "no-primitive-roles-outside-domain": "iam_bindings",
    "no-public-principals": "iam_bindings",
    "impersonation-sre-only": "iam_bindings",
    "sa-key-creation-disabled": "org_policy_rules",
    "no-open-ssh-rdp-ingress": "proposed_firewall_rules",
    "perimeter-restricts-storage": "perimeter_restricted_services",
}

#: The prose-only section: ``sec_parse`` derives this id from the heading.
UNENCODABLE_ID = "untranslated-security-review-before-merge"
UNENCODABLE_SENTENCE = "Changes must be reviewed by the security team before merge."

#: The hallucinated requirement and the near-miss the suggester must offer.
BAD_ID = "bigquery-reader-only"
BAD_ROLE = "roles/bigquery.reader"
BAD_ROLE_SUGGESTION = "roles/bigquery.dataViewer"


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


def _registered_collections() -> frozenset:
    """Every collection name :mod:`gcp_grounding.sec_ast` knows, with the lazy
    domain resolution already triggered.

    ``collections_used`` runs ``_ensure_domains`` before walking, so calling it
    on a trivial formula is the public way to force the domain layer to register
    (or to fail open) before the registry is read.
    """
    try:
        sec_ast = importlib.import_module("gcp_grounding.sec_ast")
        sec_ast.collections_used({"node": "true"})
        return frozenset(sec_ast.COLLECTIONS)
    except Exception:  # noqa: BLE001 - a probe never breaks collection
        return frozenset()


_REGISTERED_COLLECTIONS = _registered_collections()

#: The promises that are executable rules in THIS checkout, in document order.
EXECUTABLE = tuple(pid for pid in SENTENCES
                   if COLLECTIONS[pid] in _REGISTERED_COLLECTIONS)
#: The promises that fall back to the honest ``unverified`` naming a collection
#: no module in this checkout registers.
UNREGISTERED = tuple(pid for pid in SENTENCES if pid not in EXECUTABLE)

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
}


def _script(documents, expect: str) -> tuple:
    """One :class:`Proposal` per executable promise, in document order.

    Each proposal writes its own ``.json`` path so a later turn cannot overwrite
    an earlier turn's evidence, and the id carries the promise id so a pytest
    failure names the promise without a lookup.

    A promise that became executable with no document written for it is a HARD
    failure, not a quiet skip. Silently covering four of six promises is the
    missed-abstain failure mode this whole suite exists to catch: the run would
    stay green while the two domain promises enforced nothing that anybody
    checked. The assertion names the promise, so whoever lands the module that
    registers its collection is told exactly what to add.
    """
    missing = [pid for pid in EXECUTABLE if pid not in documents]
    assert not missing, (
        f"{missing} became executable in this checkout (their collections are "
        f"registered now) but have no {expect} document — add one per promise to "
        f"{'VIOLATING' if expect == 'violating' else 'BENIGN'} so the promise is "
        f"actually driven, rather than passing by omission")
    script = []
    for pid in EXECUTABLE:
        payload = documents[pid]
        script.append(Proposal(
            id=f"{pid}-{expect}",
            kind="org_policy" if DOMAINS[pid] == "org_policy" else "iam",
            tool_name="Write",
            rel_path=f"{pid}-{expect}.json",
            payload=payload,
            expect="block" if expect == "violating" else "pass",
            rationale=f"an agent edit that {'breaks' if expect == 'violating' else 'honours'} "
                      f"the promise {pid!r}",
        ))
    return tuple(script)


# -- spawning the CLI ---------------------------------------------------------


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

    S04's subject is the false-positive budget of a *rule*, and the full
    artifact carries three promises that deliberately do not enforce (the prose
    sentence and, in a partial checkout, the two domain promises). ``cli.py``
    prints one operator line per run in that case — by design, so an inert
    guardrail is never invisible — which is a constant, document-independent
    string that would sit on stderr under every benign proposal and mask exactly
    the chatter S04 is looking for. Pruning is not editing: the surviving
    records are byte-identical, so ``sec_rules._admit``'s sexpr agreement and
    witness re-classification still decide them.
    """
    sec_artifact = importlib.import_module("gcp_grounding.sec_artifact")
    doc = sec_artifact.load(compiled["artifact"])
    kept = tuple(p for p in doc.promises if p.status == "compiled")
    assert {p.id for p in kept} == set(EXECUTABLE), (
        "the pruned artifact must carry exactly the executable promises, or S04 "
        "passes vacuously against an empty ruleset")
    path = tmp_path_factory.mktemp("enforcing") / ARTIFACT_NAME
    path.write_text(sec_artifact.dumps(dataclasses.replace(doc, promises=kept)),
                    encoding="utf-8")
    return path


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
    """One record per promise, each carrying everything a reviewer needs."""
    doc = compiled["doc"]
    promises = {p["id"]: p for p in doc["promises"]}
    assert set(promises) == set(SENTENCES) | {UNENCODABLE_ID}, (
        f"the artifact must hold one record per promise, got {sorted(promises)}")
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

    for pid in EXECUTABLE:
        promise = promises[pid]
        assert promise["status"] == "compiled", (
            f"{pid} quantifies over {COLLECTIONS[pid]!r}, which IS registered in "
            f"this checkout, so it must compile — got {promise['status']!r} "
            f"({promise['reason']!r})")
        assert promise["smt"]["sexpr"], f"{pid}: a compiled promise needs its sexpr"
        for polarity in ("positive", "negative"):
            witness = promise["witnesses"][polarity]
            assert witness is not None, (
                f"{pid}: a compiled promise requires a {polarity} witness")
            assert witness["assignment"], (
                f"{pid}: the {polarity} witness must assign the formula's free "
                f"constants")

    for pid in UNREGISTERED:
        promise = promises[pid]
        assert promise["status"] == "unverified", (
            f"{pid} names {COLLECTIONS[pid]!r}, which no module in this checkout "
            f"registers, so the only honest status is unverified")
        assert COLLECTIONS[pid] in promise["reason"], (
            f"{pid}: the abstention must NAME the collection it could not "
            f"resolve — got {promise['reason']!r}")

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


def test_S01b_partial_checkout_is_reported_not_hidden(compiled):
    """The fallback branch, stated out loud.

    Not an ``xfail`` and not a skip: the module stays green in a partial
    checkout, but a reader of the run has to be able to see that two of the six
    promises did not enforce and exactly why.
    """
    if not UNREGISTERED:
        return
    pytest.skip(
        "these promises are honestly unverified in this checkout because no "
        "module registers their collections: "
        + "; ".join(f"{pid} needs {COLLECTIONS[pid]} (gcp_grounding.sec_domains)"
                    for pid in UNREGISTERED))


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
    """A FakeAgent proposes one document per compiled promise, each violating
    exactly that promise, and every one is BLOCKED with the promise id on stderr.

    Indistinguishable from a built-in block — exit 2, byte-empty stdout, the
    rendered report on stderr — and attributable: the operator (and the agent
    reading the feedback) can tell WHICH English sentence fired, which a generic
    "policy violation" could not.
    """
    script = _script(VIOLATING, "violating")
    assert script, "no executable promise has a violating counterpart"
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
            first = False

        # The bucket and the message, through the same dispatch: a block whose
        # verdict was `ungrounded` on some unrelated name would satisfy
        # assert_blocked while proving nothing about the promise.
        report = ground_json(agent.file_path(proposal),
                             snapshot=estate_snapshot_path,
                             env={"GCP_GROUNDING_REQUIREMENTS": str(compiled["artifact"])})
        verdict = assert_recorded(report, status="contradicted", target=pid)
        assert verdict["kind"] == f"sec:{DOMAINS[pid]}", verdict
        assert pid in verdict["message"], verdict


# -- S04: the false-positive budget applies to compiled rules too --------------


def test_S04_benign_counterparts_pass(agent_workdir, enforcing_artifact,
                                      estate_snapshot_path):
    """The satisfying counterpart of every compiled promise passes in silence.

    Byte-empty on both streams: a rule that chatters on a clean edit is a rule
    that gets switched off, and the hook's stderr lands in the agent's context.
    """
    script = _script(BENIGN, "benign")
    assert script, "no executable promise has a benign counterpart"
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
        report = ground_json(agent.file_path(proposal),
                             snapshot=estate_snapshot_path,
                             env={"GCP_GROUNDING_REQUIREMENTS": str(enforcing_artifact)})
        verdict = assert_recorded(report, status="grounded", target=pid)
        assert verdict["kind"] == f"sec:{DOMAINS[pid]}", verdict


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
    assert checked == len(EXECUTABLE), (
        f"expected {len(EXECUTABLE)} compiled promises to re-classify, checked "
        f"{checked}")


# -- S06: block becomes abstain when z3 is gone -------------------------------


def test_S06_no_z3_degrades(agent_workdir, compiled, estate_snapshot_path,
                            no_z3_env):
    """Without z3 every compiled-rule verdict moves to ``unverified``, and none
    moves to a silent pass — the same block-to-abstain invariant the built-in
    z3 checks obey.

    The control is in the same test: the first promise is also run in the z3
    world, so a run where the rules never loaded at all cannot masquerade as an
    honest degradation.
    """
    requirements = {"GCP_GROUNDING_REQUIREMENTS": str(compiled["artifact"])}
    agent = FakeAgent(agent_workdir, _script(VIOLATING, "violating"))
    control_done = False

    for _ in range(agent.remaining()):
        proposal, _event = agent.turn()
        pid = proposal.id.rsplit("-violating", 1)[0]
        path = agent.file_path(proposal)

        if not control_done:  # the z3-world control, on the same document
            control = ground_json(path, snapshot=estate_snapshot_path,
                                  env=dict(requirements))
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
    requirements = {"GCP_GROUNDING_REQUIREMENTS": str(compiled["artifact"])}
    reports = [compiled["report"]]

    first = EXECUTABLE[0]
    for documents, flavour in ((VIOLATING, "violating"), (BENIGN, "benign")):
        path = agent_workdir / f"{first}-{flavour}-s07.json"
        path.write_text(json.dumps(documents[first], indent=2, sort_keys=True),
                        encoding="utf-8")
        reports.append(ground_json(path, snapshot=estate_snapshot_path,
                                   env=dict(requirements)))

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
    pid = EXECUTABLE[0]
    path = agent_workdir / f"{pid}-blocked.json"
    path.write_text(json.dumps(VIOLATING[pid], indent=2, sort_keys=True),
                    encoding="utf-8")
    overlay = blocked_import_env("gcp_grounding.sec_rules")

    outcome = run_hook(
        {"hook_event_name": "PostToolUse", "tool_name": "Write",
         "tool_input": {"file_path": str(path), "content": path.read_text(encoding="utf-8")}},
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
