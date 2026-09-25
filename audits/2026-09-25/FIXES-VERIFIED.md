# Closure report — every row of `REPORT.md`, re-verified

**Question.** The consolidated audit ([`REPORT.md`](REPORT.md)) raised 57 rows and applied
nothing. Seven fix tasks have since landed. Is each row actually closed?

**Subject.** `gcp-policy-grounding` at `agent/verify-fixes` `d201bda`, whose tree is
identical to `agent/fix-docs` for every audited path.
**Baseline compared against.** `ded929a` — the commit the audit reports were written on.
**Date.** 2026-09-25.
**Nature.** Read-only, like the six reports before it. **Nothing is fixed here.** A row
found NOT closed is reported, never repaired. The only file this task wrote is this one:

```
git diff --name-only agent/fix-docs -- gcp_grounding tests examples run_demo.sh \
    README.md simple_readme.md sec_requirements pyproject.toml     # -> empty
git status --porcelain                                             # -> clean
```

## 1. Verdict

**55 rows closed, 2 no-change-by-design, 0 not closed.**

| state | rows | what it means |
| --- | ---: | --- |
| closed | 55 | the row's proposed fix is in the tree, and the defect it names no longer reproduces under the source report's own probe |
| no-change-by-design | 2 | `R56`, `R57` — the source report marked them "None needed"; both were re-run and both recordings are still true |
| not closed | 0 | |

The full suite is green and no xfail turned XPASS:

```
/home/jones/Downloads/gcp-policy-grounding/.venv/bin/python -m pytest -q tests/
4591 passed, 2 skipped, 15 xfailed in 121.84s        # exit 0
```

against the audit's measured baseline of `4456 passed, 3 skipped, 19 xfailed`. The skip
that went is `SA-SECAST-CALLED-ONCE`'s (row R45, retired by R03's closure); the four
xfails that went are `ESC-GX-SPEC-002` (R45) and the three `ESC-GX-*-REMOVAL-CEILING`
escalations R43 was expected to force to XPASS and retire.

Two things this report will not claim. It did not re-run the five source audits, so a
finding they missed is still missed here. And the rows are verified against the fix each
row **proposed** — where a row offered alternatives and the fix took the smaller one,
that is recorded as the closure, not held against it.

---

## 2. Method

* **The suite** ran once, whole, from the worktree root with the repo venv's interpreter.
* **Every `run_demo.sh` scenario** ran from a scratch copy, `env` containing exactly
  `PATH`, cwd the copy — the demos-and-quotes audit's own recipe
  (`git archive --format=tar HEAD | tar -x`, with `.venv/bin/{python,gcp-ground}` as
  two-line `exec` shims onto the repo venv's interpreter with `PYTHONPATH` pinned at the
  copy, so the code measured is the copy's with z3 importable). Run twice: once with the
  export's own mtimes, once with **every tree mtime backdated 400 days**, which is the
  condition row R05 is about.
* **R01, R02, R05, R06 and R15 were re-probed** with fresh corpora modelled on the source
  reports' probes. R01's and R02's corpora are authored from nothing — a made-up
  two-project organisation (`zolt.example`, `organizations/770` → `projects/zolt-prod`)
  with its own snapshot, sidecars, second source and documents; no repository fixture is
  an input to either.
* **Each of those probes carries a sensitivity control**: the identical corpus run against
  `ded929a`, the audit's own tree, exported to a second scratch copy. A probe that
  diverges there and holds here is measuring the fix. That control is what separates
  "closed" from "the probe agrees with itself".
* **Exit codes are read straight off the process** (`subprocess.run(...).returncode`),
  never through a pipe. Every child's environment is stripped of `GCP_GROUNDING*` before
  the run, and the clock is pinned per probe, so nothing here is decided by an exported
  setting or by the wall clock.
* **Compiled artifacts go to the scratchpad**, never into the tree — including the
  `sec_requirements/compiled/` directory row R52 asserts is absent.

---

## 3. The five re-probes

### R01 — `--drift-policy` beats the environment

Fresh corpus: an api snapshot holding one INGRESS rule scoped to a partner range, a
tfstate view of the **same** row opened to `0.0.0.0/0` (so the merged fact is disputed),
a sidecar declaring the api source complete, and a REST `compute#firewall` proposal that
is world-open on tcp/22. Five runs — the audit's four plus the unconfigured control:

```
verify-policy <corpus>/violating.json --snapshot <corpus>/snapshot.json \
    --merge-source <corpus>/tfview.json --origins <corpus>/snapshot.origins.json \
    --as-of 2026-09-21T00:00:00Z --no-config --format json [--drift-policy FLAG]
```

| flag | `$GCP_GROUNDING_DRIFT_POLICY` | documented | this tree | `ded929a` |
| --- | --- | --- | --- | --- |
| — | — | exit 1, `contradicted` | exit 1, `contradicted` | exit 1, `contradicted` |
| `abstain` | — | exit 0, `unverified` | exit 0, `unverified` | **exit 1, `contradicted`** |
| — | `abstain` | exit 0, `unverified` | exit 0, `unverified` | exit 0, `unverified` |
| `annotate` | `abstain` | exit 1, `contradicted` | exit 1, `contradicted` | **exit 0, `unverified`** |
| `abstain` | `annotate` | exit 0, `unverified` | exit 0, `unverified` | **exit 1, `contradicted`** |

Three of five cells diverge on `ded929a` — the same three the audit measured wrong — and
all five hold here. The downgraded verdict names its reason:
`[not decided: drift policy 'abstain' was requested, so a finding whose evidence is
partly uncertain is reported as undecided rather than as …]`. The environment-only cell
still decides, so the library-caller fallback survived the threading. **R01 closed.**

### R02 — an emptied REST deny policy is still a deny policy

Fresh corpus: an estate granting `iam.serviceAccounts.actAs` to a CI service account
through a custom role, guarded by
`policies/cloudresourcemanager.googleapis.com%2Fprojects%2Fzolt-prod/denypolicies/zolt-actas-guard`.
The `--baseline` is that guard with its rule; three proposals remove it three ways.

```
verify-policy --proposal <corpus>/<proposal> --baseline <corpus>/baseline.json \
    --snapshot <corpus>/snapshot.json --as-of 2026-09-21T00:00:00Z --no-config
```

| proposal | this tree | `ded929a` |
| --- | --- | --- |
| `wake_removed.json` (`"rules": []`) | **exit 1**, `⚠ [iam_deny_shadow] …: removing or narrowing rule 0 wakes the dormant grant …` | exit 0, `? [document] …: document kind was not recognized (top-level keys ['displayName','etag','name','rules'])` |
| `wake_absent.json` (no `rules` key — the REST spelling) | **exit 1**, the same woken-grant verdict | exit 0, the same unrecognized-document abstention |
| `wake_excepted.json` (narrowed by an `exceptionPrincipals` entry) | exit 0 | exit 0 — identical on both trees |

The emptied policy is now recognised and reaches `check_deny_pair`, so the documented wake
arc runs and the run exits 1. It also carries a second, accurate abstention
(`? [document] …: detected iam_deny_policy content, but nothing checkable could be
extracted from it`), which sits under the contradiction that decides the run.

One observation about the third row, since it differs from the audit's: this corpus's
narrowing arm does **not** wake the grant on either tree. Both exception spellings tried
(`principal://goog/subject/…` and the plain `serviceAccount:…`) fall outside the curated
v1→v2 containment table `README.md:105-114` names as a stated limit, so the check abstains
or passes for that reason rather than for R02's. That is a property of this fresh corpus,
not a difference between the trees — the pre-fix control above is what establishes the
probe's sensitivity. **R02 closed.**

### R05 — the provider schema no longer goes stale with the checkout

`examples/terraform-schema/provider-schema.json` now ships inside the documented
`gcp-provider-schema/1` envelope with `captured_at: 2026-07-25T08:00:00Z`, and the
`verify_schema` arc pins `GCP_GROUNDING_NOW=2026-07-25T12:00:00Z`.

```
env -i PATH=… bash run_demo.sh 4      # from a git archive scratch copy
env -i PATH=… bash run_demo.sh 4b
```

| tree | tree mtimes | scenario 4 | scenario 4b |
| --- | --- | --- | --- |
| this tree | export's own | PASS, exit 0 | PASS, exit 0 |
| this tree | **backdated 400 days** | PASS, exit 0 | PASS, exit 0 |
| `ded929a` | backdated 400 days | **FAIL, exit 1** | **FAIL, exit 1** |

The pre-fix control reproduces the finding exactly: `scenario 4: FAIL — 1 of 1 steps
diverged`, the step exiting 0 with `? [tf_schema] the captured provider schema at … is …
old (file mtime …), past the 7 days ceiling …` and `[tf_attribute]` demoted `✗` → `?`.
Here, at 400 days of mtime age, both arcs print the `✗ [tf_attribute]` finding and exit 1
as documented. **R05 closed.**

### R06 — demo step 4's did-you-mean

```
GCP_GROUNDING_NOW=2026-07-18T12:00:00Z gcp-ground verify-policy \
    tests/fixtures/gcp/policies/iam_policy_bad.json \
    --snapshot tests/fixtures/gcp/snapshot.json
```

exit 1, and the documented evidence is there:

```
✗ [role] bindings[0].role: role 'roles/bigquery.reader' does not exist in the snapshot
    (captured 2026-07-18T09:30:00Z)  (did you mean: roles/bigquery.jobUser,
    roles/bigquery.dataViewer?)
```

Control: the same command **without** the pin still exits 1 — the trap the row named —
but both the `✗` and the did-you-mean are absent. Two pinned runs are byte-identical, so
the step's output does not depend on when it is run. **R06 closed.**

### R15 — demo step 3's three pieces of evidence

```
GCP_GROUNDING_NOW=2026-07-25T12:00:00Z gcp-ground verify-policy \
    tests/fixtures/gcp/agentic/iam/A10_owner_to_external.policy.json \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json \
    --requirements <compiled> --explain
```

exit 1, and all three appear:

```
⚠ [sec:iam] no-primitive-roles-outside-domain: refuted by iam_bindings[0] …
✗ [principal] bindings[0].members[0]: principal 'user:attacker@evil.example' does not
    exist in the snapshot (captured 2026-07-25T08:00:00Z)
✓ [iam_escalation] bindings[0].role: warning — roles/owner grants roles/owner
    (named-admin-role), iam.roles.update (role-mutation), iam.serviceAccounts.actAs
    (impersonation) +1 more to user:attacker@evil.example; review the principal
```

Control: unpinned, the `✗ [principal]` line is gone and the promise refutation alone
carries the exit — the two-of-three decay the row describes. **R15 closed.**

---

## 4. The demo matrix

`--list` enumerates 24 scenarios and all 24 were run, twice, from the scratch copy with
`env` containing only `PATH`:

| tree | tree mtimes | arcs passing |
| --- | --- | --- |
| this tree | the export's own | **24 / 24** |
| this tree | backdated 400 days | **24 / 24** |

Labels: `1 2a 2b 3 3b 3c 3d 4 4b 4c 4d 5 5a 5b 5c 5d 5e 5f 5g 6 6a 6b 6c w`. Every run
names its backend before its first step (`solver backend: z3 — the exits documented below
assume it`), which is row R42's fix; the solverless arm was driven separately and prints
the other half:

```
GCP_GROUND=<shim blocking z3> bash run_demo.sh 3
  solver backend: builtin — z3 is NOT importable here, and the exits
                  documented below assume it: without the solver every
                  DENIED verdict that rests on it becomes an abstention,
                  so those steps diverge. Install it with: python3 -m pip install -e '.[z3]'
  ? [firewall_exposure] …: z3 is not available (solver backend 'builtin') — public
      exposure was not decided
scenario 3: FAIL — 1 of 1 steps diverged from the exits the README documents
```

— a diverging arc now readable against the capability it was judged with. Scenario `4c`
passes on that arm, as the runner's prose says such arcs do.

---

## 5. The hallucination register, re-resolved

Each row re-run with `REPORT.md` §3's own verification command.

| # | claim | command | observed now |
| --- | --- | --- | --- |
| H1 / R07 | `--baseline-target` | `grep -rn "baseline-target" gcp_grounding/ tests/ README.md simple_readme.md` | 3 hits, **all** in `tests/test_gcp_audit_hallucinated_refs.py` asserting the name's absence. `baseline.REMEDIES[0]` = `'pass the target explicitly (the --target DOMAIN:KEY flag)'`, and `--target DOMAIN:KEY` is in `verify-policy --help` |
| H2 / R08 | a `completeness` config key | `grep -n "or the config key" gcp_grounding/sources.py` | no hits. `'completeness' in discovery.CONFIG_KEYS` is still `False` — the key was not added, which `README.md:1155-1157` explains is the design |
| H3 / R09 | `identity.CATEGORY_SPECS` | `grep -rn "CATEGORY_SPECS" gcp_grounding/` | no hits. `knowledge.py:745` now reads `:data:`gcp_grounding.identity.SPECS``; `len(identity.SPECS) == 19` |
| H4 / R10 | `gcp_grounding.tfsource.merge` | `grep -n "tfsource.merge" gcp_grounding/tfsource/map_network.py` | no hits; 5 references to `gcp_grounding.merge` instead. `gcp_grounding/merge.py` exists, `gcp_grounding/tfsource/merge.py` does not |
| H5 / R11 | `ORG-EFFECTIVE-REGISTER-ACTIVATION` | `grep -rn "ORG-EFFECTIVE-REGISTER-ACTIVATION" --include='*.py' --include='*.md' .` outside `audits/` | 2 hits, both in `tests/test_gcp_audit_hallucinated_refs.py` naming the retired id. `tests/test_gcp_org_effective.py:1190` now heads its reason `ESC-ORGEFF-REGISTER-ACTIVATION`, which **is** in `ESCALATIONS` (15 entries) |
| H6 / R12 | `Escalation.closed_by` | `sed -n '11,15p' tests/escalations.py` | the docstring now describes the shipped practice: "the entry goes with it, replaced in place by a `# RETIRED —` comment". `fields(Escalation)` is unchanged (`id, clause, unsatisfiable, owner_task, node_id`); `closed_by` remains `ProductEscalation`'s alone |

Beyond the six: `registry.PAIR_CHECKS` (row R22, and the seventh bad reference the
package sweep found) resolves nowhere in `gcp_grounding/` any more —
`preflight.py:512` and `engine.py:635`, `:752` now say "a provider's `PAIR_CHECKS` table
— read through `registry.pair_check`".

A package-wide sweep resolving every fully-qualified `:role:`gcp_grounding.…``
cross-reference (reading `__annotations__` as well as attributes, so annotation-only
frozen-dataclass fields are not false positives) found **292 distinct targets, none
unresolvable**.

---

## 6. README quotes, re-derived

The thirteen test modules that read `README.md` all pass:

```
python -m pytest -q tests/test_gcp_readme_walkthrough.py \
    tests/test_gcp_readme_three_input.py tests/test_gcp_readme_demo_steps.py \
    tests/test_gcp_run_demo.py tests/test_gcp_audit_docs.py \
    tests/test_gcp_examples_orgpolicy.py tests/test_gcp_agentic_benign.py \
    tests/test_gcp_sec_fixtures.py tests/test_gcp_iam_deny.py \
    tests/test_gcp_policy_gate.py tests/test_gcp_sec_parse.py \
    tests/test_gcp_sec_cli.py tests/test_gcp_drift_policy_flag.py
241 passed, 2 skipped, 2 xfailed          # exit 0
```

Independently of the suite, each quoted block a fix moved was re-derived by rerunning its
own command:

| quote | command | observed |
| --- | --- | --- |
| steps 10a / 10b / 10c | the three pinned `--provider-schema` runs | exit 1 / 1 / 0, as documented |
| `README.md:2285` — 10c's recap | the 10c run's `--explain` tail | `decision recap: APPROVED (exit 0) — grounded=8 unchecked=5`, matching the page's new `unchecked=5` |
| `README.md:1677` — the scenario-1 variation | scenario 1's command with and without `--provider-schema`, under the pin | the two reports are **byte-identical**; unpinned, the one difference is the `? [tf_schema]` ceiling line, exactly as the new sentence says |
| `README.md:2502` (R36) — `[firewall_reopen]` | scenario 5f | the run prints `e.g. src 0.0.0.0; dst 35.0.0.0; protocol 6; port 443` — bare, which is why the page now writes `src …; dst …` rather than `src (…)` |
| `README.md:2669` (R35) — the 12a listing | step 12a | exit 0; the three quoted `✓` lines sit at positions 15, 16 and 18 of twenty, with other `✓` lines between and after them — the gaps the page now marks `…` |
| `README.md:242` (R34) — the provenance convention | the same 12a run | **22 of 22** verdict lines end with `[snapshot <captured_at>]`, so the new page-wide sentence is true of every block |
| `README.md:1017` + `simple_readme.md:95-98` (R13) | `verify-policy --proposal examples/terraform/main.tf.json --snapshot … --no-config` | exit **0**, `PASSED — NOTHING VERIFIED (1 unchecked)`, `? [document] …: document kind was not recognized (top-level keys ['resource']) — nothing was checked` — the silent pass both pages now spell out |
| `README.md:1315` (R16) — the `--state-explain` drill-down | a live `--state-explain DOMAIN:KEY` run | the `chosen:` line carries `source`, `[kind]`, `origin`, `locator`, `captured_at`, `domain-scope`, `taint`; the page now quotes `origin=` and `captured_at=`, and the alternate's mandatory `record:` line |
| `README.md:482` (R37) — the walkthrough promise block | compared against `examples/walkthrough/requirements.md` | both `note:` lines are in the committed block and both are now quoted |
| `README.md:836` (R55) — arc `w`'s order | `run_demo.sh w` | step 1/3 compile, step 2/3 **the REST IAM allow policy**, step 3/3 the terraform binding — the order the amended sentence states |
| `README.md:1897-1945` (R57) — step 9a | the 9a command | exit 1, three findings, and all three quoted fragments present verbatim (whitespace-normalised for the page's line wraps) |

---

## 7. Per-row closure

`state` is **closed** (the proposed fix is in the tree and the defect no longer
reproduces), **no-change-by-design** (the source report marked the row "None needed"), or
**not closed**. Nothing in this table is a second opinion on whether the row was worth
fixing.

| # | sev | state | command | observed |
| --- | --- | --- | --- | --- |
| R01 | real-bug | closed | §3, five CLI cells over a fresh disputed row | all five as documented here; 3 of 5 diverge on `ded929a` |
| R02 | real-bug | closed | §3, emptied + absent + narrowed deny proposals | emptied → exit 1 with the woken-grant verdict; exit 0 `document kind was not recognized` on `ded929a` |
| R03 | real-bug | closed | `grep -n 'calls["n"]' tests/test_gcp_sec_ast.py` | `:451: assert calls["n"] == 1` — the `<= 1` that zero satisfied is gone |
| R04 | real-bug | closed | `env PYTHONPATH=tests/agentic/_blockimports GCP_TEST_BLOCK_IMPORTS=z3 pytest -q -rxXs tests/test_gcp_sec_cli.py` | `27 passed, 15 skipped, 1 xfailed`, **exit 0** (audit: 1 failed, exit 1). The case carries `@_needs_z3` at `:943` |
| R05 | broken | closed | §3 / §4, arcs 4 and 4b from a 400-day-old scratch copy | PASS on this tree, FAIL on `ded929a` |
| R06 | broken | closed | §3, README step 4 with its pin | exit 1 with the `✗ [role]` and the did-you-mean; both absent unpinned |
| R07 | hallucinated | closed | §5 H1 | `REMEDIES[0]` names `--target DOMAIN:KEY`, a flag argparse defines |
| R08 | hallucinated | closed | §5 H2 | "or the config key" gone from both sentences; the key still absent from `CONFIG_KEYS` |
| R09 | hallucinated | closed | §5 H3 | `knowledge.py:745` → `identity.SPECS` |
| R10 | hallucinated | closed | §5 H4 | five references re-pointed to `gcp_grounding.merge` |
| R11 | hallucinated | closed | §5 H5 | `ESC-ORGEFF-REGISTER-ACTIVATION` registered and heading the xfail reason |
| R12 | hallucinated | closed | §5 H6 | docstring corrected to the deleted-entry + `# RETIRED —` practice; no field added |
| R13 | misdocumented | closed | §6, the snapshot-only `.tf.json` run | the precondition and its silent-pass consequence are in `README.md:1019-1027` and `simple_readme.md:95-98`, and the run behaves as both now say |
| R14 | misdocumented | closed | `sed -n '100,122p' README.md` | the limits paragraph now carries "a REST allow-policy document names no project anywhere, so the estate-side masked and threaded arcs abstain on one by name … `--target iam_bindings:<key>` resolves a baseline row and does not supply it" |
| R15 | misdocumented | closed | §3, README step 3 with its pin | all three pieces of evidence present at exit 1 |
| R16 | misdocumented | closed | §6, a live `--state-explain DOMAIN:KEY` | the quoted `chosen:` line now carries `origin=` and `captured_at=`, and the alternate's `record:` line is quoted |
| R17 | misdocumented | closed | `grep -rn 'six domain\|eleven domain' gcp_grounding/sec_ast.py sec_requirements/README.md` | `sec_ast.py:16` and `:141` both read "eleven"; `len(sec_domains.COLLECTION_SPECS) == 11` |
| R18 | misdocumented | closed | count `\|`-rows in `sec_requirements/README.md` | the full collection table is now in the authoring guide: **15 rows** (4 seed + 11 domain), matching `len(sec_ast.COLLECTIONS)` after `register()` |
| R19 | misdocumented | closed | `sed -n '1p' gcp_grounding/registry.py` | "the sixteen later grounding-domain modules"; `len(PROVIDER_MODULES) == 16` |
| R20 | misdocumented | closed | `sed -n '7p' gcp_grounding/compare.py` | "nineteen category specs"; `len(identity.SPECS) == 19` |
| R21 | misdocumented | closed | `grep -n 'from_env' gcp_grounding/cli.py` | `:135`, `:150`, `:1168` all spell `sources.from_env`; `hasattr(sources.SourceOptions, 'from_env')` is `False`, `hasattr(sources, 'from_env')` is `True` |
| R22 | misdocumented | closed | `grep -rn 'registry.PAIR_CHECKS' gcp_grounding/` | no hits; `preflight.py:512` and `engine.py:635`, `:752` name the providers' tables read through `registry.pair_check` |
| R23 | misdocumented | closed | regex ``` ``<file>.py:<line>`` ``` over `gcp_grounding/` | **0 anchors remain** (audit: 16, 12 drifted). The report's own recommended option: `sec_artifact.py:446` now reads `:meth:`GcpSnapshot.load`.` with no line number |
| R24 | misdocumented | closed | in-process count + `grep` over the two files | `len(REQUIRED_MK_IDS) == 91`, `len(register()) == 44`, missing `47`; the prose says "the missing 47", and `escalations.py:291` records that the figures "are recomputed from `len(register())` / `len(REQUIRED_MK_IDS)`" |
| R25 | misdocumented | closed | `sed -n '20,55p' tests/agentic/budget.py`; `sed -n '300,315p' tests/escalations.py` | budget.py records "their union measures 474 spawns against the 488 below — MEASURED 2026-09-25", and cites R25 for the stale 408; escalations.py says "a full run spends 216 of the 216 marked spawns the ceiling allows", recomputed from `contract_spawn_ceiling()` (which returns 216) |
| R26 | misdocumented | closed | `grep -rn 'absent from this checkout\|in this checkout at all' tests/` | neither reason carries the clause any more; both stand on the surviving ground (`tests/mutation_entries.py` does not carry `REM-GX-HFW-FOLD`). Both files are present |
| R27 | dead-code | closed | `grep -rn 'mutually_exclusive_always_false'` | the method stays in vendored `core/` — the row's own proposed disposition — with `ESC-CORE-SOLVER-DEAD-PROBE` recorded in `PRODUCT_ESCALATIONS` and a case in `tests/test_gcp_audit_tests_and_registers.py` |
| R28 | dead-code | closed | `grep -rn 'add_all'` | kept and pinned (the row's second option): `tests/test_gcp_redact.py:334-349` asserts `add_all` is `add` in a loop and reports nothing |
| R29 | dead-code | closed | `grep -rn 'any_source'` | kept and pinned: `tests/test_gcp_sources.py:175-199` asserts `any_source is bool(options.configured())` and that zero is not an error |
| R30 | dead-code | closed | `grep -rn '_collection_rows'` | **0 sites** — deleted, as proposed |
| R31 | cosmetic | closed | `verify-policy --explain --state-explain` over a fresh corpus | `state used this run:` appears **once** here, **twice** on `ded929a`. The `--state-explain DOMAIN:KEY` form stays additive (its `state fact` block still prints) |
| R32 | cosmetic | closed | `--max-age {36h,90m,129600,30s,7d}` over a 15-day-stale snapshot | "past the **36 hours** / **90 minutes** / **36 hours** / **30 seconds** / **7 days** freshness limit". `_describe_limit(parse_duration('30s')) == '30 seconds'`; `_describe` still renders the measured age |
| R33 | cosmetic | closed | one bash-mutation hook event under each policy | `block` → exit 2, 614 B, names `--bash-policy=warn`; `warn` → exit 0, 555 B, **does not**; `off` → exit 0, byte-silent |
| R34 | cosmetic | closed | §6 | the page states the convention once, at `README.md:244-253`, and 22 of 22 real verdict lines carry the suffix it describes |
| R35 | cosmetic | closed | §6 | the three quoted 12a lines are non-contiguous in the real listing and the page now marks each gap `…` |
| R36 | cosmetic | closed | §6, scenario 5f | the gate prints `src 0.0.0.0; dst 35.0.0.0` bare; the page now writes `src …; dst …` |
| R37 | cosmetic | closed | §6 | both `note:` lines of the committed block are quoted |
| R38 | cosmetic | closed | regex `:role:`…` with no closing backtick on the line | **0 wrapped sites** (audit: 11; the fix task found 12, including one in a `#:` comment) |
| R39 | cosmetic | closed | `grep -n 'network_tag_exists' gcp_grounding/estate.py` | `:18` reads ``knowledge.GcpSnapshot.network_tag_exists``, which exists; the module-level name does not |
| R40 | cosmetic | closed | `pytest -q -s tests/test_gcp_mutation_contract.py::test_the_anchor_of_every_entry_resolves_on_content_and_drift_only_prints` | **0 `DRIFT` lines** printed (audit: 21), 1 passed |
| R41 | cosmetic | closed | `grep -n 'xfail_strict' pyproject.toml`; AST over `tests/` | `xfail_strict = true` at `:31`, with R41 cited in the comment. 26 `mark.xfail` calls, none spelling `strict=False`; the 10 that omit `strict=` are strict by the new default. A18's marker now names the registered `ESC-IAM-RUNTIME-ONLY-CONDITION` |
| R42 | note | closed | §4, the solverless arm | `run_demo.sh:22-26` states the fallback needs z3, **and** every run names the backend it resolved — both halves of the proposal |
| R43 | note | closed | `mutation_contract.removal_register()`; `grep -rn 'REMOVAL-CEILING'` | 19 removals, **none pending**; `contract_spawn_ceiling() == 216`; the three `ESC-GX-{NETWORK,VPCSC,ABSTAIN}-REMOVAL-CEILING` entries are `# RETIRED —` comments in `tests/escalations.py` |
| R44 | note | closed | `grep -c 'def test_' tests/test_gcp_examples_orgpolicy.py` | the module exists with 6 test functions and names every `5*` label — `5 5a 5b 5c 5d 5e 5f 5g` — closing the 7 rows no test named |
| R45 | note | closed | `grep -rn 'SA-SECAST-CALLED-ONCE\|ESC-GX-SPEC-002'` | closed by R03, as the row predicted: the entry is PRESENT rather than AWAITING, `OUT_OF_DOCUMENT_OWNERS` is empty, `ESC-GX-SPEC-002` is retired, and the suite's skip count fell 3 → 2 |
| R46 | note | closed | `sed -n '912,937p' tests/test_gcp_sec_cli.py` | `test_this_module_is_green_and_its_fallback_cases_run_in_a_solverless_child` runs the module in a z3-blocked child and asserts both `_needs_no_z3` cases report PASSED there |
| R47 | note | closed | a compiled-promise run's `--explain` tail | narrative `not checked  no-open-ssh-rdp-ingress [vpc_firewall]` (×3) and summary `promises in force : 6 enforcing (3 not checked), 2 not`, with `not checked` on each listed sentence — the count and the list agree |
| R48 | note | closed | reverse `grep` per `PRODUCT_ESCALATIONS` id | all 12 ids are quoted outside the register; the four the row named now sit in `sec_domains.py`, `iam_deny_checks.py` (×2 + `mutation_entries.py`). The one that cannot be quoted — `ESC-CORE-SOLVER-DEAD-PROBE`, in vendored `core/` — is in a declared `UNQUOTABLE_IDS` set with its reason |
| R49 | note | closed | `pytest -q tests/test_gcp_agentic_benign.py -k readme` | 2 passed. `test_the_corpus_readme_table_names_exactly_the_payloads_the_script_loads` compares the table's `file` and `lands as` columns against `BENIGN_SCRIPT` |
| R50 | note | closed | `sed -n '305,330p' tests/test_gcp_sec_evidence.py` | `assert lines[-2:] == ["      + compliant: (no pinned witness)", "      - violating:  (no pinned witness)"]` — extracted by index and compared with `==`, with a witness-count assertion beside it |
| R51 | note | closed | `grep -n 'byte_deterministic' -A 30 tests/test_gcp_sec_parse.py` | renamed `test_parse_text_is_byte_deterministic_across_processes_and_hash_seeds`, and it parses in children under three `PYTHONHASHSEED` values, citing R51 |
| R52 | note | closed | `grep -n 'compiled\|TEMPLATE' sec_requirements/README.md` | `:32-34` — "This directory holds `TEMPLATE.md` and this README … `sec_requirements/compiled/` exists only once you have written a" requirement. The directory does hold exactly those two files |
| R53 | note | closed | `grep -n 'categories with no' gcp_grounding/baseline.py` | `:774` reads "The **two** record categories with no entry"; `facts.TABLE_CATEGORIES - _PROJECTIONS` is exactly `{roles, resource_hierarchy}` |
| R54 | note | closed | `grep -n 'sec_parse\|sec_domains\|sx-sec-' sec_requirements/README.md` | the guide names `gcp_grounding/sec_parse.py` (`:5`) and `gcp_grounding/sec_domains.py` (`:131`); no `sx-*` task id remains in it |
| R55 | note | closed | §6, `run_demo.sh w` | the arc runs compile → REST policy → terraform, which is the order `README.md:837-839` now states |
| R56 | note | **no-change-by-design** | the five `5b`–`5f` arcs and arc `w`'s REST step, run in §4 | all six prose-documented commands behave as the page says (24/24 arcs PASS); the source report marked this "None needed; recorded as coverage", and no change was made |
| R57 | note | **no-change-by-design** | `verify-policy --proposal examples/terraform-masked/base.tf.json --snapshot … --terraform-state … --explain` | exit **1**, three findings, all three quoted fragments byte-exact; `\| 9a \|` matches no at-a-glance row, which `README.md:1971-1973` says is deliberate. No change was made |

---

## 8. Limits of this verification

Stated so the coverage above is not read wider than it is.

* **The five source audits were not re-run.** A defect none of them found is still not
  found. This task re-ran each row's own evidence, not each row's whole surface.
* **The pre-fix control is `ded929a`, not the audit's `90248ba`.** `90248ba` is not a ref
  in this repository; `ded929a` is the commit the reports were committed on and the
  baseline the fix design names. Every control divergence reported in §3 reproduced there.
* **R02's narrowing arm could not be reproduced on this fresh corpus.** Both exception
  spellings tried fall outside the curated v1→v2 containment table, so that arm abstains
  identically on both trees. R02's closure rests on the emptied arm plus the pre-fix
  control, which is what the row is about.
* **The role sweep in §5 is scoped to fully-qualified targets** (`:role:`gcp_grounding.…``)
  inside `gcp_grounding/`. The audit's 907 distinct targets include relative spellings and
  `tests/`; 292 is this sweep's own denominator, not a re-measurement of theirs.
* **R32's sub-day spellings were measured through the CLI over a stale fixture**, not over
  every duration token the parser accepts.
* **Cloud Armor, hierarchical firewall policies and VPC-SC** were no more exercised here
  than by the source audits — `REPORT.md` §4 names that as the wave's largest behavioural
  gap and it is unchanged.
* **`--llm` / `sec_llm`** was not exercised, for the same reason.

---

## Appendix — every command run for this report

Interpreter `/home/jones/Downloads/gcp-policy-grounding/.venv/bin/python` (CPython 3.14.7,
z3 present), `PYTHONPATH` pinned at this worktree, cwd the worktree root unless a scratch
copy is named. Exit codes captured directly from each process.

```
# the suite
python -m pytest -q tests/                               # 4591 passed, 2 skipped,
                                                         # 15 xfailed — exit 0
python -m pytest -q <the 13 README-reading modules>      # 241 passed, 2 skipped,
                                                         # 2 xfailed — exit 0

# the demos, from a git archive scratch copy with venv exec shims
git archive --format=tar HEAD  | tar -x -C <scratch>/demo/repo
git archive --format=tar ded929a | tar -x -C <scratch>/mainctl/repo
env -i PATH=<PATH> bash run_demo.sh --list               # 24 scenarios
env -i PATH=<PATH> bash run_demo.sh <label>              # each of the 24, twice:
                                                         # export mtimes, then -400d
GCP_GROUND=<z3-blocking shim> bash run_demo.sh 3         # the builtin arm

# the fresh-corpus re-probes (R01, R02), each against both trees
verify-policy <r01>/violating.json --snapshot <r01>/snapshot.json \
    --merge-source <r01>/tfview.json --origins <r01>/snapshot.origins.json \
    --as-of 2026-09-21T00:00:00Z --no-config --format json [--drift-policy FLAG]
verify-policy --proposal <r02>/wake_{removed,absent,excepted}.json \
    --baseline <r02>/baseline.json --snapshot <r02>/snapshot.json \
    --as-of 2026-09-21T00:00:00Z --no-config

# the README demo steps (R06, R15), pinned and unpinned
GCP_GROUNDING_NOW=2026-07-25T12:00:00Z verify-policy \
    tests/fixtures/gcp/agentic/iam/A10_owner_to_external.policy.json \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json --requirements <out> --explain
GCP_GROUNDING_NOW=2026-07-18T12:00:00Z verify-policy \
    tests/fixtures/gcp/policies/iam_policy_bad.json \
    --snapshot tests/fixtures/gcp/snapshot.json

# the quoted blocks
GCP_GROUNDING_NOW=2026-07-25T12:00:00Z verify-policy --proposal \
    examples/terraform-schema/proposal_{typo,newer,ok}.tf.json --snapshot … \
    --provider-schema examples/terraform-schema/provider-schema.json --explain
verify-policy --proposal examples/terraform/main.tf.json --snapshot … \
    --terraform-state examples/terraform/terraform.tfstate [--provider-schema …]
verify-policy --proposal examples/terraform-orgpolicy/proposal_egress_world.tf.json …
GCP_GROUNDING_NOW=2026-07-18T12:00:00Z verify-policy --proposal \
    examples/terraform-denypolicy/plan_base.json … --explain
verify-policy --proposal examples/terraform-masked/base.tf.json … --explain
verify-policy --proposal examples/terraform/main.tf.json --snapshot … --no-config
verify-policy … --state-explain iam_bindings://cloudresourcemanager.googleapis.com/…
bash run_demo.sh w

# the cosmetics (R31, R32, R33, R47), against both trees where a control helps
verify-policy <c>/policy.json --snapshot <c>/snapshot.json --no-config \
    --explain --state-explain
verify-policy <c>/policy.json --snapshot <c>/snapshot.json --no-config --max-age <token>
verify-policy --hook --bash-policy {block,warn,off} --snapshot <c>/snapshot.json \
    --no-config   < a PostToolUse Bash event

# the z3-blocked world (R04, R46)
env PYTHONPATH=tests/agentic/_blockimports GCP_TEST_BLOCK_IMPORTS=z3 \
    python -m pytest -q -rxXs tests/test_gcp_sec_cli.py     # exit 0

# the registers and the static rows
python -m pytest -q -s tests/test_gcp_mutation_contract.py::\
    test_the_anchor_of_every_entry_resolves_on_content_and_drift_only_prints
python -m pytest -q tests/test_gcp_agentic_benign.py -k readme
# in-process: len(REQUIRED_MK_IDS)=91  len(register())=44  missing=47
#             contract_spawn_ceiling()=216  MAX_SUBPROCESS_SPAWNS=488
#             len(PROVIDER_MODULES)=16  len(identity.SPECS)=19
#             len(sec_domains.COLLECTION_SPECS)=11  len(baseline._PROJECTIONS)=6
#             removal_register()=19, none pending
#             AST over tests/: 26 mark.xfail calls, none strict=False
#             292 fully-qualified role targets in gcp_grounding/, none unresolvable

# the hallucination register, with REPORT.md §3's own commands
grep -rn "baseline-target" gcp_grounding/ tests/ README.md simple_readme.md
grep -n  "or the config key" gcp_grounding/sources.py
grep -rn "CATEGORY_SPECS" gcp_grounding/
grep -n  "tfsource.merge" gcp_grounding/tfsource/map_network.py
grep -rn "ORG-EFFECTIVE-REGISTER-ACTIVATION" --include='*.py' --include='*.md' .
sed -n '11,15p' tests/escalations.py
grep -rn "registry.PAIR_CHECKS" gcp_grounding/

# this task wrote no repository file but this one
git diff --name-only agent/fix-docs -- gcp_grounding tests examples run_demo.sh \
    README.md simple_readme.md sec_requirements pyproject.toml     # empty
git status --porcelain                                             # clean
git grep -In -i -e <vendor> -e <account> -- .                       # 0 hits outside audits/
```
