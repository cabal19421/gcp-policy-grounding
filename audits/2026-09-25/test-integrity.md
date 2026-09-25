# Audit: does the suite prove what it appears to prove?

**Task:** `audit-test-integrity`, from `designs/gcp-codebase-audit.md`.
**Tree:** `gcp-policy-grounding` at `90248ba` ("Merge the output-quality chain…"),
read through the worktree `agent/audit-test-integrity`. Nothing was fixed; the
only file this task writes is this report.

---

## Scope

Whether the 4,456 tests the suite reports as passing are really load-bearing:
vacuous tests, self-satisfying assertions, permanently disarmed nodes, fixtures
nothing reads, assertion weakenings in recent history, the spawn budget's stated
versus measured cost, and the pins that anchor the README to the code.

## Method

Every command below was run from the worktree root with the oracle's interpreter,
`/home/jones/Downloads/gcp-policy-grounding/.venv/bin/python` (Python 3.14.7, z3
5.0.0). Exit codes were captured directly with `echo "…=$?"`, never through a pipe.
Scratch probes live under the task scratchpad; none was written into the repo.

| # | Probe | What it produced |
|---|---|---|
| 1 | `python -m pytest -rxXs tests/` ×2 | the skip/xfail inventory, and the determinism comparison |
| 2 | the same run under a `sys.addaudithook` pytest plugin (`-p auditplug`, loaded off `PYTHONPATH`) | every `open()` of a path under `tests/fixtures/`, every `subprocess.Popen` argv naming one, and `SubprocessBudget`'s per-label counts captured at session teardown |
| 3 | AST walk of all 152 test modules (3,081 `test*` functions) | no-assert / assert-on-constant / swallowed-AssertionError census |
| 4 | second AST walk | self-comparing assertions, and tests whose every assertion is on a mock they configured |
| 5 | third AST walk over every `pytest.mark.xfail` call | strictness and reason of each marker |
| 6 | `git show --unified=0` over the 194 non-merge commits touching `tests/` since 2026-07-27 (60 days) | deleted asserts, `==`→`in`, widened bounds, added xfail/skip, dropped `strict=True` — each read against its commit subject |
| 7 | direct in-process probes of `sec_ast`, `tests.mutation_contract`, `tests.test_gcp_mutation_contract` | the measured values behind three documented ones |
| 8 | a fresh `compile-requirements examples/walkthrough` | an independent re-derivation of the artifacts README.md quotes |
| 9 | the suite re-run with `GCP_TEST_BLOCK_IMPORTS=z3` | what the `_needs_no_z3` world actually looks like |

Baseline, run 1 and run 2 (`-rxXs`):

```
=========== 4456 passed, 3 skipped, 19 xfailed in 115.93s (0:01:55) ============
=========== 4456 passed, 3 skipped, 19 xfailed in 110.12s (0:01:50) ============
```

Exit 0 both times. **0 xpassed, 0 failed, 0 errors.**

One probe is worth stating carefully because its blast radius is easy to
over-read. Re-running the whole suite with z3 blocked in the **parent**
interpreter gives `52 failed, 4180 passed, 227 skipped, 19 xfailed` (exit 1), but
that number is an upper bound, not an attribution: `hookrunner.SCRUBBED_ENV` does
not scrub `PYTHONPATH`/`GCP_TEST_BLOCK_IMPORTS`, so the block also reaches every
spawned child, including the many that are written expecting a solver. Only
failures reached **in-process** are attributable, and TI-02 below is cited from a
single-module run for exactly that reason.

---

## Findings

| id | severity | location | claim | evidence | proposed fix (NOT applied) |
|---|---|---|---|---|---|
| **TI-01** | real-bug | `tests/test_gcp_sec_ast.py:448` | `test_ensure_domains_called_at_most_once` proves the lazy domain resolution is attempted exactly once. | The assertion is `assert calls["n"] <= 1`, which zero calls satisfies. Probed in-process: on clean source `calls["n"] = 1`, so `== 1` would pass today; with `sec_ast._ensure_domains` stubbed to a no-op, `calls["n"] = 0` and **`<= 1` still passes** — the mutant that removes the lazy resolution entirely survives. `tests/spec_assertions.py:210-215` registers `SA-SECAST-CALLED-ONCE` with `predicate='calls["n"] == 1'`, i.e. the register itself names `== 1` as the required text. | Restore `assert calls["n"] == 1`. |
| **TI-02** | real-bug | `tests/test_gcp_sec_cli.py:910-937` | `test_no_sec_verdict_carries_a_line_number` is solver-independent: it carries no `_needs_z3` marker, unlike the eleven tests above it. | Its closing non-vacuity assertion is `assert any(v.kind.startswith("sec:") for r in reports for v in r.verdicts)` (line 937). With no solver, no promise compiles, `sec_rules.load_directory` loads no rule, and no `sec:` verdict is ever minted. `PYTHONPATH=tests/agentic/_blockimports GCP_TEST_BLOCK_IMPORTS=z3 python -m pytest -q -rxXs tests/test_gcp_sec_cli.py` → `1 failed, 27 passed, 13 skipped, 1 xfailed`, exit 1, failing in-process at `tests/test_gcp_sec_cli.py:937` with `assert False`. That is the same world the module's own `_needs_no_z3` marker (line 76) exists to serve, and the fallback the product advertises (`solver.py:117` logs "falling back to the builtin solver; arity answers are identical"). The defect is in the test's guard, not in the product, and it does not affect the documented `.[dev]` install. | Mark the test `@_needs_z3`, or branch the non-vacuity assertion on `HAVE_Z3` the way the module's other solver-sensitive cases do. |
| **TI-03** | misdocumented | `tests/test_gcp_mutation_contract.py:215-216`; `tests/escalations.py:268-286`; `tests/escalations.py:612` | The mutation register's shortfall is "44 of the 65 … the missing 21", and `REQUIRED_MK_IDS` "grew to 77". | Measured in-process: `len(REQUIRED_MK_IDS) == 91` (also asserted at `tests/test_gcp_mutation_contract.py:204`), `len(register()) == 44`, so **47 required ids are absent**, not 21 — the whole `MK-D*` (12), `MK-E*` (7), `MK-F*` (14), `MK-H*` (5), `MK-O*` (2), `MK-S*` (2) and `MK-V*` (5) families. Three different figures (65, 77, 91) are in the tree at once. Nothing tests the prose: `tests/test_gcp_escalations.py` checks an escalation's shape, id uniqueness, strict-xfail marking, node collectibility, clause anchoring and owner existence — never whether the numbers in `unsatisfiable` are still true. | Recompute the two reasons from `len(REQUIRED_MK_IDS)` / `len(register())` rather than quoting a literal, or add a register self-test that fails when a quoted count drifts. |
| **TI-04** | note | `tests/mutation_contract.py:515-520`; `tests/mutation_entries.py` | The mutation contract executes the register on every full run. | The contract's own ceiling is `4*44 + 19 + 16 = 211`, and the instrumented run measured **marked spawns 211 / ceiling 211 — zero headroom**. Five `Removal`s are `pending` and therefore never executed: `RM-HOOK-SUCCESS-BEFORE-THE-EVENT`, `RM-NETWORK-PLANE-UNAVAILABLE`, `RM-VPCSC-ABSENT-VERSUS-EMPTY`, `RM-VPCSC-DOCUMENT-AND-PAIR-CHECKS`, `RM-VPCSC-DOMAIN-UNREGISTERED`. Three strict xfails say so in as many words — e.g. `ESC-GX-VPCSC-REMOVAL-CEILING`: "all three removals KILL … but the frozen spawn ceiling has zero headroom". So five mutations that are recorded as proven-to-kill are not run by the oracle, and the reason is a budget, not a technical one. | Raise `contract_spawn_ceiling`'s per-entry accounting (or `SPAWNS_PER_ENTRY`) by the five children, then flip the five `pending` flags; the three xfails then XPASS and force deliberate retirement, which is the mechanism working as designed. |
| **TI-05** | misdocumented | `tests/agentic/budget.py:28`; `tests/escalations.py:295` | "their union measures 408 spawns in a full run"; the machinery "spends 192 of the 199 marked spawns `contract_spawn_ceiling()` allows". | Instrumented full run: unmarked **474** spawns against `MAX_SUBPROCESS_SPAWNS = 488` (14 of headroom), marked **211** against a ceiling of **211**. Both quoted numbers describe earlier trees. The arithmetic the comment documents is still exactly right (450→466→478→488 tracks 456→466→474 measured); only the prose figures are stale. | Re-state the two sentences with the measured 474/488 and 211/211, or drop the absolute numbers and keep the per-raise accounting. |
| **TI-06** | note | `tests/test_gcp_run_demo.py:25-27`; `README.md:1621-1648` | The suite is the conformance pin between the README's at-a-glance table, the `run_demo.sh` arcs and the committed proposals. | The table has 24 scenarios and `run_demo.sh` defines 24 labels, but `test_gcp_run_demo.py` executes exactly three arcs end to end — `demo("3c")` (line 133), `demo("4")` (144), `demo("w")` (156); the remaining four invocations are `--list` twice, a `4c` run against a stub `GCP_GROUND` that returns an undocumented exit (174), and `demo("42")`, a label the README does not name (182). What `--list` pins is the *enumeration*, not the verdicts. Cross-referencing each table row's proposal against every `tests/**/*.py`: **7 of 24 rows are named by no test at all** — `5` (`base.tf.json`), `5b`, `5c`, `5d`, `5e`, `5f`, `5g`, the whole `examples/terraform-orgpolicy/` family bar one. Only `proposal_serial_and_publicip.tf.json` is used, and only by two `tests/test_gcp_cli_summary.py:465,556` cases that pin `--explain` sentences, not the row's documented verdict. So README claims like "APPROVED — all eleven promises hold" (row 5) and "DENIED — `vpc-externally-peered-vpc-gcp` + `compute-disable-internet-neg` VIOLATED" (row 5c) are asserted nowhere. | Add a `tests/test_gcp_examples_orgpolicy.py` in the shape of the existing `test_gcp_examples_{masked,roles,schema,denypolicy,terraform}.py` modules, pinning each 5* row's exit and named promises. |
| **TI-07** | note | `tests/test_gcp_spec_assertions.py:256`; `tests/spec_assertions.py:265,279` | An `AWAITING` entry is temporary — "an entry whose owner will never land is a permanent excuse wearing an owner's name" (`tests/test_gcp_spec_assertions.py:336-339`). | `SA-SECAST-CALLED-ONCE`'s owner is `sx-sec-ast`, a task of the **predecessor** design document, which `tests/spec_assertions.py:271-280` records as structurally un-ownable in this document and routes to `ESC-GX-SPEC-002`. That escalation's own node (`test_every_awaiting_owner_is_a_task_in_this_document`) is `xfail(strict=True)`. The net effect is that TI-01's weakening is (a) skipped by the register, (b) excused by a mapping, and (c) the assertion that would object is strict-xfailed — three mechanisms, none of which can redden. This is one of the 3 skips in every run. | Either fix TI-01 (which retires the entry outright) or re-own `SA-SECAST-CALLED-ONCE` to a task in the current document. |
| **TI-08** | note | `tests/test_gcp_sec_cli.py:76,871,892` | The two `_needs_no_z3` tests "say what the no-solver world must look like, and they only run there" (`tests/test_gcp_sec_cli.py:863-867`). | They are 2 of the 3 skips in every run, with reason "a solver is available, so the fallback backend is not live". `pyproject.toml` puts z3 in both the `z3` and the `dev` extra, and `README.md:141,1603` install `.[dev]` — so in the documented configuration these two positive assertions about the fallback backend never execute at all, and the world they describe is (per TI-02) not green. | Run the module once in a z3-blocked child as part of the suite (the `blocked_import_env` machinery already exists), so the fallback-backend claims are exercised somewhere. |
| **TI-09** | note | `tests/fixtures/gcp/agentic/benign/README.md` | "Every document in this directory is a payload of the twelve-proposal script in `tests/test_gcp_agentic_benign.py`." | The instrumented run shows **156 of 157** files under `tests/fixtures/` are opened by the pytest process or named in a child's argv. The single exception is this README itself — so its own sentence does not hold of it, and, more usefully, its 12-row `file → lands as → why it is benign` table is pinned by no test while `BENIGN_SCRIPT` (`tests/test_gcp_agentic_benign.py:122`) is the real list. A row renamed on one side would not be noticed. | Add one assertion in `test_gcp_agentic_benign.py` comparing the README table's `file` column to the payload names `BENIGN_SCRIPT` loads, the way `test_gcp_run_demo.py` pins the at-a-glance table. |
| **TI-10** | note | `tests/test_gcp_sec_parse.py:268-270` | `test_parse_text_is_byte_deterministic` proves `parse_text` is byte-deterministic. | Its only assertion is `assert m.parse_text(text, "iam.md") == m.parse_text(text, "iam.md")` — two calls in one interpreter. Within a process, `dict`/`set` iteration order is already stable, so this can only catch a clock, a counter or an RNG, not the hash-seed-dependent ordering that "byte-deterministic" is usually about. Contrast `tests/test_gcp_redact.py:76,83`, where the same shape is backed by two real cross-process pins. | Compare against a child-process parse of the same text, as `test_gcp_redact.py` does, or rename the test to what it checks. |
| **TI-11** | note | `tests/test_gcp_sec_evidence.py:313-314` (commit `65dcbcf56`, "verify-policy --explain: a decision narrative, not a dump") | The test pins the exact witness lines the explainer emits. | The commit turned `assert positive == "      + compliant: (no pinned witness)"` / `assert negative == "…"` — equality on two *extracted* lines — into `assert "…" in lines` for each. The restructure the commit subject declares plausibly moved the lines, so the change is justified; what was silently dropped alongside it is the *position*, and with it the guarantee that no other witness line was emitted. It is the only genuine `==`→`in` loosening in 60 days of history: the scan raised 44 candidates, and the other 43 were all its own artefact — a `--unified=0` hunk in which an *added* message-content assertion (`assert "…" in verdict["message"]`) sits beside an unrelated *removed* status assertion (`assert v.status == "unverified"`), i.e. tests being strengthened, not loosened. | Re-extract the two lines by index and compare with `==`, or assert the full witness block. |
| **TI-12** | cosmetic | `pyproject.toml` `[tool.pytest.ini_options]`; `tests/test_gcp_agentic_iam.py:554-559` | Every xfail in the suite is strict, so an escalation cannot outlive its cause. | True today — all 20 `pytest.mark.xfail` calls pass `strict=True` — but `xfail_strict` is **not** set in the ini, so a future marker that omits it is silently non-strict, and the enforcement in `tests/test_gcp_escalations.py:140` covers only node ids that are *in the escalation register*. `tests/test_gcp_agentic_iam.py:554` is already outside it: a strict xfail on the `A18_cel_outside_subset` case whose reason names a product cause and no `ESC-` id, so no register forces its retirement (`tests/integration_repins.py` does not carry it either). | Set `xfail_strict = true` in `[tool.pytest.ini_options]`, and either register A18's escalation or point its reason at an existing id. |

---

## Verified true

Each of these was checked and **held**; they are listed so the reader can see the
coverage, not only the failures.

### The run itself

* **Determinism.** Two full `-rxXs` runs produced byte-identical `short test
  summary info` sections (24 lines each, diffed after normalising the wall-clock
  duration) and identical counts: `4456 passed, 3 skipped, 19 xfailed`, exit 0.
  A third run under the audit plugin reported the same three numbers again.
* **No XPASS, no flake.** `XFAIL 19 / XPASS 0 / SKIPPED 3 / FAILED 0 / ERROR 0`
  in both runs.
* **The clock is pinned once, session-wide.** `tests/conftest.py:_pin_the_clock`
  sets `GCP_GROUNDING_NOW=2026-07-18T12:00:00Z` for the whole session and
  restores it at teardown, so the fixture-era snapshots do not start failing the
  seven-day freshness ceiling a week after they were authored. `_scrub_sec_llm_env`
  removes the three `GCP_SEC_LLM*` names so no in-process test can reach a real
  runner, and `_apply_contract_removal` applies `GCP_TEST_REMOVAL` **after**
  collection via `pytest.MonkeyPatch`, so a removal cannot skip its own witnesses.

### Vacuity

* **No vacuous assertions.** Across 3,081 `test*` functions in 152 modules: **0**
  `assert True`, `assert 1`, `assert <non-empty literal>`, or `assert ...`; and a
  separate walk found **0** asserts comparing only constants to each other.
* **No test lacks proof.** Six functions carry no `assert` statement — all in
  `tests/test_gcp_sec_ast.py` (`test_every_node_kind_validates_clean:132`,
  `test_ip_and_cidr_literals:161`, `test_port_literal_boundary_table:485`,
  `test_proto_literal_boundary_table:493`,
  `test_int_literals_carry_no_port_or_proto_range:497`,
  `test_port_in_bounds_table:507`). Each asserts by *does-not-raise*: the module's
  `m.validate` raises `InvalidAst` on a bad node, and the three parametrized
  tables go through `_decide` (`tests/test_gcp_sec_ast.py:473-477`), which uses
  `pytest.raises(InvalidAst)` on the reject side. These are real assertions my
  scanner could not see through a helper, not holes.
* **No swallowed assertion errors.** One `except Exception:` in a test body,
  `tests/test_gcp_agentic_plumbing.py:220`, and it is the opposite of a swallow:
  it re-derives `HAVE_ESTATE_CATEGORY` from a real `GcpSnapshot.from_dict` call
  and then asserts the flag against the result (line 222), alongside a concrete
  `assert env.HAVE_ESTATE_CATEGORY is True` pin at line 210.
* **No mock-only tests.** One candidate,
  `tests/test_gcp_fetch.py:281 test_run_terraform_schema_surfaces_failure`, whose
  every `assert` names a mock attribute — but it also wraps the call in
  `pytest.raises(RuntimeError, match="No configuration files")`, and the two
  mock-attribute assertions pin the **argv and cwd the production code passed**
  (`["terraform","providers","schema","-json"]`, `cwd="/repo/infra"`), which is a
  claim about the code, not about the double.
* **Self-comparing assertions are determinism checks, not tautologies.** Six
  `assert f(x) == f(x)` shapes exist (`test_gcp_redact.py:73`,
  `test_gcp_report.py:178`, `test_gcp_sec_artifact.py:93`,
  `test_gcp_sec_ast.py:359`, `test_gcp_sec_llm.py:166`, `test_gcp_sec_parse.py:270`).
  Five are paired with a strictly stronger sibling assertion in the same test or
  the next one — `report` also compares against `json.dumps(bad.to_dict(), …)`,
  `sec_artifact` also pins order-independence, `sec_ast` also pins argument
  re-ordering, `redact` has two cross-process pins at lines 75 and 82. Only
  `sec_parse`'s stands alone (TI-10).
* **`assert env.HAVE_X is measured.live` is acknowledged, not hidden.**
  `tests/test_gcp_agentic_plumbing.py:96` is `X is X` by construction —
  `tests/agentic/env.py:135-148` *defines* each flag as
  `capabilities.probe(...).live`. The test's own docstring says exactly that and
  carries three concrete `is True` pins (lines 158-160) plus independent
  `kind in KINDS` and `importlib.util.find_spec` conjuncts, so the node still
  bites if a checker regresses.

### Skips and xfails

* **There is not one unconditional skip in the suite.**
  `grep -rn "pytest.mark.skip(" tests --include='*.py'` → no output, exit 1.
  Every skip is a `skipif` on a measured capability or a runtime `pytest.skip`
  with a stated reason.
* **All three skips in a normal run are explained, and two are environmental.**
  `tests/test_gcp_sec_cli.py:870` and `:891` ("a solver is available, so the
  fallback backend is not live" — see TI-08), and
  `tests/test_gcp_spec_assertions.py:256` ("SA-SECAST-CALLED-ONCE: awaiting
  sx-sec-ast, which owes this predicate" — see TI-07).
* **All 20 `pytest.mark.xfail` markers are `strict=True`.** AST-verified; the
  `NOT strict=True` list is empty. A strict xfail cannot rot into silence — the
  day its cause is fixed it XPASSes and reddens.
* **19 of 20 xfail reasons name a registered escalation id**, and
  `tests/test_gcp_escalations.py:140` enforces the coupling in both directions
  for every registered node (strict marker present, reason names *this* id, node
  collectible, owner a real task, clause anchored in the design corpus). The one
  exception is A18 (TI-12).
* **The escalation self-test is itself tested.** `tests/test_gcp_escalations.py:200-218`
  drives its own AST checker over four synthetic sources: a good strict xfail, a
  dropped `strict=True`, a marker naming the wrong id, and an absent node.

### Fixtures

* **156 of 157 files under `tests/fixtures/` are reached by a full run** — 152
  opened directly in the pytest process (recorded by an audit hook on the `open`
  event) and a further 12 named in a spawned child's argv, overlapping. The one
  exception is the reviewer-facing `benign/README.md` (TI-09). A purely textual
  scan flags 55 more as "unreferenced", but that is a false positive: the agentic
  catalogues build their paths from case ids (`f"{case.id}.policy.json"`), which
  the instrumented run resolves.

### The spawn budget

* **The budget is real, it is bound where no module can opt out, and it bites.**
  `tests/conftest.py:_bind_subprocess_budget` is session-scoped and autouse, so
  every `hookrunner` spawn lands on the counter. Measured at teardown:

  ```
  unmarked 474 / ceiling 488      marked 211 / ceiling 211
  top labels: hook_envelope 55, agentic_sequence 54, hook_bash 36,
              hook_tool_scope 32, agentic_iam 29, agentic_secreq 29, …
  marked:     mutation_contract.run_nodes 112, .materialise 98, 1 other
  ```

  The unmarked total sits under its ceiling with 14 to spare; the contract's own
  ceiling is exactly consumed (TI-04). The teardown check is exercised
  independently: the instrumented run also captured two stub budgets, one of
  which is deliberately driven to `3 / ceiling 2` by the plumbing tests so the
  `AssertionError` path is covered without spawning anything.
* **Marked and unmarked spawns are routed by the child's own environment**
  (`SubprocessBudget.increment(label, env=…)` reads `GCP_MUTATION_CONTRACT_CHILD`
  from the env actually handed to the child), so the contract cannot borrow the
  suite's headroom.

### README pins

* **No test pins a README *line number*.** Every README anchor in the suite is a
  content fragment: ` ```text ` blocks (`tests/test_gcp_readme_walkthrough.py:53`),
  ` ```bash ` and ` ```json ` blocks (`tests/test_gcp_readme_three_input.py:15-16`),
  `### ` headings, and `| a | b | c | d |` table rows
  (`tests/test_gcp_run_demo.py:55`). Nine test modules read `README.md`.
* **The quoted fragments still match, verified independently of the suite.** A
  fresh `python -m gcp_grounding compile-requirements examples/walkthrough
  --snapshot tests/fixtures/gcp/agentic_snapshot.json --out <scratch>`
  (exit 0) produced

  ```
  (exists ((b iam_bindings)) (and (not (suffix b.member "@acme.example")) (eq b.role "roles/owner")))
  ```

  which is an exact substring of `README.md`, and a source citation
  `examples/walkthrough/requirements.md:25` which is also quoted there verbatim.
* **The `--list` ↔ table ↔ `examples/` triangle is pinned**, even though the arcs
  themselves are not all run (TI-06): `test_list_enumerates_exactly_the_readme_table`,
  `test_every_listed_scenario_names_a_proposal_under_examples`, and
  `test_a_scenario_the_readme_does_not_name_is_refused`.

### 60 days of history

194 non-merge commits touched `tests/` since 2026-07-27. Every hunk matching a
weakening pattern was read against its commit subject.

* **Every `strict=True` removal was a marker being retired, not relaxed.** Seven
  hits; all seven are the *deletion of a whole xfail block* as its escalation was
  closed (`28686a49a` "Land the IAM repin's deferred half and retire
  ESC-GX-IAM-REPIN-SPLIT", `fa163e4a7`, `f6eaff244`) or prose in a docstring. No
  surviving marker lost its strictness — confirmed against the tree by the AST
  scan above. **Zero `strict=False` anywhere in `tests/`.**
* **Every widening replaced an assertion with an equal-or-stronger one, in the
  same commit, with the reason written down.**
  - `841e137d1`, `d84e3bb34`, `9e847b33b` turned
    `assert registry.document_checks() == ()` into a per-owner subset. The tree
    today (`tests/test_gcp_registry.py:242-244`) carries
    `assert by_module.get(module, set()) == names, module` for every module in
    `DOCUMENT_CHECK_OWNERS` — a per-module **equality**, strictly stronger than
    the subset the branch wrote, with a 10-line comment explaining why the old
    `== ()` could no longer hold once domain modules landed.
  - `f6eaff244` replaced `assert len(removal_register()) == 7` with
    `RC2_REMOVAL_IDS <= ids`; the tree pairs it with
    `pending <= RC2_REMOVAL_IDS` and `len(pending) <= PENDING_REMOVAL_MAX`
    (`tests/test_gcp_mutation_entries.py:95-102`), i.e. grow-only on one axis and
    shrink-only on the other, which a bare count could not express.
  - `b0170f69e` replaced `len(annotated) == len(blocked) == 2` with a named-key
    subset; `tests/test_gcp_agentic_tf_drift.py:944` still asserts
    `set(annotated) == set(blocked)` beside it.
  - `f95c55c33`'s pair belongs to a rewritten test whose docstring records the
    re-measurement ("10 of 10 now fail here") and which is accompanied by a new
    `test_no_case_false_blocks_on_a_resource_type`.
* **Every deleted assert was replaced or re-landed.** 29 hunks. The dominant
  shape is a run of per-index assertions collapsing into one list equality
  (`20f52936b`, `a1ab2d639` — `assert lines[0] == …; assert lines[1] == …`
  becoming `assert lines == [ … ]`), which is stronger, not weaker. The
  catalogue repins (`f95c55c33`, `79f4b7b82`, `4b562f7da`, `a93d2984d`) delete
  generic channel assertions and add case-specific message assertions in the same
  hunk. The one commit that removed an exit-code assertion without replacing it,
  `a72bf2752`, was caught and repaired by name four commits later: `ebf878ac4`
  "Pin the promise arm's run outcome in BOTH worlds, **where the deleted
  exit-code assertion left a hole**".
* **Added xfails and skips are accounted for.** 117 added-xfail and 58
  added-skip lines, all of them either (a) a strict xfail whose reason names an
  escalation registered in `tests/escalations.py` in the same commit, or (b) a
  `skipif` on a measured capability (`HAVE_Z3`, `capabilities.probe(...).live`,
  `find_spec`). No commit in the window adds a bare `pytest.mark.skip`.

---

## Appendix A — the 3 skips and 19 xfails, verbatim

Skips (identical in both runs):

```
SKIPPED [1] tests/test_gcp_sec_cli.py:870: a solver is available, so the fallback backend is not live
SKIPPED [1] tests/test_gcp_sec_cli.py:891: a solver is available, so the fallback backend is not live
SKIPPED [1] tests/test_gcp_spec_assertions.py:256: SA-SECAST-CALLED-ONCE: awaiting sx-sec-ast, which owes this predicate
```

Xfails, by cause:

| group | nodes | cause |
|---|---|---|
| spawn ceiling (TI-04) | `agentic_abstain::test_the_hook_success_removal_is_live_in_the_contract`, `agentic_network::test_the_network_plane_removal_is_live_in_the_contract`, `agentic_vpcsc::test_the_vpcsc_removals_are_live_in_the_contract` | `ESC-GX-{ABSTAIN,NETWORK,VPCSC}-REMOVAL-CEILING` — the removals kill, the budget has no room |
| register not seeded | `mutation_contract::test_every_required_must_kill_id_is_in_the_register`, `mutation_contract::test_this_gate_can_afford_to_execute_every_active_mutation_itself`, `mutation_entries::…`, `hfw_checks::test_the_folds_mutation_entry_is_seeded_in_the_in_repo_contract`, `iam_deny_checks::test_the_deny_mutation_entries_are_active_in_the_register`, `org_effective::test_the_org_effective_mutation_entries_are_active_in_the_register` | `ESC-GX-GATE-001/002`, `ESC-GX-SEEDA-001`, `ESC-GX-HFW-FOLD-ENTRY`, `ESC-DENY-REGISTER-ACTIVATION`, `ORG-EFFECTIVE-REGISTER-ACTIVATION` — entries parked because the frozen flip test runs against `git archive HEAD` |
| product gaps | `agentic_benign::…grounded_floor…`, `agentic_iam::…[A18_cel_outside_subset]`, `agentic_network::…absent_baseline`, `agentic_network::…hierarchical_proposals_own_port…`, `agentic_tf_benign::…promise_contradicts_the_widening…`, `agentic_vpcsc::…deletion…`, `agentic_vpcsc::…dry_run_removal…`, `sec_cli::…spurious_drift`, `sec_rules::…dict_key` | real product limitations, each with a named escalation and a recorded residual risk |
| corpus not tracked | `spec_assertions::test_the_design_corpus_is_tracked_in_the_repository`, `spec_assertions::test_every_awaiting_owner_is_a_task_in_this_document` | `ESC-GX-SPEC-001/002` — `designs/` is git-ignored (TI-07) |

## Appendix B — what the 3,081 test functions look like

| check | result |
|---|---|
| test functions scanned | 3,081 in 152 modules |
| `assert True` / constant-truthy asserts | 0 |
| asserts comparing two constants | 0 |
| functions with no assertion of any kind | 0 (6 flagged, all proving by `pytest.raises` / does-not-raise) |
| handlers swallowing `AssertionError`/`Exception` | 0 (1 flagged, a deliberate re-derivation) |
| tests asserting only on self-configured mocks | 0 (1 flagged, also pins real argv) |
| `f(x) == f(x)` self-comparisons | 6, all determinism checks; 1 weak (TI-10) |
| `pytest.mark.xfail` markers | 20, all `strict=True` |
| unconditional `pytest.mark.skip` | 0 |
| fixture files under `tests/fixtures/` never touched by a full run | 1 of 157 |
