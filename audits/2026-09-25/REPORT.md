# Codebase audit — consolidated report

**Question.** Do the desired functions truly exist, or are any hallucinated?

**Subject.** `gcp-policy-grounding` at `main` `90248ba`.
**Date.** 2026-09-25.
**Task.** `audit-consolidate` of `designs/gcp-codebase-audit.md`, depending on all five
read-only audits.
**Nature.** Read-only, like its five sources. **Nothing is fixed.** The only file this
task wrote is this one; `git diff --name-only integration/gx-base -- gcp_grounding tests
examples run_demo.sh README.md simple_readme.md sec_requirements` is empty.

**Sources**, all in this directory:

| report | task | findings |
| --- | --- | --- |
| [`docs-vs-code.md`](docs-vs-code.md) | every documented name and claim resolved against the code | 15 (D1–D15) |
| [`phantom-code.md`](phantom-code.md) | static integrity of the package | 11 (PC-01–PC-11) |
| [`behavior-claims.md`](behavior-claims.md) | live probes of every documented behavioural guarantee | 9 (B1–B9) |
| [`test-integrity.md`](test-integrity.md) | does the suite prove what it appears to prove | 12 (TI-01–TI-12) |
| [`demos-and-quotes.md`](demos-and-quotes.md) | every demo arc and every quoted fragment | 13 (D1–D13) |

The two reports that both use a bare `D` prefix are disambiguated throughout as
**`DC-D…`** (docs-vs-code) and **`DQ-D…`** (demos-and-quotes).

**What this task did and did not do.** It read all five reports in full, deduplicated
them, ranked them, and cross-checked them against each other. It did **not** re-run the
five audits. Every row below is carried from a source report and points back at it; the
source row is authoritative and carries the full evidence. Nothing was softened and
nothing was dropped: all 60 source findings appear, in 57 rows after three merges of
genuinely duplicate findings (each merge is marked and carries both source ids). The
only claims stated in this report's own voice — the six hallucination-register locations
and the 19-vs-20 xfail reconciliation — were verified here, and the verification command
and output are recorded with them.

---

## 1. Verdict

**The desired functions exist. Nothing the user-facing documentation promises is
fictional.** Across roughly 10,300 resolved checks, every function, module, class, CLI
flag, environment variable, config key, collection, field, verdict kind, check family and
exit code that `README.md`, `simple_readme.md`, `sec_requirements/README.md` or any
`--help` text names **exists**, and where it was probed it behaves as described — the
worked IAM encoding reproduces byte-for-byte end to end, all 24 demo arcs pass under the
documented environment, 1,003 imports and 1,385 module-attribute loads resolve with zero
problems, all 820 `__all__` names exist, all 51 argparse actions reach a handler that
reads them, and all 39 settings-layer round-trips report the layer that supplied them.

**Six items are rated hallucinated, and not one of them is a documented user-facing
capability.** One is printed by the running tool at a user or an agent (`--baseline-target`,
a CLI flag that was never implemented); one is a docstring promising a config key whose
presence would make the parser refuse the operator's whole config file; two are internal
docstring cross-references naming a constant and a module that do not exist; two are
test-harness claims (a dataclass field that does not exist, and an escalation id in no
register). The full register is §3.

**The more consequential result is not about hallucination at all.** Four findings are
rated `real-bug` and two `broken`, and the two highest-impact are product defects in the
gate's decision path, both found only by running the tool:

* `--drift-policy abstain` is read from **the environment only**, so the flag is ignored
  and an exported `GCP_GROUNDING_DRIFT_POLICY=abstain` silently converts every blocking
  built-in finding into an abstention and exit 0 — including for a CI job that passes
  `--drift-policy annotate` precisely to prevent that (B1).
* A REST deny policy whose `rules` array is **emptied** — the loudest possible removal —
  is not recognised as a deny policy at all, so the documented "a deny deletion that
  wakes a dormant escalation-class grant is contradicted outright" arc never runs and the
  run exits 0 with `NOTHING VERIFIED` (B3).

### Counts

Claims are counted at each source report's own granularity; units differ by row and are
stated. "Failed" means a finding was raised.

| category | checked | held | failed | source |
| --- | ---: | ---: | ---: | --- |
| Documented names: collections, field/sort pairs, closed sets, CLI flags, env vars, config keys, verdict kinds, exit codes, repo paths, README anchors | 265 | 264 | 1 | docs-vs-code |
| Docstring cross-references (distinct targets; 1,458 reference sites) | 907 | 905 | 2 | docs-vs-code |
| Docstring `file:line` anchors | 16 | 4 | 12 | docs-vs-code |
| Counted claims ("N collections/domains/categories/tables") | 12 | 7 | 5 | docs-vs-code |
| Imports, module-attribute loads, `__all__` names | 3,208 | 3,208 | 0 | phantom-code |
| Registries: `PROVIDER_MODULES`, registered callables + arities, `sec_domains` tables | 53 | 53 | 0 | phantom-code |
| CLI actions reaching a handler; settings-layer round-trips | 90 | 90 | 0 | phantom-code |
| Definition census (module-level defs/classes and methods) | 1,984 | 1,980 | 4 | phantom-code |
| Escalation + mutation registers (ids swept, anchors resolved) | 199 | 195 | 4 | phantom-code |
| Documented behavioural guarantees, probed live | 80 | 71 | 9 | behavior-claims |
| Demo arcs, steps, fenced commands, quoted blocks, flags, Expect cells, paths, templates | 241 | 235 | 6 | demos-and-quotes |
| Test functions, xfail markers, fixtures, 60 days of commits, budget counters | 3,454 | 3,442 | 12 | test-integrity |
| **total** | **≈10,509** | **≈10,454** | **60** | |

### Findings by severity

| severity | source findings | consolidated rows | what it means here |
| --- | ---: | ---: | --- |
| broken | 2 | 2 | a shipped artifact does not do what it is documented to do when run as shipped |
| real-bug | 4 | 4 | the product or the suite reaches a wrong or absent decision |
| hallucinated | 6 | 6 | a name, flag, field or id that is referenced but does not exist |
| misdocumented | 16 | 14 | the thing exists; the description of it is wrong or incomplete |
| dead-code | 4 | 4 | defined, reachable by no caller in package, CLI, scripts or tests |
| cosmetic | 11 | 11 | output or prose blemish with no decision consequence |
| note | 17 | 16 | recorded coverage or design observation, no fix owed |
| **total** | **60** | **57** | |

Three merges account for the difference: `PC-04`+`TI-03` (one register-count defect found
twice), `B4`+`DQ-D13` (one undocumented precondition, two doc sites), `DC-D1`+`DC-D3`
(one stale count, three places).

---

## 2. Consolidated findings

**Ranking rule.** Severity class first, then user impact within the class. The design's
vocabulary does not order its severities, so this report orders them
**real-bug → broken → hallucinated → misdocumented → dead-code → cosmetic → note**, and
puts `real-bug` above `broken` deliberately: for a policy gate, a wrong or absent
security decision outranks a demo arc that fails to reproduce. `hallucinated` is placed
above `misdocumented` because a name that cannot exist costs a reader — or an agent
following a remediation string — a retry loop against nothing. An operator who disagrees
can re-rank by the `severity` column alone.

**No fix below is applied.** Every "proposed fix" is the source report's proposal,
carried verbatim in substance.

| # | severity | source | location | finding | evidence | proposed fix (NOT applied) |
| --- | --- | --- | --- | --- | --- | --- |
| R01 | real-bug | B1 | `registry.py:351`,`:269`,`:224`; `sec_rules.py:187`; `engine.py:881`; `preflight.py:345` | `--drift-policy abstain` is implemented by an adjudicator that reads **the environment only**, so the flag is ignored and the environment beats the flag — the opposite of `README.md:1086` ("Flags beat the environment") and of the flag's own help text. | Four runs, one disputed firewall row: `--drift-policy abstain` → exit 1, `⚠ [firewall_exposure] … contradicted=1` (flag ignored, stdout byte-identical to the unconfigured run, 2885 B); `GCP_GROUNDING_DRIFT_POLICY=abstain` with no flag → exit 0, downgraded; `--drift-policy annotate` **with** env `abstain` → exit 0, downgraded (env beats flag). `registry._invoke` passes `_drift_policy()` (reads `DRIFT_POLICY_ENV`) to `drift.guarded`, never `options.drift_policy`; `RuleContext.drift_policy` defaults `""` and neither construction site sets it. The `block` half of the same flag is wired correctly. — behavior-claims.md B1 | Thread the resolved policy: pass `options.drift_policy` to `registry._invoke` (on the check `ctx`) and set `RuleContext(drift_policy=…)` at `engine.py:881` and `preflight.py:345`; keep `_drift_policy()` as the library-caller fallback only. |
| R02 | real-bug | B3 | `preflight.py:112` (`_is_iam_deny_policy`) | A REST deny policy whose `rules` array is **emptied** is not recognised as a deny policy, so the documented wake arc (`README.md:77`, `:100-105`) never runs on the loudest possible removal. | Fresh corpus: baseline = the policy with the rule, proposal = the same policy with `"rules": []` → **exit 0**, `PASSED — NOTHING VERIFIED (2 unchecked)`, `? [document] …: document kind was not recognized (top-level keys ['etag','name','rules'])`. The same corpus *narrowing* the rule instead is caught: exit 1, `⚠ [iam_deny_shadow] …: removing or narrowing rule 0 wakes the dormant grant of iam.serviceAccounts.actAs …`. `_is_iam_deny_policy` requires `len(rules) > 0` plus a `denyRule` item, so `detect_kind` falls through to `None`. — behavior-claims.md B3 | Recognise a deny policy by its `name` shape (`policies/<parent>/denypolicies/<id>`) in addition to a non-empty `rules` list, as `detect_kind` already recognises Org Policy v2 by `"/policies/"` in `name` (`preflight.py:224-225`). An empty `rules` list then reads as "captured and empty", which is what the wake arc needs. |
| R03 | real-bug | TI-01 | `tests/test_gcp_sec_ast.py:448` | `test_ensure_domains_called_at_most_once` claims to prove lazy domain resolution is attempted exactly once; its assertion is `assert calls["n"] <= 1`, which **zero** calls satisfies. | In-process: clean source gives `calls["n"] == 1` (so `== 1` would pass today); with `sec_ast._ensure_domains` stubbed to a no-op, `calls["n"] == 0` and `<= 1` **still passes** — the mutant that removes lazy resolution entirely survives. `tests/spec_assertions.py:210-215` registers `SA-SECAST-CALLED-ONCE` with `predicate='calls["n"] == 1'`, i.e. the register itself names the required text. — test-integrity.md TI-01 | Restore `assert calls["n"] == 1`. (Retires the `AWAITING` entry, which closes R45.) |
| R04 | real-bug | TI-02 | `tests/test_gcp_sec_cli.py:910-937` | `test_no_sec_verdict_carries_a_line_number` carries no `_needs_z3` marker but fails in the no-solver world the module's own `_needs_no_z3` marker exists to serve. | `PYTHONPATH=tests/agentic/_blockimports GCP_TEST_BLOCK_IMPORTS=z3 python -m pytest -q -rxXs tests/test_gcp_sec_cli.py` → `1 failed, 27 passed, 13 skipped, 1 xfailed`, exit 1, failing in-process at line 937 (`assert any(v.kind.startswith("sec:") …)` → `assert False`): with no solver no promise compiles and no `sec:` verdict is minted. The defect is in the test's guard, not the product, and it does not affect the documented `.[dev]` install. — test-integrity.md TI-02 | Mark the test `@_needs_z3`, or branch the non-vacuity assertion on `HAVE_Z3` as the module's other solver-sensitive cases do. |
| R05 | broken | DQ-D1 | `README.md:1632-1633` (rows 4, 4b); `examples/terraform-schema/provider-schema.json` | Rows 4 and 4b are documented "DENIED" and `./run_demo.sh 4` checks that exit — but the committed provider schema carries no capture stamp, so the freshness ceiling reads its **mtime** and both arcs fail from any copy older than 7 days. | From a `git archive` scratch copy: `env -i PATH=… bash run_demo.sh 4` → exit **1**, `scenario 4: FAIL — 1 of 1 steps diverged`; the step exits 0 with `? [tf_schema] the captured provider schema … is 29 days old (file mtime 2026-08-27T09:39:55+00:00), past the 7 days ceiling … demoted to abstentions`, and `[tf_attribute]` is demoted `✗`→`?`. `os.utime(provider-schema.json, None)` alone flips both back to PASS. Same for `4b`. — demos-and-quotes.md D1 | Give the committed schema an explicit `captured_at` (the reader's own envelope shape, `README.md:1416-1418`), or pin `GCP_GROUNDING_NOW` in the `verify_schema` arc as scenario 6 already does. |
| R06 | broken | DQ-D2 | `README.md:1693-1696` (demo step 4) | Demo step 4 is documented as "a made-up role fails existence grounding and the report suggests the real name". It produces **no `✗` verdict and no did-you-mean** — and still exits 1 for an unrelated reason, so the step looks like it worked. | `gcp-ground verify-policy tests/fixtures/gcp/policies/iam_policy_bad.json --snapshot tests/fixtures/gcp/snapshot.json` → exit 1, `grounded=0 ungrounded=0 contradicted=1 unverified=10`; `roles/bigquery.reader` reads `? [role] bindings[0].role: snapshot did not capture roles — existence of 'roles/bigquery.reader' is undecidable offline`, because the fixture's `captured_at` is 2026-07-18, 69 days past the ceiling. Exit 1 comes from `⚠ [cel] … condition is never true — dead binding`. Under `GCP_GROUNDING_NOW=2026-07-19T09:30:00Z` the documented `✗ [role] … (did you mean: roles/bigquery.jobUser, roles/bigquery.dataViewer?)` appears. No arc covers this step. — demos-and-quotes.md D2 | Pin `GCP_GROUNDING_NOW` in the step (as steps 12/12a–12d already do) or re-stamp the fixture; the capability itself is intact. |
| R07 | hallucinated | B2 | `gcp_grounding/baseline.py:220` | `baseline.REMEDIES[0]` tells the operator to "pass the target explicitly (**the --baseline-target flag**)". No such flag exists. | Verified here: `grep -rn "baseline-target" gcp_grounding/ tests/ README.md simple_readme.md` → one hit, `gcp_grounding/baseline.py:220` (the message itself). The only target flag argparse defines is `--target DOMAIN:KEY` (`cli.py:975`). Observed live in a `--completeness complete` run: `? [baseline:target] … 1) pass the target explicitly (the --baseline-target flag) …`. `baseline.TOOL_INPUT_KEYS` does accept a `baseline_target` tool-input **key**, but the message says "flag". — behavior-claims.md B2 | Change `baseline.REMEDIES[0]` to name `--target DOMAIN:KEY`. This is remediation text handed to an agent, so the wrong flag name costs a retry loop. |
| R08 | hallucinated | PC-01 | `gcp_grounding/sources.py:46`, `:464` | Both docstrings say `completeness` "is set explicitly — `--completeness` **or the config key** — or not at all". There is no config key, and naming one **refuses the operator's whole config file**. | Verified here: `sources.py:46` reads `It is set explicitly — ``--completeness`` or the config key — or not at all.` and `:464` `of: ``--completeness`` (or the config key) lands here because`. `'completeness' in discovery.CONFIG_KEYS` → `False`; writing the key yields `cfg=None` with `unrecognized config key(s) ['completeness'] - a typo must not silently demote a setting`. `README.md:1155-1157` states the opposite and correct thing. — phantom-code.md PC-01 | Delete "or the config key" from both docstrings, leaving `--completeness` as the one spelling. Do **not** add the key: the README paragraph explains why its absence is the design. |
| R09 | hallucinated | DC-D4 | `gcp_grounding/knowledge.py:745` | a `:data:` cross-reference to `gcp_grounding.identity.CATEGORY_SPECS` — a constant that does not exist. | Verified here: `grep -rn "CATEGORY_SPECS" gcp_grounding/` → exactly one hit, `knowledge.py:745`, the reference itself. The module exports `SPECS` (`identity.py:597`, `Mapping[str, CategorySpec]`) and the class `CategorySpec` (`identity.py:212`); `identity.py:18` documents them as the `:class:` `CategorySpec` and the `:data:` `SPECS`. — docs-vs-code.md D4 | Re-point the reference to `gcp_grounding.identity.SPECS`. |
| R10 | hallucinated | DC-D5 | `gcp_grounding/tfsource/map_network.py:33`, `:70`, `:619`, `:649`, `:793` | five `:mod:` cross-references to `gcp_grounding.tfsource.merge`, a module that does not exist. | Verified here: `grep -n "tfsource.merge" gcp_grounding/tfsource/map_network.py` returns exactly those five lines; `ls gcp_grounding/tfsource/` is `discover.py hcl_lite.py hcl.py __init__.py map_network.py mapping.py map_policy.py normalize.py plan.py state.py` — no `merge.py`. The described behaviour lives in **top-level** `gcp_grounding/merge.py` ("FRAGMENT ASSEMBLY, per source", `merge.py:33`; `_fragment_priority` `:405`; the priority-then-address sort `:692-694`). — docs-vs-code.md D5 | Re-point all five to `gcp_grounding.merge`. |
| R11 | hallucinated | PC-03 | `tests/test_gcp_org_effective.py:1190` | A `strict=True` xfail whose reason is headed `"ORG-EFFECTIVE-REGISTER-ACTIVATION: …"` — the exact shape the other strict xfails use to name their escalation — but that id is in **no** register. | Verified here: `grep -rn "ORG-EFFECTIVE-REGISTER-ACTIVATION"` over `*.py`/`*.md` outside `audits/` → one hit, `tests/test_gcp_org_effective.py:1190`. Sweep of 155 known ids across `ESCALATIONS`, `PRODUCT_ESCALATIONS`, `mutation_entries.*`, `spec_assertions.ASSERTIONS`, `REQUIRED_MK_IDS`: the id is in nothing; its reason text only *cites* the registered `ESC-DENY-REGISTER-ACTIVATION` as an analogue. Effect: `tests/test_gcp_escalations.py` walks register → node, so this node is invisible to the frozen self-test and no `clause`/`unsatisfiable`/`owner_task` is recorded for the fourteen parked MK-F entries. — phantom-code.md PC-03 | Append `Escalation(id="ESC-ORGEFF-REGISTER-ACTIVATION", …, node_id="tests/test_gcp_org_effective.py::test_the_org_effective_mutation_entries_are_active_in_the_register")` to `tests/escalations.py` (deliberately un-frozen) and re-head the xfail reason with that id; extend `OUT_OF_DOCUMENT_OWNER_TASKS` if the owner is a predecessor-document task. |
| R12 | hallucinated | PC-02 | `tests/escalations.py:13` | The module docstring says an escalation is closed by deleting the xfail and "the entry stays, with `closed_by` naming the change". `Escalation` has no `closed_by` field. | Verified here: `dataclasses.fields(Escalation)` → `['id','clause','unsatisfiable','owner_task','node_id']`; `dataclasses.fields(ProductEscalation)` → `['id','clause','why','product_fix','residual_risk','closed_by']`. The same file contradicts its own docstring twice (`:309-311`, `:540-542`: "this register carries no `closed_by` for a node-bearing entry"), and both retired `Escalation`s had to be **deleted** and replaced with a prose `# RETIRED —` comment because the documented mechanism does not exist. — phantom-code.md PC-02 | Either add `closed_by: str = ""` to `Escalation` and relax the frozen self-test's strict-xfail requirement for entries carrying one, or correct the docstring at `:12-13` to describe what actually happens. The second is smaller and matches shipped practice. |
| R13 | misdocumented | **B4 + DQ-D13** (merged) | `gcp_grounding/cli.py:1532`, `:1563`; `README.md:977-991`; `simple_readme.md:91-95` | A `.tf`/`.tf.json` proposal is read as terraform **only** when one of `_STATE_OPTIONS` is also configured. With `--snapshot` alone the run exits 0 having checked nothing — and neither page states the consequence where the reader would meet it. | `--proposal corpus/violating.tf.json` (INGRESS `tcp/22` from `0.0.0.0/0`) with `--snapshot` alone → **exit 0**, `PASSED — NOTHING VERIFIED (1 unchecked)`, `? [document] …: document kind was not recognized (top-level keys ['resource'])`; raw HCL → exit 0, `? [document] …: the document is not valid JSON`. Add `--terraform-state` and both are judged: exit 1, `⚠ [firewall_exposure] google_compute_firewall.zolt_allow_ssh_world: a public source (35.32.0.0) can reach tcp/22 through this rule`. Every terraform invocation in `README.md` happens to carry such an option, so the precondition is never visible; `simple_readme.md:91-95` states the rule ("REQUIRES") but not that the tool passes silently rather than refusing. `README.md:1558-1567` *does* state it correctly and reproduces byte-exactly. — behavior-claims.md B4, demos-and-quotes.md D13 | State the precondition and its silent-pass consequence where `.tf`/`.tf.json` are introduced (`README.md:977-991` and §"Proposing a terraform change"), carry the `README.md:1563-1566` clause into `simple_readme.md`, or make `gate.terraform_route` decide the route on the snapshot-only path too. |
| R14 | misdocumented | B5 | `gcp_grounding/iam_deny_checks.py:632`, `:491-493`; `README.md:105-114` | Over a REST **IAM allow policy** the `iam_deny_shadow` masked/threaded arcs can never fire — they always abstain. `README.md` states this check's limits explicitly and this limit is not among them. | `corpus/iam_bad.policy.json` grants `roles/owner` to `allUsers`; the estate deny table denies `resourcemanager…projects.setIamPolicy` to `principalSet://goog/public:all` at `projects/zolt-prod`; `roles/owner` includes that permission — a textbook full mask. Observed: `? [iam_deny_shadow] bindings[1]: … but the grant names no readable project, so whether the deny policy attached at 'projects/zolt-prod' governs it was not decided`. The same interaction over a `tf_plan` (which carries `project`) produces the documented warning. `_document_grants` builds every `_Grant` without a `project` and `_governs` refuses an empty project first. Deliberate and pinned (`tests/test_gcp_iam_deny_checks.py:381`), so a doc gap, not a defect. — behavior-claims.md B5 | Add one clause to the stated-limits paragraph: a REST allow-policy document names no project, so the estate-side masked/threaded arcs abstain on it by name and the interaction is decided only over terraform. Note whether `--target iam_bindings:<key>` should supply the project — today it does not reach `_document_grants`. |
| R15 | misdocumented | DQ-D3 | `README.md:1685-1687` (demo step 3) | Step 3 is documented as exiting 1 "with the evidence — the principal provably absent from the snapshot, the violated domain promise, and the escalation warning". Two of the three are demoted to abstentions. | Real output: the promise refutation is there (`⚠ [sec:iam] no-primitive-roles-outside-domain: refuted by iam_bindings[0] …`), but `? [principal] bindings[0].members[0]: snapshot did not capture principals — existence of 'user:attacker@evil.example' is undecidable offline` and `? [iam_escalation] snapshot did not capture roles — escalation classes were not decided`. Under `GCP_GROUNDING_NOW=2026-07-26T08:00:00Z` all three appear. Same root cause as R06. The page **does** state this caveat for the same phenomenon at `:950-954`, `:1858-1861`, `:2431-2433` — step 3 is the one that does not. — demos-and-quotes.md D3 | Pin the clock for step 3, or add the "over a fresh snapshot" qualifier the page already uses at `:2431-2433`. |
| R16 | misdocumented | DQ-D4 | `README.md:1290`, `:1293-1295` | The quoted `--state-explain DOMAIN:KEY` block shows lines the tool cannot print: the `chosen:` line is quoted with five fields where the renderer always emits seven, and each alternate's mandatory `record:` line is omitted. | `explain_state.py:720-726` emits `source=`, `[kind]`, `origin=`, `locator=`, `captured_at=`, `domain-scope=`, `taint=` unconditionally; README:1290 drops `origin=` and `captured_at=`. Every alternate is always followed by a `record:` line (`explain_state.py:740`), which `:1293-1295` omits. A live drill-down prints `chosen: source=… [tfstate] origin=… locator=… captured_at=… domain-scope=partial taint=-` followed by `record: …`. — demos-and-quotes.md D4 | Re-capture the block from a real run, or mark the omitted fields with the page's own `…`. |
| R17 | misdocumented | **DC-D1 + DC-D3** (merged) | `sec_requirements/README.md:128-130`; `gcp_grounding/sec_ast.py:16`, `:141` | The "**six** domain collections" count is stale in three places; the domain layer registers **eleven**, and it landed. The user-facing instance also contradicts `README.md:364-365` on the same page-turn. | Verified here: `sec_requirements/README.md:128` "The domain layer (`sx-sec-domains`) registers six more once it lands —"; `sec_ast.py:16` "extended by the six domain sections"; `sec_ast.py:141` "# The six domain collections would exist only if…". Measured: `len(sec_domains.COLLECTION_SPECS) == 11`; `len(sec_ast.COLLECTIONS)` goes 4 → 15 across `register()`. The five the sentence omits are `deny_rules`, `deny_rule_exceptions`, `effective_org_policy_bool`, `effective_org_policy_values`, `proposed_role_permissions`. `README.md:364-365` states the correct number. — docs-vs-code.md D1 and D3 | Replace the prose with the eleven names (or the full table) and drop "once it lands"; s/six/eleven/ in both `sec_ast.py` sites. |
| R18 | misdocumented | DC-D2 | `README.md:718-719` | "`sec_requirements/README.md` is the canonical grammar: every node keyword, every term, every header key, **and the full collection table**." | Verified here at `README.md:718-719`. `sec_requirements/README.md:121-126` tabulates **4** collections and names 6 more in prose with "Their field lists live with that task" — 10 of 15 collections, and field lists for 4. The full table is `README.md:367-382`. The node-keyword, term and header-key claims all hold. — docs-vs-code.md D2 | Move or duplicate the 15-row table into `sec_requirements/README.md`, or change the sentence to "…every header key; the full collection table is above". |
| R19 | misdocumented | DC-D8 | `gcp_grounding/registry.py:1` | "The single extension seam for **the twelve** later grounding-domain modules." | Verified here: `registry.py:1` reads `"""The single extension seam for the twelve later grounding-domain modules.` — `len(registry.PROVIDER_MODULES) == 16` (`fw_claims`, `fw_checks`, `fw_estate`, `hfw_claims`, `hfw_checks`, `armor_claims`, `armor_checks`, `vpcsc_claims`, `vpcsc_checks`, `iam_deny`, `iam_checks`, `iam_scope`, `iam_deny_checks`, `org_checks`, `org_effective`, `tf_schema_checks`). — docs-vs-code.md D8 | s/twelve/sixteen/, or drop the number. |
| R20 | misdocumented | DC-D7 | `gcp_grounding/compare.py:7` | "…and **eighteen** category specs plus every key form plus the whole comparison algebra in one diff…" | Verified here: `compare.py:7` reads `about content), and eighteen category specs plus every key form plus the whole`. `len(gcp_grounding.identity.SPECS) == 19`, matching the 19 `GcpSnapshot` categories (`captured_at` excluded). `knowledge.py:79-81` states the correct partition: "Nineteen in total: five pre-existing vocabularies, six flat vocabularies, eight record tables". — docs-vs-code.md D7 | s/eighteen/nineteen/. |
| R21 | misdocumented | DC-D9 | `gcp_grounding/cli.py:150`, `:1168` | "…and NEVER from ``sources.SourceOptions.from_env``…" — the attribute path is wrong; the behavioural claim about `from_env` is correct. | `hasattr(sources.SourceOptions, 'from_env')` → `False`. The callable is module-level `sources.from_env`. — docs-vs-code.md D9 | ``sources.from_env``. |
| R22 | misdocumented | DC-D10 | `gcp_grounding/preflight.py:477`; `gcp_grounding/engine.py:609`, `:724` | a `:data:` cross-reference to `~gcp_grounding.registry.PAIR_CHECKS`, and "`registry.PAIR_CHECKS` is keyed by DOCUMENT KIND" — registry has no such table. | `hasattr(registry, 'PAIR_CHECKS')` → `False`; registry's upper-case names are `DRIFT_POLICY_ENV`, `ESTATE_INCOMPLETE`, `NOT_DECIDED`, `PROVIDER_MODULES`. `PAIR_CHECKS` is a **provider-module** table (`fw_checks.py:404`, exported `:69`; `iam_deny_checks.py:100`) that registry reads through `registry.pair_check()` (`registry.py:201-204`). `registry.py:20` documents it correctly. — docs-vs-code.md D10 | Re-point to `~gcp_grounding.fw_checks.PAIR_CHECKS`, or reword to "the providers' `PAIR_CHECKS` tables, read via the `:func:` `registry.pair_check`". |
| R23 | misdocumented | DC-D6 | 12 docstring line anchors (`sec_artifact.py:20`,`:446`; `sec_ast.py:13`,`:542`; `sec_domains.py:83`; `sec_encode.py:4`,`:9`,`:51`; `sec_evidence.py:203`; `sec_probes.py:24`,`:38`; `sec_vocab.py:28`) | 12 of the 16 `<file>.py:<line>` anchors inside package docstrings point at unrelated code. | e.g. `sec_artifact.py:446` says "mirroring `:meth:`GcpSnapshot.load`` (``knowledge.py:139-142``)", but `knowledge.py:139-142` is blank lines plus the head of `_str_tuple`; `GcpSnapshot.load` is at `knowledge.py:511`. Four anchors are accurate (`sec_encode.py:10`, `:84`; `sec_evidence.py:5`, `:21`). Full per-anchor table in the source report. — docs-vs-code.md D6 + "Line-anchor detail" | Re-point each anchor, or replace the `file:line` form with the symbol name alone, which never drifts. |
| R24 | misdocumented | **PC-04 + TI-03** (merged) | `tests/test_gcp_mutation_contract.py:9-11`, `:215-216`; `tests/escalations.py:268-286`, `:612` | The mutation-register shortfall is stated as "44 of the **65** … the missing **21**", and elsewhere as `REQUIRED_MK_IDS` "grew to **77**". The required tuple is **91** and **47** are missing. Three figures are in the tree at once. | Verified here in-process: `len(REQUIRED_MK_IDS) == 91`, `len(register()) == 44`, missing `== 47`. Verified stale sites: `test_gcp_mutation_contract.py:9` "44 of the 65", `:11` "the missing 21", `:216` "of the 65", `escalations.py:272` "the register holds 44 of the 65", `:274` "missing 21 cannot be added", `:612` "REQUIRED_MK_IDS grew to 77". The growth is itself documented at `test_gcp_mutation_contract.py:40-48`; only the debt sentences were not updated. The stalest is the xfail `reason=`, because `pytest -rx` prints it on every run, understating the gap by 26 ids. Nothing tests the prose. — phantom-code.md PC-04, test-integrity.md TI-03 | Recompute both reasons from `len(REQUIRED_MK_IDS)` / `len(register())` rather than quoting literals (TI-03's proposal, which prevents recurrence), or at minimum update `:215-216`, `:9-11` and `escalations.py:272-274` to "44 of the 91" / "the missing 47". The `clause` field at `escalations.py:269-270` quotes the design verbatim and must **not** be touched. |
| R25 | misdocumented | TI-05 | `tests/agentic/budget.py:28`; `tests/escalations.py:295` | "their union measures 408 spawns in a full run"; the machinery "spends 192 of the 199 marked spawns `contract_spawn_ceiling()` allows". Both describe earlier trees. | Instrumented full run: unmarked **474** against `MAX_SUBPROCESS_SPAWNS = 488` (14 headroom), marked **211** against a ceiling of **211**. The arithmetic the comment documents is still exactly right (450→466→478→488 tracks 456→466→474); only the prose figures are stale. — test-integrity.md TI-05 | Re-state the two sentences with the measured 474/488 and 211/211, or drop the absolute numbers and keep the per-raise accounting. |
| R26 | misdocumented | PC-05 | `tests/test_gcp_hfw_checks.py:1612`; `tests/escalations.py:178-179` | Both record as measured fact that `tests/mutation_entries.py` and `tests/mutation_contract.py` are "absent from this checkout" / "neither file is in this checkout at all". Both files are present. | `tests/mutation_entries.py` exists (1160 lines), `tests/mutation_contract.py` (529 lines); both import in-process and `register()` returns 44 entries. The escalation still stands on its *other*, live ground — `REM-GX-HFW-FOLD` appears only in `tests/escalations.py:171` and `tests/test_gcp_hfw_checks.py`, never in `mutation_entries.py`, so the assertion genuinely still fails and the strict xfail is honest. Only the stated reason has rotted. — phantom-code.md PC-05 | Rewrite both reasons to the surviving fact ("`tests/mutation_entries.py` is a FROZEN acceptance path for `gx-hierfw-placement` and does not yet carry `REM-GX-HFW-FOLD`"), dropping the absent-from-this-checkout clause. |
| R27 | dead-code | PC-09 | `gcp_grounding/core/solver.py:39` | `ConstraintSolver.mutually_exclusive_always_false(guards)` is called nowhere and overridden nowhere, and its docstring forward-promises a generalization that does not exist: "with z3 this generalizes to symbolic conditions." | Verified here: the def is at `core/solver.py:39`. `grep -rn "mutually_exclusive_always_false" .` (excluding `.git/`) → one hit, the `def` line. Neither subclass (`BuiltinSolver:59`, `Z3Solver:74`) overrides it; `Z3Solver` overrides only `arity_satisfies` and `explain` — so the z3 generalization has no override seam in use. — phantom-code.md PC-09 | Vendored `gcp_grounding/core/` is out of bounds for a test task (the convention `PRODUCT_ESCALATIONS` exists for), so record a `ProductEscalation` rather than editing. If `core/` is ever in scope: delete the method, or drop the "with z3 this generalizes" sentence, which is the part that reads as a promise. |
| R28 | dead-code | PC-07 | `gcp_grounding/redact.py:758` | `SecretVault.add_all(values)` is never called. `SecretVault` is exported in `redact.__all__`, so this is a public class's public, untested method. | Verified here: the def is at `redact.py:758`. `grep -rn "add_all" .` (excluding `.git/`) → one hit, the `def` line — no caller in the package, the CLI, `show_promises.py` or any of the 150 test modules. — phantom-code.md PC-07 | Delete it (callers already loop over `add`, which returns the store/skip decision this method discards), or keep it and pin it with a test; an untested public method is how the `add` and `add_all` contracts drift apart. |
| R29 | dead-code | PC-08 | `gcp_grounding/sources.py:315` | `SourceOptions.any_source` (a `@property`) is never read. `SourceOptions` is exported. | Verified here: the def is at `sources.py:315`. `grep -rn "any_source" .` (excluding `.git/`) → one hit, the `def` line. Every live caller asks `configured()` directly, which is what `any_source` wraps in `bool(...)`. — phantom-code.md PC-08 | Delete it, or pin it. Its docstring's claim ("Whether ANY source is configured. Zero is not an error") is true today, but nothing asserts it stays true. |
| R30 | dead-code | PC-06 | `gcp_grounding/cli.py:3729` | `_collection_rows(sec_rules, ctx, name)` — a one-line wrapper returning `_collection_reading(...)[0]`, called from nowhere. | Verified here: the def is at `cli.py:3729`. `grep -rn "_collection_rows" .` (excluding `.git/`) → exactly one hit, the `def` line. Not in `cli.__all__`, not reachable by name. — phantom-code.md PC-06 | Delete it. Its body is `return _collection_reading(sec_rules, ctx, name)[0]`, so nothing is lost; the four live callers of that function already index it directly. |
| R31 | cosmetic | B7 | `gcp_grounding/cli.py:2007` and `:1115-1117` | Passing **both** `--explain` and `--state-explain` prints the whole state block twice, contradicting `cli.py:369-370` ("`--explain` appends the same lines"). | One run with both flags: `state used this run:` ×2, `settings:` ×2, `source coverage (gcp-source-ledger/1)` ×2, `now             =` ×2, `targets:` ×2, `drift:` ×2 — while `what was proposed:`, `decision:` and `summary — what just happened:` are ×1. `_narrative_lines` ends by calling `_state_explain_lines` (`:2007`) and `main` calls it again unconditionally (`:1115-1117`). stdout is unaffected. — behavior-claims.md B7 | Skip the second emission when `args.explain` already appended it, unless `--state-explain` was given a `DOMAIN:KEY` argument (that form prints a different drill-down block and should still be additional). |
| R32 | cosmetic | B6 | `gcp_grounding/freshness.py:240-247`, used at `:329` | The staleness verdict renders the **configured** ceiling in whole days (or whole hours under a day), so it names a ceiling that is not the one configured. | Measured through the CLI (snapshot 15 days old): `--max-age 36h` → "past the **1 day** freshness limit"; `--max-age 90m` → "**1 hour**"; `--max-age 129600` → "1 day". Directly, `freshness._describe(parse_duration("30s")) == '0 hours'`, so `--max-age 30s` would report "the **0 hours** freshness limit", which reads as no ceiling at all. The gate's behaviour is correct in every case — only the prose rounds. — behavior-claims.md B6 | Render the configured limit from the operator's own token (or with a remainder-preserving formatter), keeping `_describe` for the measured age. |
| R33 | cosmetic | B8 | `gcp_grounding/cli.py:2305` | The bash-mutation banner advises "or pass `--bash-policy=warn` if the command is intentional" under `--bash-policy warn` too — advising the flag already in force. | Same fresh event, byte-identical 622 B stderr under both policies; only the first line and the exit code differ: `block` → exit 2, `BLOCKED — unchecked GCP mutation in a shell command`; `warn` → exit 0, `WARNING — …`; both then print the identical advice. — behavior-claims.md B8 | Emit the remediation clause only when the policy is `block`. |
| R34 | cosmetic | DQ-D7 | `README.md:2037-2044` (9e check listing) | Three `✓` lines are quoted as printed; each really ends with a provenance suffix the quote drops with no `…`. | Real: `… no public source reaches a sensitive port [snapshot 2026-07-25T08:00:00Z]`, and for the pair check `… [pair scope projects/acme-prod/global/networks/prod-vpc INGRESS] [target … \| source examples/terraform-masked/terraform-after-removal.tfstate \| how tf-address] [snapshot …]`. Measured: with suffixes dropped the block matches, with them kept it does not. The same elision applies to `:2439-2504` and `:2613-2629`. — demos-and-quotes.md D7 | State once that quoted verdict lines are shown without their provenance suffix, or keep the suffixes. |
| R35 | cosmetic | DQ-D6 | `README.md:2613-2629` (12a check listing) | Three contiguous `✓` lines are presented as "the check listing"; the real listing has two further `✓` lines **between** them, with no `…` marking the gap. | The real listing carries `✓ [sec:iam] every-deny-covers-token-creation: the obligation holds over the document — grounded` and `✓ [sec:org_policy] sa-…` between the quoted `[org_effective]` and `[sec:iam] no-principal-threads-the-guardrail` lines. Each quoted line is individually byte-exact. — demos-and-quotes.md D6 | Insert the page's own `…` between the selected lines. |
| R36 | cosmetic | DQ-D5 | `README.md:2442` | `— e.g. src (…); dst (…); protocol 6; port 443` — the gate prints these witnesses **bare**, so the parentheses are the page's mask, not the output's. | Real (scenario `5f`): `e.g. src 0.0.0.0; dst 35.0.0.0; protocol 6; port 443`. Unlike `[firewall_exposure]`, where `a public source (35.32.0.0) can reach tcp/22 through this rule` really does print them, so `(…)` there is byte-faithful. A reader diffing 5f against their terminal sees a difference the convention does not explain. — demos-and-quotes.md D5 | Write `src …; dst …` for `[firewall_reopen]`, or say the mask sometimes supplies its own brackets. |
| R37 | cosmetic | DQ-D8 | `README.md:459-475` | "`examples/walkthrough/requirements.md` holds one sentence and one block:" — the committed block also carries two `note:` lines, dropped from inside the quote. | The committed `promise` block carries `note: domain membership is read off the member id's suffix…` and `note: the collection is iam_bindings…`. The frontmatter and intro prose are also above the quote, which the page does acknowledge at `:477`. — demos-and-quotes.md D8 | Quote the block whole, or say the `note:` lines are elided. |
| R38 | cosmetic | DC-D12 | 11 sites (`cli.py:2964`, `:3974`; `drift.py:239`, `:547`; `gate.py:427`; `iam_scope.py:24`; `provider_schema.py:64`; `reconciled.py:4`; `registry.py:581`; `sec_domains.py:41`; `sources.py:38`) | A Sphinx role target broken across a source line, so the target as written contains a newline plus indentation and cannot resolve as a reference. | e.g. `gate.py:427` spells a `:meth:` target as `PolicyGroundingGate.` + newline + eight spaces + `_ground_with_state`. Every one of the 11 **does** resolve after whitespace normalisation, so no name is wrong — only the spelling. Full list in the source report. — docs-vs-code.md D12 | Keep each role target on one line (wrap before the role, not inside it). |
| R39 | cosmetic | DC-D11 | `gcp_grounding/estate.py:17` | "…so ``knowledge.network_tag_exists`` answers ``True`` or UNKNOWN and never ``False``." — it is a method, not a module function. | `hasattr(knowledge, 'network_tag_exists')` → `False`; `hasattr(knowledge.GcpSnapshot, 'network_tag_exists')` → `True`. The behavioural claim is untested here; only the name path is wrong. — docs-vs-code.md D11 | ``knowledge.GcpSnapshot.network_tag_exists``. |
| R40 | cosmetic | PC-11 | `tests/mutation_entries.py` (21 entries) | 21 of the 44 mutation entries carry a `line_hint` that no longer sits inside the scope its anchor resolves in; the printed number is up to ~1,000 lines off. | `tests/test_gcp_mutation_contract.py::test_the_anchor_of_every_entry_resolves_on_content_and_drift_only_prints` PASSES and prints 21 `DRIFT` lines, e.g. `DRIFT MK-I13: hint 548 outside _guarded.extract (1580-1596); the anchor resolved at 1594`. The field is advisory by contract (`tests/mutation_contract.py:47-48`: "printed in every failure, NEVER asserted"), so nothing breaks — but its stated purpose is to help a human find the site. — phantom-code.md PC-11 | Re-stamp the 21 hints from the resolved line the test already prints. Content anchoring is working exactly as designed — this is the navigation aid, not the anchor. |
| R41 | cosmetic | TI-12 | `pyproject.toml` `[tool.pytest.ini_options]`; `tests/test_gcp_agentic_iam.py:554-559` | Every xfail is strict today, but `xfail_strict` is not set in the ini, so a future marker that omits `strict=True` would be silently non-strict; and A18's marker names a product cause and no `ESC-` id, so no register forces its retirement. | Verified here by AST over `tests/`: 20 `pytest.mark.xfail` calls, **all** `strict=True`. The enforcement in `tests/test_gcp_escalations.py:140` covers only node ids in the escalation register; `tests/test_gcp_agentic_iam.py:554` is outside it and `tests/integration_repins.py` does not carry it either. — test-integrity.md TI-12 | Set `xfail_strict = true` in `[tool.pytest.ini_options]`, and either register A18's escalation or point its reason at an existing id. |
| R42 | note | DQ-D12 | `run_demo.sh:22-23` | The runner says "with no venv present it falls back to `python3 -m gcp_grounding` from this checkout" without saying the documented exits need z3. On that fallback **14 of 24 arcs FAIL** even with fresh mtimes. | Every DENIED verdict that rests on the solver becomes an abstention — e.g. scenario 3 exits 0 with `? [firewall_exposure] … z3 is not available (solver backend 'builtin') — public exposure was not decided`. Measured across all four condition combinations in the source report's method table. — demos-and-quotes.md D12 | Say the fallback runs but that the documented exits assume z3, or have the runner name the backend it resolved. |
| R43 | note | TI-04 | `tests/mutation_contract.py:515-520`; `tests/mutation_entries.py` | The mutation contract's spawn ceiling is exactly consumed, so five `Removal`s recorded as proven-to-kill are never executed by the oracle — for a budget reason, not a technical one. | Ceiling `4*44 + 19 + 16 = 211`; instrumented run measured **marked spawns 211 / ceiling 211 — zero headroom**. The five pending: `RM-HOOK-SUCCESS-BEFORE-THE-EVENT`, `RM-NETWORK-PLANE-UNAVAILABLE`, `RM-VPCSC-ABSENT-VERSUS-EMPTY`, `RM-VPCSC-DOCUMENT-AND-PAIR-CHECKS`, `RM-VPCSC-DOMAIN-UNREGISTERED`. Three strict xfails say so in as many words (`ESC-GX-{ABSTAIN,NETWORK,VPCSC}-REMOVAL-CEILING`). Corroborated by phantom-code VT-14/VT-15, which confirm the register's state machine is otherwise clean (44 active, `AWAITING_MAX` empty). — test-integrity.md TI-04 | Raise `contract_spawn_ceiling`'s per-entry accounting (or `SPAWNS_PER_ENTRY`) by the five children, then flip the five `pending` flags; the three xfails then XPASS and force deliberate retirement, which is the mechanism working as designed. |
| R44 | note | TI-06 | `tests/test_gcp_run_demo.py:25-27`; `README.md:1621-1648` | The at-a-glance table has 24 scenarios and `run_demo.sh` defines 24 labels, but `test_gcp_run_demo.py` executes exactly three arcs end to end; **7 of 24 rows are named by no test at all**. | The three executed are `demo("3c")`, `demo("4")`, `demo("w")`; the other invocations are `--list` twice, a `4c` run against a stub `GCP_GROUND`, and `demo("42")` (a label the README does not name). `--list` pins the *enumeration*, not the verdicts. The 7 unnamed rows are `5`, `5b`, `5c`, `5d`, `5e`, `5f`, `5g` — the whole `examples/terraform-orgpolicy/` family bar one file used by two `--explain` sentence pins. So claims like row 5's "APPROVED — all eleven promises hold" and row 5c's "DENIED — `vpc-externally-peered-vpc-gcp` + `compute-disable-internet-neg` VIOLATED" are asserted nowhere in the suite. (They *are* checked by `run_demo.sh` itself: demos-and-quotes V2/V7 measured 24/24 arcs PASS and 24/24 Expect cells matching — the gap is that the suite does not run them.) — test-integrity.md TI-06 | Add `tests/test_gcp_examples_orgpolicy.py` in the shape of the existing `test_gcp_examples_{masked,roles,schema,denypolicy,terraform}.py` modules, pinning each 5* row's exit and named promises. |
| R45 | note | TI-07 | `tests/test_gcp_spec_assertions.py:256`; `tests/spec_assertions.py:265`, `:279` | R03's weakening is excused by three independent mechanisms, none of which can redden. | `SA-SECAST-CALLED-ONCE`'s owner is `sx-sec-ast`, a task of the **predecessor** design document, which `tests/spec_assertions.py:271-280` records as structurally un-ownable here and routes to `ESC-GX-SPEC-002`; that escalation's own node is `xfail(strict=True)`. Net effect: (a) skipped by the register, (b) excused by a mapping, (c) the assertion that would object is strict-xfailed. This is one of the 3 skips in every run. — test-integrity.md TI-07 | Either fix R03 (which retires the entry outright) or re-own `SA-SECAST-CALLED-ONCE` to a task in the current document. |
| R46 | note | TI-08 | `tests/test_gcp_sec_cli.py:76`, `:871`, `:892` | The two `_needs_no_z3` tests "say what the no-solver world must look like, and they only run there" — and in the documented install they never run at all. | They are 2 of the 3 skips in every run ("a solver is available, so the fallback backend is not live"). `pyproject.toml` puts z3 in both the `z3` and the `dev` extra, and `README.md:141`, `:1603` install `.[dev]` — so these two positive assertions about the fallback backend never execute, and the world they describe is (per R04) not green. — test-integrity.md TI-08 | Run the module once in a z3-blocked child as part of the suite (the `blocked_import_env` machinery already exists), so the fallback-backend claims are exercised somewhere. |
| R47 | note | B9 | `gcp_grounding/cli.py:_SUMMARY_LABELS` (`:3210`) | The summary's promise count and the narrative's own label disagree about the same promise in the same run: the narrative says `not checked`, the summary says `1 enforcing, 0 not`. | A compiled `vpc_firewall`-domain promise run against an IAM allow policy: narrative `not checked  zolt-forall-over-firewalls [vpc_firewall]`, summary five lines later `promises in force       : 1 enforcing, 0 not` with the sentence listed unmarked. The stdout report says nothing about the promise (`grounded=4 … unverified=0`), because `CompiledRule.applies_to` (`sec_rules.py:215`) gates on document kind before the evidence floor is reached. "In force" and "checked" are genuinely different properties and the narrative does disclose the difference — but a reader of the summary alone is told "1 enforcing" about a promise this run did not evaluate. — behavior-claims.md B9 | Carry the narrative's `not checked` marker into the summary block's promise list, as the block already carries `not enforcing` for a compile-time rejection. |
| R48 | note | PC-10 | `tests/escalations.py:786`, `:809`, `:853`, `:892` | Four of the ten `PRODUCT_ESCALATIONS` are quoted **nowhere** outside the register, although `ProductEscalation.id`'s own doc comment says "Stable id, quoted from the module that works around it". | Reverse sweep: `ESC-DENY-ESTATE-TIER`, `ESC-DENY-GROUP-MEMBERSHIP`, `ESC-DENY-CONDITION-SAT`, `ESC-DENY-PRINCIPAL-HIERARCHY` have `total=1` reference each — their own definition. Contrast the two that work as documented: `ESC-DENY-ALLOW-CONDITIONS` is in the runtime verdict text (`iam_deny_checks.py:762`, `:1062`) and `ESC-DENY-FETCH-CAPTURE` is quoted from `facts.py:431` and `iam_deny_checks.py:960`. — phantom-code.md PC-10 | Quote each of the four from the abstention it explains — the id in the `unverified` message where the abstention is minted — or, where no message exists to carry it, from the code comment at the site. |
| R49 | note | TI-09 | `tests/fixtures/gcp/agentic/benign/README.md` | Its 12-row `file → lands as → why it is benign` table is pinned by no test, while `BENIGN_SCRIPT` is the real list; a row renamed on one side would not be noticed. | The instrumented run shows **156 of 157** files under `tests/fixtures/` are opened by the pytest process or named in a child's argv; the single exception is this README, so its own sentence ("Every document in this directory is a payload of the twelve-proposal script…") does not hold of it. — test-integrity.md TI-09 | Add one assertion in `test_gcp_agentic_benign.py` comparing the README table's `file` column to the payload names `BENIGN_SCRIPT` loads, as `test_gcp_run_demo.py` pins the at-a-glance table. |
| R50 | note | TI-11 | `tests/test_gcp_sec_evidence.py:313-314` (commit `65dcbcf56`) | The one genuine `==`→`in` loosening in 60 days of history: two exact witness-line equalities became substring membership, silently dropping the *position* guarantee. | The commit turned `assert positive == "      + compliant: (no pinned witness)"` (and its negative twin) into `assert "…" in lines`. The restructure the commit subject declares plausibly moved the lines, so the change is justified; what went with it is the guarantee that no other witness line was emitted. The scan raised 44 candidates and the other 43 were its own artefact — `--unified=0` hunks where an *added* message assertion sits beside an unrelated *removed* status assertion, i.e. tests being strengthened. — test-integrity.md TI-11 | Re-extract the two lines by index and compare with `==`, or assert the full witness block. |
| R51 | note | TI-10 | `tests/test_gcp_sec_parse.py:268-270` | `test_parse_text_is_byte_deterministic` compares two calls in one interpreter, so it cannot catch the hash-seed-dependent ordering "byte-deterministic" usually means. | Its only assertion is `assert m.parse_text(text, "iam.md") == m.parse_text(text, "iam.md")`. Within a process, `dict`/`set` iteration order is already stable, so this can only catch a clock, a counter or an RNG. It is the one of six self-comparing assertions in the suite with no stronger sibling; contrast `tests/test_gcp_redact.py:76`, `:83`, where the same shape is backed by two real cross-process pins. — test-integrity.md TI-10 | Compare against a child-process parse of the same text, as `test_gcp_redact.py` does, or rename the test to what it checks. |
| R52 | note | DC-D15 | `README.md:2895`; `sec_requirements/README.md:13-14` | The docs tell the reader to commit artifacts to `sec_requirements/compiled/`, which does not exist — a reader running `gcp-ground compile-requirements` with the default `DIR=sec_requirements` compiles **zero** documents. | `sec_requirements/` contains only `README.md` and `TEMPLATE.md`; no `*.promises.json` is committed anywhere. This is self-consistent — `sec_requirements/README.md:18-19` says the directory is written by stage 1, and `TEMPLATE.md` is skipped by `sec_parse.discover` — but the first run a reader makes finds nothing. — docs-vs-code.md D15 | State in `sec_requirements/README.md` that the shipped directory holds the template only, and that the demo corpora live under `tests/fixtures/gcp/sec_requirements/` and `examples/*/`. |
| R53 | note | DC-D13 | `gcp_grounding/baseline.py:774` | "category → (projector, document kind). **The five categories** with no entry have no document form…" — no category set in the tree yields five. | Verified here: `baseline.py:774` reads `#: category → (projector, document kind). The five categories with no entry`. `len(baseline._PROJECTIONS) == 6`; of the 8 record tables (`facts.TABLE_CATEGORIES`) exactly **2** lack an entry — `roles` and `resource_hierarchy`, the two the same sentence names. Against all 19 snapshot categories, 13 lack one; against `facts.TF_CATEGORIES` (14), 8 do. — docs-vs-code.md D13 | Either "the two record categories with no entry" (matching the sentence's own examples) or drop the count. |
| R54 | note | DC-D14 | `sec_requirements/README.md:5`, `:128` | The user-facing authoring guide names design task ids (`sx-sec-parse`, `sx-sec-domains`) that correspond to no file, module or entry point, and `designs/` is not in the tree. | The real modules are `gcp_grounding/sec_parse.py` and `gcp_grounding/sec_domains.py`. (`sx-detect-kind` is used the same way at `iam_deny.py:6` and in several tests, so this is a house convention — but in an authoring guide it names nothing the reader can open.) — docs-vs-code.md D14 | Name the modules in the authoring guide; keep task ids to internal docstrings. |
| R55 | note | DQ-D9 | `README.md:819-821` | "`./run_demo.sh w` runs … the compile of step three above, then the verify below and its REST-policy counterpart" — the arc's order is the other way round. | The runner's order is compile → **REST policy** (`step 2/3`) → terraform proposal (`step 3/3`). The page's own `:968` gets it right ("is step two of the arc"). — demos-and-quotes.md D9 | Swap the two clauses at `:820`. |
| R56 | note | DQ-D11 | `README.md:2409-2410`, `:968-970` | Five arcs (`5b`–`5f`) and arc `w`'s REST step run commands that appear in no fenced block; they are documented in prose instead. | "swap the `--proposal` path; everything else is identical"; "is step two of the arc". All six commands were reconstructed and run; all six behave as the page says. — demos-and-quotes.md D11 | None needed; recorded as coverage. |
| R57 | note | DQ-D10 | `README.md:1897-1904` (step 9a) | A documented command with a documented exit (1) that no at-a-glance row maps to, so `run_demo.sh` never checks it. | `README.md:1924-1926` says so deliberately. Verified by hand: exit **1**, three findings, and all three quoted fragments (`:1932`, `:1937-1938`, `:1939-1940`) byte-exact. — demos-and-quotes.md D10 | None needed; recorded so the reader knows one documented exit is unguarded. |

---

## 3. Hallucination register

"Hallucinated" is reserved by the design for a name, function, flag, behavior, or claim
that the documentation or code references but that **does not exist or does not do what
is claimed**. Six items qualify. Each location below was re-verified in this worktree; the
verification command and its output are given.

| # | what is claimed | exactly where the false claim is made | what actually exists | verification run here |
| --- | --- | --- | --- | --- |
| H1 | a CLI flag `--baseline-target`, named in remediation text the tool prints at a user or an agent | `gcp_grounding/baseline.py:220` — `REMEDIES[0] = "pass the target explicitly (the --baseline-target flag)"`, reached through the `? [baseline:target]` verdict | `--target DOMAIN:KEY` (`cli.py:975`). A `baseline_target` *tool-input key* exists in `baseline.TOOL_INPUT_KEYS:212-213`, but that is not a flag and the message says "flag" | `grep -rn "baseline-target" gcp_grounding/ tests/ README.md simple_readme.md` → **1 hit**, `gcp_grounding/baseline.py:220` — the message itself, and nothing else in the tree |
| H2 | a config-file key for `completeness` | `gcp_grounding/sources.py:46` — "It is set explicitly — ``--completeness`` or the config key — or not at all." and `gcp_grounding/sources.py:464` — "of: ``--completeness`` (or the config key) lands here because" | `--completeness` only. Naming the key in a config file makes `discovery.discover` return `cfg=None` and **refuse the whole file**: `unrecognized config key(s) ['completeness']`. `README.md:1155-1157` states the correct rule | `sed -n '46p;464p' gcp_grounding/sources.py` → both sentences present verbatim as quoted |
| H3 | `gcp_grounding.identity.CATEGORY_SPECS`, a data table | `gcp_grounding/knowledge.py:745` — "as :data:\`gcp_grounding.identity.CATEGORY_SPECS\` requires, but a" | `identity.SPECS` (`identity.py:597`, `Mapping[str, CategorySpec]`) and the class `CategorySpec` (`identity.py:212`) | `grep -rn "CATEGORY_SPECS" gcp_grounding/` → **1 hit**, `knowledge.py:745`, the reference itself — the name is defined nowhere |
| H4 | the module `gcp_grounding.tfsource.merge`, in five separate sentences describing fragment assembly | `gcp_grounding/tfsource/map_network.py:33`, `:70`, `:619`, `:649`, `:793` | top-level `gcp_grounding/merge.py` ("FRAGMENT ASSEMBLY, per source", `:33`; `_fragment_priority` `:405`; priority-then-address sort `:692-694`) | `grep -n "tfsource.merge" gcp_grounding/tfsource/map_network.py` → exactly lines 33, 70, 619, 649, 793; `ls gcp_grounding/tfsource/` → `discover.py hcl_lite.py hcl.py __init__.py map_network.py mapping.py map_policy.py normalize.py plan.py state.py` — **no `merge.py`** |
| H5 | the escalation id `ORG-EFFECTIVE-REGISTER-ACTIVATION`, used in the id-naming position of a `strict=True` xfail reason | `tests/test_gcp_org_effective.py:1190` — `reason="ORG-EFFECTIVE-REGISTER-ACTIVATION: the fourteen MK-F entries are seeded PARKED …"` | nothing. It is in no register (`ESCALATIONS`, `PRODUCT_ESCALATIONS`, `mutation_entries.*`, `spec_assertions.ASSERTIONS`, `REQUIRED_MK_IDS` — 155 known ids). The reason only *cites* the registered `ESC-DENY-REGISTER-ACTIVATION` as an analogue | `grep -rn "ORG-EFFECTIVE-REGISTER-ACTIVATION"` over `*.py`/`*.md` outside `audits/` → **1 hit**, `tests/test_gcp_org_effective.py:1190`, the reason string itself |
| H6 | a `closed_by` field on `Escalation`, documented as the mechanism by which an escalation is retired | `tests/escalations.py:13` — "An escalation is CLOSED by landing its fix and deleting the ``xfail`` — the entry stays, with ``closed_by`` naming the change." | `Escalation` has `id, clause, unsatisfiable, owner_task, node_id`. Only `ProductEscalation` has `closed_by`. The file's own retirement comments contradict the docstring twice (`:309-311`, `:540-542`), and both retired `Escalation`s were **deleted** and replaced with prose `# RETIRED —` comments | in-process: `[f.name for f in dataclasses.fields(Escalation)]` → `['id','clause','unsatisfiable','owner_task','node_id']`; `…fields(ProductEscalation)` → `['id','clause','why','product_fix','residual_risk','closed_by']` |

**What the register does and does not say.** None of these six is a documented user-facing
capability: no README, `simple_readme.md`, `sec_requirements/README.md` or `--help` claim
is among them. Exactly one — **H1** — is a string the running tool prints at a user or an
agent; it is the highest-priority hallucination for that reason, and it is also the one
that no docs-audit could have caught, because it lives in a verdict message rather than in
documentation or a docstring (see §4, "seams"). **H2** is the only one whose advice, if
followed, breaks the operator's run. **H3** and **H4** are internal docstring
cross-references. **H5** and **H6** are test-harness claims and affect no shipped behaviour.

---

## 4. Coverage

### What each task audited

| surface | docs-vs-code | phantom-code | behavior-claims | test-integrity | demos-and-quotes |
| --- | :-: | :-: | :-: | :-: | :-: |
| `README.md` (all sections, tables, LLM blocks) | ● names + claims | | ● claim sources | ● pins that quote it | ● every fenced command + quoted block |
| `simple_readme.md`, `sec_requirements/README.md` | ● | | ● claim sources | | ● |
| `gcp-ground --help` × 4 subcommands (49 flags / 51 actions) | ● every flag | ● every action reaches a reader | ● behaviour of ~20 flags | | ● 21 long flags used in fences |
| module docstrings across 79 `.py` files (1,458 role refs, 16 line anchors) | ● | ● `__all__`, imports, attrs | ● where a docstring promises behaviour | | |
| `gcp_grounding/` static integrity (imports, attrs, defs, arities) | | ● 1,984 defs, 3,208 names | | | |
| `registry.PROVIDER_MODULES` (16) + the five check tables | ● names | ● import + arity | ● decisions of `fw_*`, `iam_*`, `org_effective`, `tf_schema_checks` | | |
| `sec_domains` / `sec_ast` / `sec_rules` / `sec_probes` / `sec_encode` / `sec_artifact` | ● registries + grammar | ● name-based registry whole | ● compile rejections, evidence floor, census | | ● explainer artifacts byte-for-byte |
| settings layering (`discovery`, `sources`, `cli`, env, config) | ● keys + labels | ● 39 round-trips | ● discovery vs auto-detection, refusals | | ● config example parses |
| freshness / the clock | ● defaults | | ● ceiling both paths, all spellings, one instant | | ● (root cause of D1–D3) |
| hook mode, `--bash-policy`, `scan-command` | ● exit codes | | ● 8 hook guarantees + 4 scan cases | | ● hook pair byte-silence |
| provider schema | ● wrapper + kinds | | ● all five documented outcomes | | ● scenarios 4, 4b, 4c, 4d |
| `deny_rules` / allow×deny shadow / org-policy fold | ● surfaces table | ● tables exist | ● 17 arcs | | ● scenarios 6, 6a, 6b, 6c |
| terraform readers (`tfsource/`), merge, drift, baseline, reconciled | ● names + docstrings | ● imports + defs | ● precedence, drift, completeness, baseline | | ● scenarios 1, 2a, 2b, 5*, w |
| `run_demo.sh` (24 scenarios, 43 steps) | ● `--list` reads README | | | ● 3 arcs executed by the suite | ● all 24 arcs × 4 environments |
| `tests/` (152 modules, 3,081 functions, 4,456 tests) | | ● escalation + mutation registers | | ● vacuity, skips, xfails, fixtures, 60 days of history, spawn budget | |
| `gcp_grounding/core/` (vendored datalog, solver, report) | ● Layout section | ● dead-code census | ● solver census output | | |

### What was out of reach

Stated by the source reports themselves, so the coverage above is not read wider than it is:

* **`--drift-policy abstain`'s rule-3 carve-out** (`drift.py:517-534`: a `contradicted`
  whose whole read set carries a material *existence* dispute won by a `complete` source
  asserting absence) was **not probed** — it needs a merge that keeps a terraform-only key
  and taints it `disputed`, which the fresh corpus does not construct. Rules 1, 2, 4 and 5
  were observed. (behavior-claims, "Coverage gaps")
* **`--llm` / `sec_llm`** and the LLM-assisted compile stage were **not exercised** by any
  task.
* **Cloud Armor, hierarchical firewall policies and VPC-SC** appear only as snapshot
  categories and as registered modules that import and expose tables. Their own documented
  findings — priority-order bypass, `goto_next` cross-level order, perimeter shrink,
  dry-run flips — were **not verified live** by anyone. This is the largest behavioural
  gap in the wave.
* **Dynamic reachability.** The dead-code census is name-based, so a definition reached
  only through a computed string would be misreported as dead. All four hits were
  re-checked by hand with a tree-wide `grep -rn` returning a single hit; each carries a
  judgment rather than a verdict.
* **`gcp_grounding/core/`** is vendored and out of bounds for edits, which is why R27 is
  proposed as a `ProductEscalation` rather than a fix.
* **The z3-blocked full-suite number** (`52 failed, 4180 passed, 227 skipped, 19 xfailed`)
  is an **upper bound, not an attribution**: `hookrunner.SCRUBBED_ENV` does not scrub
  `PYTHONPATH`/`GCP_TEST_BLOCK_IMPORTS`, so the block reaches spawned children that expect
  a solver. Only in-process failures are attributable, which is why R04 is cited from a
  single-module run.
* **`designs/`** is git-ignored and not in the tree, so the design corpus behind task ids
  and escalation clauses could not be read directly (R54, and the two `ESC-GX-SPEC-00*`
  xfails).

### Seams between tasks — and what fell into one

Two findings exist only because a task looked where the others' scopes stop, and they are
worth naming so the seam is not re-opened by a narrower future audit:

* **H1 (`--baseline-target`)** is a hallucinated flag name inside a **runtime verdict
  message**. docs-vs-code swept documentation and docstrings and correctly reported that
  every flag *the docs* name exists; phantom-code swept argparse in the other direction
  (no flag parsed and ignored). Neither scope covers strings the tool composes at runtime.
  Only behavior-claims, by reading what a run printed, could see it.
* **R13 (terraform routing)** is a *precondition* that no static reading reveals: the
  names all exist, the parser accepts the input, and the run exits 0. Only running
  `verify-policy main.tf.json --snapshot snap.json` — the most natural command a reader
  would type from the surfaces table — shows that it checks nothing.

### Cross-report consistency

The five reports agree wherever they overlap. Two apparent discrepancies were checked here
and both resolve:

* **19 vs 20 xfail markers.** phantom-code VT-09 reports "all 19 `pytest.mark.xfail`
  **decorators**"; test-integrity reports "20 `pytest.mark.xfail` **markers**, all
  `strict=True`". An AST pass over `tests/` run for this report finds **20 `mark.xfail`
  calls: 19 as decorators, 1 inside a `pytest.param(..., marks=…)` at
  `tests/test_gcp_agentic_iam.py:554`** — which is exactly the marker test-integrity
  singles out in R41. Both counts are right; they measure different things. All 20 are
  `strict=True`, as both reports state.
* **The mutation register.** phantom-code (PC-04) and test-integrity (TI-03) found the
  same defect independently and quote the same measurement; re-measured here:
  `len(REQUIRED_MK_IDS) == 91`, `len(register()) == 44`, `47` missing. Merged as R24,
  taking TI-03's stronger proposed fix.

The suite result is identical across both reports that ran it and was re-run for this
task's oracle: `4456 passed, 3 skipped, 19 xfailed`, exit 0.

---

## 5. Recommended fix order

For the operator to approve. **Nothing here is applied.** Groups are ordered by urgency;
within a group, items are independent unless a dependency is noted. Two cross-cutting
constraints apply to every group:

* **A README block edit is pinned.** Nine test modules read `README.md` and pin content
  fragments — ` ```text `, ` ```bash ` and ` ```json ` blocks, `### ` headings, and
  `| a | b | c | d |` table rows (test-integrity, "README pins"). No test pins a README
  *line number*, so the anchors in this report survive re-flow, but any edit to a quoted
  block must be re-checked against those pins.
* **`tests/escalations.py` is the hub.** R11, R24, R25, R26, R41 and R43 all touch it.
  Sequence them rather than parallelising, to avoid conflicts in one file.

**Group 1 — the two product defects. Do these first; they are the only findings where the
gate reaches a wrong or absent security decision.**

1. **R01** (`--drift-policy abstain` reads the environment only). Touches
   `registry._invoke`, `sec_rules.RuleContext`, `engine.py:881`, `preflight.py:345`.
   *Dependencies:* changes verdict statuses in any run where
   `GCP_GROUNDING_DRIFT_POLICY` is set, so the drift pins in
   `tests/test_gcp_agentic_tf_drift.py` (e.g. `:944`) must be re-read. *Note:* the
   behaviour audit did not probe drift rule 3 (§4), so the fix should land with a probe
   for it rather than assuming the rest of the adjudicator is exercised.
2. **R02** (an emptied deny policy is not recognised). Touches
   `preflight._is_iam_deny_policy` / `detect_kind`. *Dependency:* `detect_kind`'s arm
   order matters — the new `name`-shape sniff must not shadow the Org Policy v2 arm at
   `preflight.py:224-225`, which already sniffs `"/policies/"` in `name`. An emptied
   `rules: []` becoming "captured and empty" also changes `[document]` classification for
   that input, so the `? [document]` expectations for deny-policy fixtures must be
   re-read.

**Group 2 — the hallucinations. Cheap, independent, no behaviour change except H1's
message text.**

3. **R07 / H1** (`--baseline-target` → `--target DOMAIN:KEY`). Highest priority in this
   group: it is the only hallucination the tool prints at a user or an agent. *Dependency:*
   the suite pins verdict message fragments, so check for a pin on the remedy string.
4. **R08 / H2** (delete "or the config key" from `sources.py:46`, `:464`). Docstring only.
   Do **not** add the key — `README.md:1155-1157` explains why its absence is the design.
5. **R09 / H3** and **R10 / H4** (`identity.SPECS`; `gcp_grounding.merge` ×5). Docstring
   only, fully independent.
6. **R11 / H5** (register `ESC-ORGEFF-REGISTER-ACTIVATION` and re-head the xfail reason).
   *Dependency:* `tests/escalations.py`; may need `OUT_OF_DOCUMENT_OWNER_TASKS` extended.
   Land **before** R24/R25/R26 so the register file is touched once per change.
7. **R12 / H6** (`Escalation.closed_by`). Two options; the docstring correction is the
   smaller and matches shipped practice. Choosing instead to *add* the field interacts
   with the frozen self-test's strict-xfail requirement, so that variant is a larger change
   than it looks.

**Group 3 — demo reproducibility. One mechanism, two spellings; fix together or the
half-fix rots again.**

8. **R05** (stamp `examples/terraform-schema/provider-schema.json`, or pin the clock in
   the `verify_schema` arc), **R06** (demo step 4) and **R15** (demo step 3). All three are
   the same root cause in two forms: an embedded `captured_at` that is frozen in file
   content, and a file mtime that a tarball or an old checkout makes stale. *Dependencies:*
   pinning `GCP_GROUNDING_NOW` in a step **changes that step's output**, so the README
   blocks quoting it must be re-derived in the same change, and `tests/test_gcp_run_demo.py`
   re-run. R05's proposed `captured_at` route uses the wrapper envelope at
   `README.md:1416-1418`, which docs-vs-code confirmed exists
   (`provider_schema._WRAPPER_KEYS`), so that route needs no new schema.
9. **R42** (say the no-venv fallback needs z3, or have the runner name the backend it
   resolved). Independent, but belongs with the same reproducibility pass.

**Group 4 — documentation the reader acts on.**

10. **R13** (the terraform precondition and its silent-pass consequence, in `README.md`
    and `simple_readme.md`). *Note:* if the operator prefers the code route — making
    `gate.terraform_route` decide on the snapshot-only path — that is a **product** change
    and belongs in Group 1, not here; it would change exits for existing snapshot-only
    `.tf.json` runs.
11. **R14** (one clause on the `iam_deny_shadow` stated-limits paragraph), **R47** (carry
    `not checked` into the summary's promise list — a small `cli.py` change, not prose),
    **R52**, **R54**, **R55**.
12. **R17** and **R18** together (the "six"→"eleven" count and the "full collection table"
    claim both concern `sec_requirements/README.md`'s collection coverage). *Dependency:*
    if R18 is fixed by moving the 15-row table into the authoring guide, R17's user-facing
    half is fixed with it.
13. **R16**, **R34**, **R35**, **R36**, **R37** (re-capture or mark the elisions in the
    quoted blocks). *Dependency:* the README pin constraint above; re-run the
    `test_gcp_readme_*` modules.

**Group 5 — internal docstrings. Mechanical, zero risk, can be one commit.**

14. **R19**, **R20**, **R53** (the three stale counts), **R21**, **R22**, **R39** (the
    three wrong attribute paths), **R38** (11 role targets wrapped across a line),
    **R23** (12 drifted line anchors). *Recommendation on R23:* prefer the source report's
    second option — drop the `file:line` form for the symbol name alone — since re-pointing
    the anchors guarantees they drift again.

**Group 6 — suite integrity. After Group 1, so the suite pins the fixed behaviour.**

15. **R03** (restore `assert calls["n"] == 1`). **This closes R45 outright** — fixing the
    assertion retires `SA-SECAST-CALLED-ONCE`, which removes the three-mechanism excuse
    chain and one of the three permanent skips.
16. **R04** (mark the test `@_needs_z3` or branch on `HAVE_Z3`). **R04 must land before or
    with R46**: R46's fix runs `tests/test_gcp_sec_cli.py` in a z3-blocked child, which is
    exactly the run R04 fails in.
17. **R46** (run the module once in a z3-blocked child, using the existing
    `blocked_import_env` machinery).
18. **R24** then **R25** then **R26** — three stale-prose fixes in `tests/escalations.py`
    and its neighbours; sequence them in that order for one file. R24's stronger variant
    (compute the counts from `len()`) prevents all three from recurring and is the
    recommended form. Do **not** touch `escalations.py:269-270`'s `clause`, which quotes
    the design verbatim.
19. **R41** (`xfail_strict = true` plus registering A18). Land after R11/R24 so the
    register work is settled.
20. **R43** (raise the spawn ceiling and flip the five `pending` removals). *Dependencies:*
    consumes R25's constants, and **forces three strict xfails to XPASS**, which must be
    retired in the same change — that is the mechanism working as designed, not a
    regression. Budget impact: five additional children against a measured unmarked
    headroom of 14.
21. **R44**, **R49**, **R50**, **R51** (new or strengthened pins). Independent of each
    other. R44 is the largest single coverage win in the group: 7 of 24 documented demo
    rows are asserted nowhere in the suite.
22. **R27**, **R28**, **R29**, **R30** (dead code). R30 is a pure deletion. R28 and R29 are
    a keep-or-delete decision on two exported-but-unused members; either resolution is
    fine, but "keep" means adding the pin. R27 is in vendored `core/` — record a
    `ProductEscalation` rather than editing, unless `core/` is brought into scope.
23. **R48** (quote the four `PRODUCT_ESCALATIONS` from the abstentions they explain) and
    **R40** (re-stamp the 21 `line_hint`s). *Dependency:* do **R40 last** — R43 changes
    which entries execute, and the hints are re-stamped from the line the contract test
    prints, so stamping before R43 would re-stale them.

**Not in any group.** **R56** and **R57** are recorded coverage observations that the
source report explicitly marks "None needed"; they owe no fix.

---

## Appendix — verification performed for this report

Everything below ran in this worktree against
`/home/jones/Downloads/gcp-policy-grounding/.venv/bin/python` (CPython 3.14.7, z3 5.0.0),
with `sys.path` pointed at the worktree so the bytes measured are this tree's. Exit codes
were captured directly.

```
grep -rn "CATEGORY_SPECS" gcp_grounding/                      # H3: 1 hit, knowledge.py:745
grep -n  "tfsource.merge" gcp_grounding/tfsource/map_network.py   # H4: 33,70,619,649,793
ls gcp_grounding/tfsource/                                    # H4: no merge.py
sed -n '46p;464p' gcp_grounding/sources.py                    # H2: both sentences verbatim
sed -n '12,14p'  tests/escalations.py                         # H6: the closed_by sentence
grep -rn "ORG-EFFECTIVE-REGISTER-ACTIVATION" --include='*.py' --include='*.md' .
                                                              # H5: 1 hit outside audits/
grep -rn "baseline-target" gcp_grounding/ tests/ README.md simple_readme.md
                                                              # H1: 1 hit, baseline.py:220
# in-process (worktree on sys.path):
#   dataclasses.fields(Escalation)  -> id, clause, unsatisfiable, owner_task, node_id
#   dataclasses.fields(ProductEscalation) -> …, closed_by
#   len(REQUIRED_MK_IDS)=91  len(register())=44  missing=47
#   AST over tests/: 20 mark.xfail calls = 19 decorators + 1 in pytest.param
#                    (tests/test_gcp_agentic_iam.py:554); all strict=True
python -m pytest -q tests/                                    # 4456 passed, 3 skipped,
                                                              # 19 xfailed — exit 0
```

Spot-checked line anchors that resolved exactly as the source reports state:
`README.md:718-719`, `:1632-1633`, `:1693-1696`; `sec_requirements/README.md:128`;
`sec_ast.py:16`, `:141`; `compare.py:7`; `registry.py:1`; `baseline.py:220`, `:774`;
`cli.py:3729`; `redact.py:758`; `sources.py:315`; `core/solver.py:39`;
`tests/test_gcp_org_effective.py:1190`; `tests/test_gcp_mutation_contract.py:9`, `:11`,
`:216`; `tests/escalations.py:272`, `:274`, `:612`.
