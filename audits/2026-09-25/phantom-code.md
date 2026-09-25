# audit-phantom-code — static integrity of the package

**Scope.** `gcp-policy-grounding` at `90248ba` (branch `agent/audit-phantom-code`,
a worktree of that commit; `git diff --name-only integration/gx-base -- gcp_grounding
tests examples run_demo.sh README.md simple_readme.md sec_requirements` is empty, so the
tree audited is the tree that shipped). Read-only: the only file this task wrote is
this report. Every probe lived under the task scratchpad
(`…/scratchpad/probes/`), never in the repo.

**Interpreter.** `/home/jones/Downloads/gcp-policy-grounding/.venv/bin/python`
(CPython 3.14.7, z3 present). **Critical detail for anyone reproducing this:** that
venv resolves `gcp_grounding` to the **main checkout**
(`/home/jones/Downloads/gcp-policy-grounding/gcp_grounding/__init__.py`), not to a
worktree — verified with `python -P -c "import importlib.util; print(importlib.util.find_spec('gcp_grounding').origin)"`.
Every probe therefore does `sys.path.insert(0, <worktree root>)` as its first statement,
and every probe result below is about **this worktree's** bytes. Exit codes were captured
directly (`; echo "exit=$?"`), never through a pipe.

**Method, by clause of the task.**

1. `python -m compileall -q gcp_grounding`, then an AST walk over all 79 package
   files: every `import X` / `from Y import Z` resolved through
   `importlib.import_module` and `hasattr`, and every `<alias>.<attr>` load where
   `<alias>` is bound to a module checked with `hasattr`. The walker was
   **self-tested against a mutant** (a scratch copy of the package with
   `from os import no_such_name_xyz` and `os.no_such_attr_xyz` appended to
   `registry.py`): it reported 18 problems and exited 1, so a green run is not a
   vacuous one.
2. `registry.PROVIDER_MODULES` imported one by one; every `DOCUMENT_EXTRACTORS` /
   `TF_EXTRACTORS` / `CLAIM_CHECKS` / `DOCUMENT_CHECKS` / `PAIR_CHECKS` entry
   resolved to a callable and its `inspect.signature` compared against the
   **arity the call site actually passes** (read out of `registry._invoke`,
   `tf_claims.terraform_plan_claims`, `preflight.py:436`, not out of the
   docstring). The second name-based registry, `sec_domains.DOMAIN_MODULES` /
   `COLLECTION_SPECS` / `DOMAIN_COLLECTIONS` / `BASE_COLLECTION_OVERRIDES`, audited
   the same way, with `sec_domains.register()` driven live.
3. Escalation register: **both directions**. Every `ESC-…`-shaped token in every
   `.py`/`.md`/`.sh`/`.json`/`.toml` file in the tree matched against
   `ESCALATIONS ∪ PRODUCT_ESCALATIONS`; every register entry searched for outside
   its own definition; and a separate AST pass over every `pytest.mark.xfail`
   decorator in `tests/`, reading the `reason=` string and checking the id it
   names. The id regex was then **widened past `ESC-`** to any
   `(ESC|RM|MK|SA|REM|ORG|GX|RMV)-SCREAMING-KEBAB` token and matched against every
   register that could define one (155 known ids) — which is how PC-03 was found.
4. Mutation register: the **live machinery tests were run and are cited**, not
   re-implemented — `tests/test_gcp_mutation_contract.py::test_the_anchor_of_every_entry_resolves_on_content_and_drift_only_prints`
   and `::test_every_named_node_id_still_collects_and_each_exemption_prints`.
   Register statistics read from `mutation_contract.register()` /
   `removal_register()` in-process.
5. Dead-code census: AST inventory of every module-level `def`/`class` and every
   method of a module-level class in `gcp_grounding/` (1984 definitions), against an
   identifier index built over the whole tree (437 files: package, tests, CLI,
   scripts, fixtures, README, `run_demo.sh`, `pyproject.toml`). A definition counts
   as referenced if its bare name occurs anywhere except its own `def`/`class`
   line — deliberately the *loosest* possible test, so anything it flags is flagged
   on the strongest possible evidence. Dunders excluded (the interpreter calls
   those). Each hit re-checked by hand with `grep -rn` over the whole tree.
6. CLI: `cli.build_parser()` built live, every subparser's `_actions` enumerated
   (51 actions), each `dest` traced to a **read off the parsed namespace** —
   `args.<dest>`, `getattr(args, "<dest>", …)`, or a string-keyed
   `getattr(args, flag)` table whose literal names it. Attribute reads on any
   receiver other than `args` were excluded after a first pass showed them
   producing false "reads" (`ctx.snapshot`, `options.precedence`, …). Settings
   layering: the `SETTINGS_FIELDS × {cli, env, config}` matrix derived from
   `discovery.CONFIG_KEYS`/`TERRAFORM_KEYS`, `sources.ENV_FIELDS`,
   `discovery.REQUIREMENTS_ENV` and `cli._cli_layer`'s own table, then **round-tripped
   live**: each field supplied through exactly one layer and
   `Settings.origin_of(field)` asserted to name that layer.

---

## Findings

| id | severity | location | claim | evidence | proposed fix (NOT applied) |
|----|----------|----------|-------|----------|-----------------------------|
| PC-01 | hallucinated | `gcp_grounding/sources.py:46`, `gcp_grounding/sources.py:464` | Both say `completeness` "is set explicitly — `--completeness` **or the config key** — or not at all". There is no config key for `completeness`, and naming one **refuses the operator's whole config file**. | `discovery.CONFIG_KEYS` = `{snapshot, precedence, max_age, drift, targets, requirements, provider_schema, schema_policy}`; `TERRAFORM_KEYS` = `{state, plan, config_dir}`; `'completeness' in CONFIG_KEYS` → `False`. Writing `{"schema":"gcp-grounding-config/1","snapshot":"estate.json","completeness":"complete"}` and calling `discovery.discover(d)` returns `cfg=None` with the problem `"unrecognized config key(s) ['completeness'] - a typo must not silently demote a setting; expected only ['drift','max_age','precedence','provider_schema','requirements','schema','schema_policy','snapshot','targets','terraform']"`, and `resolve_settings(config=None).origin_of('completeness')` → `'default'`. `README.md:1155-1157` states the opposite and correct thing: *"There is deliberately no config-file key and no environment variable for `--completeness`"*. | Delete "or the config key" from both docstrings (`sources.py:46`, `sources.py:464`), leaving `--completeness` as the one spelling — matching README and the parser. Do **not** add the key: the README paragraph explains why its absence is the design. |
| PC-02 | hallucinated | `tests/escalations.py:13` | The module docstring says an escalation is closed by deleting the xfail and *"the entry stays, with `closed_by` naming the change"*. `Escalation` has no `closed_by` field. | `dataclasses.fields(Escalation)` → `['id','clause','unsatisfiable','owner_task','node_id']`; `dataclasses.fields(ProductEscalation)` → `[…,'closed_by']`. The same file's own retirement comments contradict the docstring twice: `tests/escalations.py:309-311` *"this register carries no `closed_by` for a node-bearing entry"*, and `:540-542` identically. Consequence, visible in the file: both retired `Escalation`s (`ESC-GX-IAM-REPIN-SPLIT`, `ESC-GX-ABSTAIN-PASSED-HEADER`) had to be **deleted** and replaced with a prose `# RETIRED —` comment, because the documented mechanism does not exist. | Either add `closed_by: str = ""` to `Escalation` and relax the frozen self-test's strict-xfail requirement for entries that carry one, or correct the docstring at `:12-13` to describe what actually happens (the entry is deleted and a `# RETIRED —` comment records the closure). The second is the smaller change and matches shipped practice. |
| PC-03 | hallucinated | `tests/test_gcp_org_effective.py:1190` | A `strict=True` xfail whose reason is headed `"ORG-EFFECTIVE-REGISTER-ACTIVATION: …"` — the exact shape the other 18 strict xfails use to name their escalation — but that id exists in **no** register. | Sweep of every escalation-shaped id in the tree against `ESCALATIONS`, `PRODUCT_ESCALATIONS`, `mutation_entries.*`, `spec_assertions.ASSERTIONS` and `REQUIRED_MK_IDS` (155 known ids): 5 referenced ids are unregistered, and of those exactly two are named by an xfail reason — `REM-GX-HFW-FOLD` (registered-as-unregisterable on purpose; see VT-11) and `ORG-EFFECTIVE-REGISTER-ACTIVATION`, which is in nothing. The reason text itself only *cites* the registered `ESC-DENY-REGISTER-ACTIVATION` as an analogue ("the same recorded constraint the deny pair's ESC-DENY-REGISTER-ACTIVATION names"). Effect: `tests/test_gcp_escalations.py` walks register → node, so this node is invisible to the frozen self-test; no `clause`, `unsatisfiable` or `owner_task` is recorded for the fourteen parked MK-F entries. | Append an `Escalation(id="ESC-ORGEFF-REGISTER-ACTIVATION", …, node_id="tests/test_gcp_org_effective.py::test_the_org_effective_mutation_entries_are_active_in_the_register")` to `tests/escalations.py` (which is deliberately un-frozen) and re-head the xfail reason with that id. `escalations.py` would also need `OUT_OF_DOCUMENT_OWNER_TASKS` extended if the owner is a predecessor-document task. |
| PC-04 | misdocumented | `tests/test_gcp_mutation_contract.py:215-216`, `tests/test_gcp_mutation_contract.py:9-11`, `tests/escalations.py:270-274` | Three places state the mutation-register debt as *"44 of the 65"* / *"the missing 21"*. The required tuple is now **91** ids and **47** are missing. | In-process: `len(REQUIRED_MK_IDS)` = 91 (and `test_the_pinned_tuples_hold_and_the_register_names_no_stranger:204` asserts exactly that), `len(register())` = 44, `sorted(set(REQUIRED_MK_IDS) - {e.id for e in register()})` = 47 ids. The growth is itself documented at `tests/test_gcp_mutation_contract.py:40-48` (65 → 77 with MK-D01..D12, 77 → 91 with MK-F01..F14) — only the three debt sentences were not updated. The stalest is the xfail `reason`, because that string is what a reader sees: `pytest -rx` prints `XFAIL … ESC-GX-GATE-001: the register holds 44 of the 65`, understating the gap by 26 ids on every run. | Update the `reason=` at `:215-216` to "44 of the 91", the module docstring at `:9-11`, and `ESCALATIONS`' `unsatisfiable` at `tests/escalations.py:272-274` ("the missing 47"). The `clause` field at `:269-270` quotes the design verbatim and should **not** be touched. |
| PC-05 | misdocumented | `tests/test_gcp_hfw_checks.py:1612`, `tests/escalations.py:178-179` | Both record as measured fact that `tests/mutation_entries.py` (and `tests/mutation_contract.py`) are *"absent from this checkout"* / *"neither file is in this checkout at all"*. Both files are present. | `ls tests/mutation_entries.py` → exists (1160 lines); `tests/mutation_contract.py` → 529 lines; both import in-process (`register()` returns 44 entries). The escalation still stands on its *other*, live ground — `grep -rn REM-GX-HFW-FOLD` finds the id only in `tests/escalations.py:171` and `tests/test_gcp_hfw_checks.py` (never in `mutation_entries.py`), so the assertion `"REM-GX-HFW-FOLD" in source` genuinely still fails and the strict xfail is honest. Only the stated reason has rotted. | Rewrite both reasons to the surviving fact ("`tests/mutation_entries.py` is a FROZEN acceptance path for `gx-hierfw-placement` and does not yet carry `REM-GX-HFW-FOLD`"), dropping the absent-from-this-checkout clause. |
| PC-06 | dead-code | `gcp_grounding/cli.py:3729` | `_collection_rows(sec_rules, ctx, name)` — a one-line wrapper returning `_collection_reading(...)[0]`, called from nowhere. | The identifier `_collection_rows` occurs **exactly once** in the whole tree: `grep -rn "_collection_rows" .` (excluding `.git/`) → `gcp_grounding/cli.py:3729:def _collection_rows(...)`. Not in `__all__` (`cli.__all__` does not carry it), not reachable by name (no `getattr` on a string that spells it). Judgment: **dead** — private, unexported, unreferenced, untested. | Delete it. Its body is `return _collection_reading(sec_rules, ctx, name)[0]`, so nothing is lost; any future caller can index `_collection_reading` directly, as the four live callers of that function already do. |
| PC-07 | dead-code | `gcp_grounding/redact.py:758` | `SecretVault.add_all(values)` is never called. | `grep -rn "add_all" .` (excluding `.git/`) → one hit, the `def` line. `SecretVault` *is* exported (`redact.__all__` line 72 carries `"SecretVault"`), so this is a public class's public method — but no caller, in the package, the CLI, `show_promises.py` or any of the 150 test modules, and no test exercises it. Judgment: **public API by declaration, dead by use** — an untested convenience loop over `add`. | Either delete it (callers already loop over `add`, which returns the store/skip decision this method discards), or keep it and pin it with a test; leaving an untested public method is how the `add` contract and the `add_all` contract drift apart. |
| PC-08 | dead-code | `gcp_grounding/sources.py:315` | `SourceOptions.any_source` (a `@property`) is never read. | `grep -rn "any_source" .` (excluding `.git/`) → one hit, the `def` line. `SourceOptions` is exported (`sources.__all__`). Every live caller asks `configured()` directly (e.g. `sources.py` and `estate.py` call sites), which is what `any_source` wraps in `bool(...)`. Judgment: **public API by declaration, dead by use**. | Delete it, or pin it. The docstring's claim ("Whether ANY source is configured. Zero is not an error") is true of `bool(self.configured())` today, but nothing asserts it stays true. |
| PC-09 | dead-code | `gcp_grounding/core/solver.py:39` | `ConstraintSolver.mutually_exclusive_always_false(guards)` is called nowhere, overridden nowhere, and its docstring promises a generalization that does not exist: *"with z3 this generalizes to symbolic conditions."* | `grep -rn "mutually_exclusive_always_false" .` (excluding `.git/`) → one hit, the `def` line. Neither subclass in the file (`BuiltinSolver:59`, `Z3Solver:74`) overrides it; `Z3Solver` overrides only `arity_satisfies` and `explain`. So the z3 generalization the docstring forward-references is not merely unimplemented — there is no override seam in use for it. Judgment: **dead**, in vendored `core/`. | Vendored `gcp_grounding/core/` is out of bounds for a test task (the convention `PRODUCT_ESCALATIONS` exists for), so the honest move is a `ProductEscalation` recording it rather than an edit. If `core/` is ever in scope: delete the method, or drop the "with z3 this generalizes" sentence, which is the part that reads as a promise. |
| PC-10 | note | `tests/escalations.py:786`, `:809`, `:853`, `:892` | Four of the ten `PRODUCT_ESCALATIONS` are quoted **nowhere** outside the register, although `ProductEscalation.id`'s own doc comment (`tests/escalations.py:74`) says "Stable id, quoted from the module that works around it", and `_DENY_SCOPE_NOTES`' docstring (`:781-784`) says each is recorded "so a reader of a named abstention can find why it is the intended state". | Reverse sweep over the whole tree: `ESC-DENY-ESTATE-TIER`, `ESC-DENY-GROUP-MEMBERSHIP`, `ESC-DENY-CONDITION-SAT`, `ESC-DENY-PRINCIPAL-HIERARCHY` have `total=1` reference each — their own definition. Contrast the two that work as documented: `ESC-DENY-ALLOW-CONDITIONS` is in the *runtime verdict text* (`gcp_grounding/iam_deny_checks.py:762` `"…the allow×deny interaction was not decided (ESC-DENY-ALLOW-CONDITIONS)"`, and again at `:1062`), so its own `residual_risk` claim — "the abstention is loud and names ESC-DENY-ALLOW-CONDITIONS" — holds; `ESC-DENY-FETCH-CAPTURE` is quoted from `gcp_grounding/facts.py:431` and `iam_deny_checks.py:960`. | Quote each of the four from the abstention it explains — the id in the `unverified` message where the abstention is minted, as `ESC-DENY-ALLOW-CONDITIONS` already does — or, where no message exists to carry it, from the code comment at the site. A register entry nothing points at is a note nobody will find from the output. |
| PC-11 | cosmetic | `tests/mutation_entries.py` (21 entries) | 21 of the 44 mutation entries carry a `line_hint` that no longer sits inside the scope their anchor resolves in. The field is advisory by contract, so nothing breaks — but its stated purpose ("printed in every failure") is to help a human find the site, and the printed number is up to ~1,000 lines off. | `tests/test_gcp_mutation_contract.py::test_the_anchor_of_every_entry_resolves_on_content_and_drift_only_prints` PASSES and prints 21 `DRIFT` lines, e.g. `DRIFT MK-I13: hint 548 outside _guarded.extract (1580-1596); the anchor resolved at 1594` and `DRIFT MK-I26: hint 664 outside load_rules (988-1046); the anchor resolved at 1027`. Contract at `tests/mutation_contract.py:47-48`: *"`line_hint` is ADVISORY: printed in every failure, NEVER asserted."* | Re-stamp the 21 hints from the resolved line the test already prints. Content anchoring is working exactly as designed — this is the navigation aid, not the anchor. |

---

## Verified true

Everything below was checked and **held**, with the evidence that established it. These
are the coverage claims, not the failures.

**VT-01 — the package compiles.** `python -m compileall -q gcp_grounding` → `exit=0`,
no output. All 79 files.

**VT-02 — every import resolves, and every attribute referenced on an imported module
exists.** AST walk over all 79 package files: **1003 imported names checked, 1385
module-attribute loads checked, 0 problems, exit 0.** Relative imports resolved by
package level (`from ..preflight import …` in `tfsource/discover.py`, `from .core.log
import get_logger` in `registry.py`, etc.). The walker's teeth were demonstrated on a
mutant copy (18 problems, exit 1), so the zero is a measurement, not a silence.

**VT-03 — every `__all__` name exists.** 820 names across the package, each checked with
`hasattr` on the imported module. 0 phantoms. (A name in `__all__` that the module does
not define is the classic quiet phantom — `from mod import *` raises, everything else
passes.)

**VT-04 — all 16 `registry.PROVIDER_MODULES` import and every one registers something.**
`fw_claims`, `fw_checks`, `fw_estate`, `hfw_claims`, `hfw_checks`, `armor_claims`,
`armor_checks`, `vpcsc_claims`, `vpcsc_checks`, `iam_deny`, `iam_checks`, `iam_scope`,
`iam_deny_checks`, `org_checks`, `org_effective`, `tf_schema_checks` — 16/16 importable,
16/16 exposing at least one of the five documented tables, and every entry in
`PROVIDER_MODULES` has a file in this checkout (`missing = []`). The module's
"naming one that is absent is not an error" fail-open path is therefore not being
relied on to hide anything here.

**VT-05 — every registered callable exists and takes the arity its call site passes.**
37 registrations checked against `inspect.signature`, 0 arity mismatches:
11 `DOCUMENT_EXTRACTORS`+`TF_EXTRACTORS` pairs at `(address, values)` / `(document)`,
3 `CLAIM_CHECKS` at `(claim, ctx)`, 12 `DOCUMENT_CHECKS` at `(ctx)`, 3 `PAIR_CHECKS` at
`(ctx)`. Arities were taken from the *call sites* — `registry._invoke(fn, ctx, claim, ctx)`
at `registry.py:464`, `_invoke(fn, ctx, ctx)` at `:508`/`:517`,
`extractor(address, values)` at `tf_claims.py:100`, `list(extract(doc))` at
`preflight.py:436` — not from the registry docstring, so this is a check of the
docstring too. The merged views the gate actually consumes:
`registry.tf_extractors()` → 12 resource types;
`registry.document_checks()` → 12 checks in provider order.

**VT-06 — no registry table is defined outside `PROVIDER_MODULES`.** AST scan for
module-level assignments named `DOCUMENT_EXTRACTORS`/`TF_EXTRACTORS`/`CLAIM_CHECKS`/
`DOCUMENT_CHECKS`/`PAIR_CHECKS` across the whole package: 16 modules define one, and
all 16 are in `PROVIDER_MODULES`. A table nobody discovers — a domain module that looks
wired and is not — does not exist here.

**VT-07 — the second, name-based registry (`sec_domains`) is whole.** All 5
`DOMAIN_MODULES` values import (`iam_deny`, `fw_claims`, `armor_claims`,
`org_effective`, `vpcsc_claims`). `COLLECTION_SPECS` (11 names) and the union of
`DOMAIN_COLLECTIONS` (11 names) are **equal** — no spec nobody declares, no declared
collection with no spec. After a live `sec_domains.register()`, all 11 specs plus both
`BASE_COLLECTION_OVERRIDES` (`iam_bindings`, `org_policy_rules`) have both a registered
spec in `sec_ast.COLLECTIONS` and a registered extractor in `sec_rules.EXTRACTORS`, and
both override targets exist as `sec_rules` built-ins. One asymmetry, benign and checked:
`hier_firewall` appears in `DOMAIN_COLLECTIONS` but not `DOMAIN_MODULES` — correct,
because `hier_firewall_rules`' extractor (`_estate_hier_firewall_rules`) is estate-built
and registered unconditionally at `sec_domains.py:1671-1673`, needing no claims module.

**VT-08 — the console entry point resolves.** `pyproject.toml` declares
`gcp-ground = "gcp_grounding.cli:main"`; `cli.main` exists with signature
`(argv: 'list[str] | None' = None) -> 'int'`.

**VT-09 — every escalation id named by an xfail reason exists.** All 19
`pytest.mark.xfail` decorators in `tests/` are `strict=True`, all 19 carry an id in
their reason, and every `ESC-…` id among them is in `ESCALATIONS` or
`PRODUCT_ESCALATIONS`. (The count matches the suite: `4456 passed, 3 skipped,
19 xfailed`.)

**VT-10 — retired ids appear only where documented.** Exactly two ids are referenced but
absent from the registers by design: `ESC-GX-IAM-REPIN-SPLIT` and
`ESC-GX-ABSTAIN-PASSED-HEADER`. Both carry a `# RETIRED —` block in
`tests/escalations.py` (`:307-316` and `:538-552`) explaining why the entry was deleted
rather than kept. Every remaining reference is retirement *narrative* — a docstring or an
assertion message saying what was fixed: `tests/test_gcp_agentic_iam.py:37,780`
("…which lands it here and RETIRES that escalation"),
`tests/test_gcp_agentic_abstain.py:923,947,958` ("Until `ESC-GX-ABSTAIN-PASSED-HEADER`
was retired…", and the failure message that fires if the defect returns). No retired id
is load-bearing anywhere. A third unregistered token, `ESC-GX-SPEC-999`
(`tests/test_gcp_escalations.py:211`), is a *deliberate* synthetic in the self-test's own
teeth (`test_a_strict_xfail_that_names_another_escalation_is_caught`) and must not exist.

**VT-11 — `REM-GX-HFW-FOLD` is unregistered on purpose, and says so.**
`tests/escalations.py:166-193` (`ESC-GX-HFW-FOLD-ENTRY`) specifies the entry in full and
records that it cannot be registered from there, including the residual risk of an id
mismatch. The strict xfail at `tests/test_gcp_hfw_checks.py:1610` names the *registered*
`ESC-GX-HFW-FOLD-ENTRY` in its reason, so the frozen self-test can walk it. This is the
mechanism working — contrast PC-03, where no such entry exists. (Its "absent from this
checkout" clause has rotted; that is PC-05.)

**VT-12 — every register entry in `ESCALATIONS` is referenced outside the register.**
All 18 `Escalation`s are quoted from at least one other file (the xfail that carries them,
plus docstrings and, for `ESC-GX-SECCLI-001`, the product code at
`gcp_grounding/cli.py:2844,2872`). 6 of the 10 `PRODUCT_ESCALATIONS` likewise; the other
4 are PC-10.

**VT-13 — every mutation-register anchor resolves on content.**
`tests/test_gcp_mutation_contract.py::test_the_anchor_of_every_entry_resolves_on_content_and_drift_only_prints`
→ **PASSED**. This is the live machinery test, cited rather than re-implemented as the
task requires; it drives `mutation_contract.mutate()` over all 44 entries and fails on
any anchor that does not resolve uniquely inside its declared scope. Its 21 `DRIFT`
stdout lines are the advisory `line_hint` staleness, PC-11 — not anchor failures.

**VT-14 — every `must_fail` node id collects.**
`tests/test_gcp_mutation_contract.py::test_every_named_node_id_still_collects_and_each_exemption_prints`
→ **PASSED**, asserting `not absent` over the union of node ids from every ACTIVE entry
and every live `Removal`, against a real `pytest --collect-only` of the tree. The 11
`EXEMPT` lines it prints are node ids belonging to the 5 `pending` `Removal`s
(`RM-NETWORK-PLANE-UNAVAILABLE`, `RM-VPCSC-DOCUMENT-AND-PAIR-CHECKS`,
`RM-VPCSC-DOMAIN-UNREGISTERED`, `RM-VPCSC-ABSENT-VERSUS-EMPTY`,
`RM-HOOK-SUCCESS-BEFORE-THE-EVENT`) — declared debt, printed by design, and a subset of
`PENDING_REMOVAL_IDS` (7 named, 5 actually pending; the pin is `<=`, so it is shrink-only
and holding).

**VT-15 — the register's own state machine is clean.**
`::test_awaiting_is_computed_a_subset_of_its_pin_and_under_the_floor` → **PASSED**:
`AWAITING_MAX` is empty, `AWAITING_COUNT_MAX` is 0, and all 44 entries compute ACTIVE, so
nothing is parked behind the floor. `register()` = 44 entries, `removal_register()` = 19.

**VT-16 — no argparse flag is parsed and ignored.** All **51** actions across the root
parser and its four subcommands (`verify-policy` 27, `capture-terraform` 15,
`scan-command` 2, `compile-requirements` 7) reach a read off the parsed namespace.
45 are read as `args.<dest>`; 6 are reached through `cli._cli_layer`'s string-keyed
`getattr(args, flag, None)` tables at `cli.py:1366-1379` (`--snapshot`, `--origins`,
`--merge-source`, `--terraform-plan`, `--terraform-dir`, `--drift-policy`,
`--completeness`, `--schema-policy`, `--provider-schema`, depending on subcommand).
`--merge-source` is the one flag with *no* `args.merge_source` attribute access anywhere
— it is read only at `cli.py:1374` as the string `"merge_source"` in that table, which is
a real read and was verified by reading the loop.

**VT-17 — every settings-layer key round-trips.** `discovery.SETTINGS_FIELDS` = 15
(`OPTION_FIELDS` 13 + `targets` + `requirements`), and `OPTION_FIELDS` is derived from
`dataclasses.fields(SourceOptions)`, so it cannot drift from the options object. Live
round-trip, one layer at a time, asserting `Settings.origin_of(field)`:

* **cli**: 15/15 report `origin='cli'` **and** hold the exact value supplied.
* **env**: 13/13 of the fields that declare an env var report `origin='env'` — the 12
  in `sources.ENV_FIELDS` plus `requirements` via `discovery.REQUIREMENTS_ENV`, which
  `_env_layer` reads directly because it has no `SourceOptions` slot.
* **config**: 11/11 of the fields with a config key report `origin='config <path>'`,
  covering both `CONFIG_KEYS` (8) and the nested `TERRAFORM_KEYS` (3).

Total round-trip failures: **0**. The three gaps in the matrix are deliberate and
correctly documented: `completeness` is CLI-only (`sources.py:43-45` explains why an
exported variable must not be able to license absence reasoning — and `README.md:1155`
confirms no config key either; the docstring's claim that there *is* one is PC-01);
`origins`, `extra` and `now` have no config key; `targets` has no env var. The config
parser also **validates vocabularies at parse time** and refuses the whole file on a bad
one — observed during this audit when deliberately bad values were tried:
`'drift' 'strict' is not one of ['annotate','block','abstain']`,
`'schema_policy' 'strict' is not one of ['block','annotate','off']`,
`'precedence' 'fresh-wins': unknown precedence token …`, and a `targets` entry that is
not a `<domain>:<key>` string. The CLI and env layers do not validate at this boundary
(`resolve_settings(cli={'precedence': 'fresh-wins'})` yields `origin='cli'` and the bad
value intact) — by design, since `sources.load_current` owns that refusal for a human
(`sources.py:738,769`), but worth knowing the two layers differ in *where* they refuse.

**VT-18 — the dead-code census found four orphans and nothing else.** 1984 definitions
inventoried, 857 referenced only inside their own defining module (private helpers —
used, not dead), and exactly **4** referenced nowhere at all: PC-06 … PC-09. Every one
was re-confirmed by hand with a tree-wide `grep -rn` returning a single hit, the
definition line itself. No *class* in the package is unreferenced. `show_promises.py`,
the one repo-root script, compiles (`python -m py_compile show_promises.py` → `exit=0`),
imports only `json`/`sys`/`pathlib`, and is referenced from `README.md:246,497,500,1491,1683`,
`simple_readme.md:114`, `gcp_grounding/cli.py:3351` and `tests/test_gcp_cli_summary.py:921,942`.

**VT-19 — the suite is green, twice.** `python -m pytest -q tests/` →
`4456 passed, 3 skipped, 19 xfailed in 115.99s`, `exit=0`, run before any audit work; the
targeted machinery re-run (VT-13 … VT-15) was consistent with it. No finding in this
report reddens the suite, and none was produced by changing it.

---

## What this audit did **not** cover

Stated so the coverage above is not read wider than it is.

* **Docstring cross-references** (`:func:`/`:mod:`/`:class:`/`:data:` targets) and README
  claims generally — `audit-docs-vs-code`'s scope. PC-01 is in this report only because
  it is a *settings-layer key* claim, which clause (6) puts here.
* **Behavioral guarantees** (hook byte-silence, freshness ceilings, shadow findings, the
  evidence floor) — `audit-behavior-claims`' scope. This report proves the registered
  check *exists and is callable with the right arity*, never that it decides correctly.
* **Whether a test proves what it appears to prove** — `audit-test-integrity`'s scope. The
  mutation-register clause here was deliberately satisfied by *citing* the live machinery
  tests rather than re-deriving their verdicts.
* **Dynamic reachability.** The dead-code census is name-based. A definition reached only
  through a computed string this audit could not see would be misreported as dead — which
  is why all four hits were re-checked by hand, and why each carries a judgment rather
  than a verdict.
