# Audit: every documented name and claim exists and behaves as described

**Task:** `audit-docs-vs-code` (design `designs/gcp-codebase-audit.md`)
**Repository:** `gcp-policy-grounding` at `main` `90248ba`
**Date:** 2026-09-25
**Nature:** READ-ONLY. Nothing outside this file was changed. Every probe ran from a
scratchpad outside the repository; the only artifacts written under the repo are this
report and its `audits/2026-09-25/` directory.

## Scope

Every name and claim made by:

| Source | Extent |
| --- | --- |
| `README.md` | all 2 896 lines — the surfaces table, "How the gate thinks", the collection/sort table, the worked IAM encoding, the four reasoning rules, both LLM instruction blocks, "The three inputs" §1–§7, the provider-schema section, Layout, Development, and all of "Running the demo" including the at-a-glance table and scenarios 1–12/w |
| `simple_readme.md` | all 127 lines |
| `sec_requirements/README.md` | all 146 lines |
| `gcp-ground --help` | the top-level parser plus all four subcommands (`verify-policy`, `capture-terraform`, `scan-command`, `compile-requirements`) — 49 flags |
| module docstrings | every docstring (module, class, function) in the 79 `.py` files under `gcp_grounding/` |

## Method

All probes ran under `/home/jones/Downloads/gcp-policy-grounding/.venv/bin/python`
(Python 3.14.7, z3 5.0.0) with the **worktree** copy of the package on `sys.path`
(verified: `gcp_grounding.__file__` →
`/home/jones/Downloads/.harness-wt/gcp-policy-grounding/wt-audit-docs-vs-code/gcp_grounding/__init__.py`).
Exit codes were captured directly from `$?`, never through a pipe.

1. **Registry resolution.** `sec_ast.COLLECTIONS` before/after `sec_domains.register()`,
   `sec_ast.SORTS` / `BV_WIDTHS` / `TIERS`, `sec_artifact.{DOMAINS,MODES,STATUSES,VOCAB_KINDS,ORIGINS,SEC_SCHEMA}`,
   `core.report.STATUSES`, `preflight.DOCUMENT_KINDS`, `reasoner.EXISTENCE_KINDS`,
   `knowledge.GcpSnapshot` fields, `registry.PROVIDER_MODULES`, `discovery.{CONFIG_KEYS,TERRAFORM_KEYS,SETTINGS_FIELDS,ORIGIN_LABELS}`,
   `baseline.HOWS`, `drift.DRIFT_POLICIES`, `freshness.MAX_AGE_DEFAULT`,
   `provider_schema.{WRAPPER_SCHEMA,_WRAPPER_KEYS}`, diffed against the prose.
2. **Verdict kinds.** An AST walk over every `Verdict(...)` construction in
   `gcp_grounding/`, resolving each `kind` (literal or named constant) to a string, then
   diffed against the 31 distinct `[bracketed]` families the READMEs print.
3. **Cross-references.** An AST walk collecting **1 458** `:func:`/`:mod:`/`:class:`/`:data:`/
   `:meth:`/`:attr:`/`:exc:`/`:obj:`/`:const:` role targets from every docstring
   (907 distinct names), each resolved by import + attribute chase, with the
   containing module and enclosing class as fallback scopes and dataclass
   annotations treated as real attributes. Every survivor was adjudicated by hand.
4. **Line anchors.** Every `<file>.py:<line>` anchor inside a docstring (16 of them)
   resolved, and the lines it points at compared against what the sentence claims.
5. **Counted claims.** Every "N <collections|domains|categories|tables>" phrase in the
   package and the docs resolved against the corresponding table's `len()`.
6. **Paths and anchors.** All 118 repo-relative paths named by the three docs
   `os.path.exists()`-checked; all 34 `README.md` intra-page anchors resolved against
   its headings under GitHub's slug rules.
7. **CLI surface.** `--help` captured for the parser and all four subcommands; every
   flag extracted and diffed both ways against the docs; all 17 `GCP_GROUNDING_*`
   names in the package diffed against the 12 the docs name.
8. **Explainer reproduction (required by the task).** The "IAM encoding, worked end
   to end" section re-derived by running the real tools: the compile, `show_promises.py`,
   `sec_rules.iam_bindings` over `examples/walkthrough/policy.json`, `sec_encode.ground`
   over those rows, `sec_probes.obligation`, and the full walkthrough `verify-policy`
   run — each diffed against the README's printed version.
9. **Spot behaviour.** Exit codes and headline text for the hook pair, `scan-command`,
   the `.tf.json`-without-state route, the `--schema-policy annotate` demotion, and the
   with/without-`--provider-schema` byte-identity claim.

---

## Findings

Severity vocabulary is the design's: broken / real-bug / misdocumented / dead-code /
hallucinated / cosmetic / note. **No fix below was applied.**

| id | severity | location | claim | evidence | proposed fix (NOT applied) |
| --- | --- | --- | --- | --- | --- |
| D1 | misdocumented | `sec_requirements/README.md:128-130` | "The domain layer (`sx-sec-domains`) registers **six** more **once it lands** — `proposed_firewall_rules`, `firewall_rules`, `hier_firewall_rules`, `armor_rules`, `perimeter_resources` and `perimeter_restricted_services`." | It registers **eleven**, and it landed. `len(sec_domains.COLLECTION_SPECS) == 11`; `len(sec_ast.COLLECTIONS)` goes 4 → 15 across `sec_domains.register()`. The five the sentence omits are `deny_rules`, `deny_rule_exceptions`, `effective_org_policy_bool`, `effective_org_policy_values`, `proposed_role_permissions`. `README.md:364-365` states the correct number ("the eleven the domain layer registers"), so the two files contradict each other. | Replace the prose with the eleven names (or the full table), and drop "once it lands". |
| D2 | misdocumented | `README.md:718-719` | "`sec_requirements/README.md` is the canonical grammar: every node keyword, every term, every header key, **and the full collection table**." | `sec_requirements/README.md:121-126` tabulates **4** collections (`iam_bindings`, `org_policy_rules`, `new_iam_bindings`, `old_iam_bindings`) and names 6 more in prose with "Their field lists live with that task" — 10 of 15 collections, and field lists for 4. The full table is `README.md:367-382`. The node-keyword, term and header-key claims all hold (see *Verified true*). | Either move/duplicate the 15-row table into `sec_requirements/README.md`, or change the sentence to "every node keyword, every term and every header key; the full collection table is above". |
| D3 | misdocumented | `gcp_grounding/sec_ast.py:16` and `:141` | Module docstring: "a registry seeded with the four base entries and extended by **the six domain sections**"; comment: "The **six** domain collections would exist only if…" | Same measurement as D1: eleven domain collections. The neighbouring claims in the same docstring ("four base entries", lazy `_ensure_domains`, fail-open, `UnknownCollection`) all hold. | s/six/eleven/ in both places. |
| D4 | hallucinated | `gcp_grounding/knowledge.py:745` | `:data:\`gcp_grounding.identity.CATEGORY_SPECS\`` — "The table is keyed `projects/<project>/global/securityPolicies/<name>`, as `gcp_grounding.identity.CATEGORY_SPECS` requires…" | `hasattr(gcp_grounding.identity, 'CATEGORY_SPECS')` → `False`. The module exports `SPECS` (`identity.py:597`, `Mapping[str, CategorySpec]`) and the class `CategorySpec` (`identity.py:212`); `identity.py:18` documents them as "`:class:`CategorySpec`` and `:data:`SPECS``". | `:data:\`gcp_grounding.identity.SPECS\``. |
| D5 | hallucinated | `gcp_grounding/tfsource/map_network.py:33`, `:70`, `:619`, `:649`, `:793` | `:mod:\`gcp_grounding.tfsource.merge\`` — five references, e.g. "`gcp_grounding.tfsource.merge` assembles fragments in priority then address order". | No such module: `gcp_grounding/tfsource/` holds `discover.py`, `hcl.py`, `hcl_lite.py`, `map_network.py`, `map_policy.py`, `mapping.py`, `normalize.py`, `plan.py`, `state.py` and `__init__.py`. `importlib.import_module('gcp_grounding.tfsource.merge')` raises. The described behaviour lives in **top-level** `gcp_grounding/merge.py` — "FRAGMENT ASSEMBLY, per source" (`merge.py:33`), `_fragment_priority` (`merge.py:405`) and the priority-then-address sort at `merge.py:692-694`. | `:mod:\`gcp_grounding.merge\`` in all five places. |
| D6 | misdocumented | 12 docstring line anchors (table below) | Each `<file>.py:<lo>-<hi>` anchor claims to point at a named function/class/field. | 12 of the 16 anchors in the package point at unrelated code — see the table under *Line-anchor detail*. Example: `sec_artifact.py:446` says "mirroring `:meth:`GcpSnapshot.load`` (``knowledge.py:139-142``)", but `knowledge.py:139-142` is blank lines plus the head of `_str_tuple`; `GcpSnapshot.load` is at `knowledge.py:511`. | Re-point each anchor, or replace the `file:line` form with the symbol name alone (which never drifts). |
| D7 | misdocumented | `gcp_grounding/compare.py:7` | "…and **eighteen** category specs plus every key form plus the whole comparison algebra in one diff…" | `len(gcp_grounding.identity.SPECS) == 19`, matching the 19 `GcpSnapshot` categories (`captured_at` excluded). `knowledge.py:79-81` states the correct partition: "Nineteen in total: five pre-existing vocabularies, six flat vocabularies, eight record tables". | s/eighteen/nineteen/. |
| D8 | misdocumented | `gcp_grounding/registry.py:1` | "The single extension seam for **the twelve** later grounding-domain modules." | `len(registry.PROVIDER_MODULES) == 16` (`fw_claims`, `fw_checks`, `fw_estate`, `hfw_claims`, `hfw_checks`, `armor_claims`, `armor_checks`, `vpcsc_claims`, `vpcsc_checks`, `iam_deny`, `iam_checks`, `iam_scope`, `iam_deny_checks`, `org_checks`, `org_effective`, `tf_schema_checks`). | s/twelve/sixteen/, or drop the number ("for the later grounding-domain modules"). |
| D9 | misdocumented | `gcp_grounding/cli.py:150`, `:1168` | "…and NEVER from ``sources.SourceOptions.from_env``: ``from_env`` resolves the environment and explicit overrides only…" | `hasattr(sources.SourceOptions, 'from_env')` → `False`. The callable is module-level `sources.from_env` (in `sources.__all__`-adjacent module namespace). The *behavioural* claim about `from_env` is correct; only the attribute path is wrong. | ``sources.from_env``. |
| D10 | misdocumented | `gcp_grounding/preflight.py:477`, `gcp_grounding/engine.py:609`, `:724` | `:data:\`~gcp_grounding.registry.PAIR_CHECKS\`` / "``registry.PAIR_CHECKS`` is keyed by DOCUMENT KIND". | `hasattr(registry, 'PAIR_CHECKS')` → `False`; registry's upper-case names are `DRIFT_POLICY_ENV`, `ESTATE_INCOMPLETE`, `NOT_DECIDED`, `PROVIDER_MODULES`. `PAIR_CHECKS` is a **provider-module** table (`fw_checks.py:404`, exported at `fw_checks.py:69`; `iam_deny_checks.py:100`) that registry reads through `registry.pair_check()` (`registry.py:201-204`, `getattr(module, "PAIR_CHECKS", None)`). `registry.py:20` documents it correctly as a provider table. | `:data:\`~gcp_grounding.fw_checks.PAIR_CHECKS\`` or "the providers' ``PAIR_CHECKS`` tables, read via :func:`registry.pair_check`". |
| D11 | cosmetic | `gcp_grounding/estate.py:17` | "…so ``knowledge.network_tag_exists`` answers ``True`` or UNKNOWN and never ``False``." | `hasattr(knowledge, 'network_tag_exists')` → `False`; it is a **method**: `hasattr(knowledge.GcpSnapshot, 'network_tag_exists')` → `True`. The behavioural claim is untested here but the name path is wrong. | ``knowledge.GcpSnapshot.network_tag_exists``. |
| D12 | cosmetic | 11 sites (list below) | A Sphinx role target broken across a source line, e.g. `gate.py:427` `:meth:\`PolicyGroundingGate.\n        _ground_with_state\``. | The target as written contains a newline plus indentation, so it cannot resolve as a reference; every one of the 11 **does** resolve after whitespace normalisation, so no name is wrong — only the spelling. Full list under *Wrapped cross-references*. | Keep each role target on one line (wrap before the role, not inside it). |
| D13 | note | `gcp_grounding/baseline.py:774` | "category → (projector, document kind). **The five categories** with no entry have no document form: a flat vocabulary has names and not records, and ``roles`` and ``resource_hierarchy`` are compared field-wise…" | No category set in the tree yields five. `len(baseline._PROJECTIONS) == 6`; of the 8 record tables (`facts.TABLE_CATEGORIES`) exactly **2** lack an entry — `roles` and `resource_hierarchy`, the two the same sentence names. Against all 19 snapshot categories, **13** lack one; against `facts.TF_CATEGORIES` (14), **8** do. | Either "the two record categories with no entry" (matching the sentence's own examples) or drop the count. |
| D14 | note | `sec_requirements/README.md:5`, `:128` | "the parser (`sx-sec-parse`) implements exactly what is written here"; "The domain layer (`sx-sec-domains`)…" | `sx-sec-parse` / `sx-sec-domains` are design task ids, not artifacts: no file, module or entry point carries either name, and `designs/` is not in the tree. The real modules are `gcp_grounding/sec_parse.py` and `gcp_grounding/sec_domains.py`. (`sx-detect-kind` is used the same way at `gcp_grounding/iam_deny.py:6` and in several tests, so this is a house convention — but in a user-facing authoring guide it names nothing the reader can open.) | Name the modules in the authoring guide; keep task ids to internal docstrings. |
| D15 | note | `README.md:2895`, `sec_requirements/README.md:13-14` | "commit the artifacts it writes to `sec_requirements/compiled/`" / "a reviewable, git-committed artifact at `sec_requirements/compiled/<doc-slug>.promises.json`". | `sec_requirements/` contains only `README.md` and `TEMPLATE.md`; `sec_requirements/compiled/` does not exist and no `*.promises.json` is committed anywhere in the repo. This is *self-consistent* — `sec_requirements/README.md:18-19` says the directory is written by stage 1, and `TEMPLATE.md` is skipped by `sec_parse.discover` — but a reader following `gcp-ground compile-requirements` with the default `DIR=sec_requirements` compiles **zero** documents. | State in `sec_requirements/README.md` that the shipped directory holds the template only, and that the demo corpora live under `tests/fixtures/gcp/sec_requirements/` and `examples/*/`. |

### Line-anchor detail (D6)

All 16 `<file>.py:<line>` anchors inside package docstrings, resolved:

| docstring site | anchor | names | actually at | verdict |
| --- | --- | --- | --- | --- |
| `sec_artifact.py:20` | `knowledge.py:151-155` | `GcpSnapshot.from_dict` | `knowledge.py:528` (151-155 is inside `_str_tuple`) | drifted |
| `sec_artifact.py:446` | `knowledge.py:139-142` | `GcpSnapshot.load` | `knowledge.py:511` (139-142 is blank + `_str_tuple` head) | drifted |
| `sec_ast.py:13` | `fetch.py:344-349` | `fetch.write_snapshot` | `fetch.py:1139` (344-349 is the `constraintDefault` debug branch) | drifted |
| `sec_ast.py:542` | `fetch.py:344-349` | `fetch.write_snapshot` | as above | drifted |
| `sec_domains.py:83` | `constraints.py:442-446` | `constraints.check_policy_subset` | `constraints.py:463` (442-446 is the tail of `_grant_pairs`) | drifted |
| `sec_encode.py:4` | `constraints.py:129-269` | `constraints._CelToZ3` | class opens at `constraints.py:150`; 129-148 is `_tokenize` | drifted (start) |
| `sec_encode.py:9` | `constraints.py:54-57` | `_z3_module` | `constraints.py:67` (54-57 is the import block) | drifted or ambiguous |
| `sec_encode.py:10` | `core/solver.py:105` | `get_solver` | `core/solver.py:105` | **accurate** |
| `sec_encode.py:51` | `constraints.py:139-140` | `z3.Real("request.time")`, `z3.String("resource.name")` | `constraints.py:160-161` | drifted |
| `sec_encode.py:84` | `constraints.py:303-310` | `check_cel` | `constraints.py:305` | **accurate** |
| `sec_evidence.py:5` | `core/report.py:22-29` | the `Verdict` fields, "no evidence field" | `core/report.py:22-29` exactly | **accurate** |
| `sec_evidence.py:21` | `core/__init__.py:5-7` | the re-vendor sentence, quoted | `core/__init__.py:5-7`, verbatim | **accurate** |
| `sec_evidence.py:203` | `report.py:91-112` | "the base document … untouched" (i.e. `to_dict`) | `PolicyReport.to_dict` is `report.py:119`; 91-112 is `source`/`__post_init__`/`ok`/`summary`/`render` | drifted |
| `sec_probes.py:24` | `constraints.py:272-281` | `constraints._decide` | `constraints.py:293` (272-281 is `_CelToZ3._match`/`_expect`) | drifted |
| `sec_probes.py:38` | `constraints.py:318-321` | "``check_cel`` only WARNS on a tautology" | the tautology warning is `constraints.py:341`; 318-321 is the `UnsupportedCel` handler | drifted |
| `sec_vocab.py:28` | `reasoner.py:114-115` | "the ``captured`` guard" | 114-115 is prose inside `_enumerated`'s docstring; the guard returns begin at `reasoner.py:119` | drifted |

### Wrapped cross-references (D12)

```
gcp_grounding/cli.py:2964              :func:`gcp_grounding.gate. terraform_route`
gcp_grounding/cli.py:3974              :data:`gcp_grounding.sec_domains. PROTOCOL_NUMBERS`
gcp_grounding/drift.py:239             :class:` ~gcp_grounding.provenance.SourceLedger`
gcp_grounding/drift.py:547             :class:` ~gcp_grounding.reconciled.ReconciledSnapshot`
gcp_grounding/gate.py:427              :meth:`PolicyGroundingGate. _ground_with_state`
gcp_grounding/iam_scope.py:24          :data:`gcp_grounding.iam_checks .ESCALATION_PERMISSIONS`
gcp_grounding/provider_schema.py:64    :data:`gcp_grounding.freshness .MAX_AGE_DEFAULT`
gcp_grounding/reconciled.py:4          :class:`~gcp_grounding.provenance .SourceLedger`
gcp_grounding/registry.py:581          :func:`~gcp_grounding.provenance .require_complete`
gcp_grounding/sec_domains.py:41        :class:`~gcp_grounding.sec_encode. UnsupportedTerm`
gcp_grounding/sources.py:38            :meth:`SourceOptions .configured`
```

All eleven targets exist once the newline is removed (each was re-resolved individually).

### Nothing hallucinated in the user-facing docs

Every function, module, class, flag, environment variable, config key, collection,
field, verdict kind, check family and exit code that `README.md`, `simple_readme.md`,
`sec_requirements/README.md` or any `--help` text names **exists**. The two
hallucinated names (D4, D5) are both internal docstring cross-references.

---

## Verified true

Claims checked that **held**, with the evidence. (`$P` below is
`/home/jones/Downloads/gcp-policy-grounding/.venv/bin/python`, run from the worktree root.)

### The collection / sort registry (`README.md:358-407`)

* **All 15 rows of the collection table are exact** — name, tier and every field name
  and sort. `$P -c` over `sec_ast.COLLECTIONS` after `sec_domains.register()` returns
  exactly the 15 the README tabulates, with `iam_bindings`/`new_iam_bindings`/
  `old_iam_bindings` sharing the same four fields, `firewall_rules` and
  `proposed_firewall_rules` sharing the same fourteen, and `deny_rules` carrying
  exactly `policy:Str, rule_index:Int, denied_principal:Str, permission:Str,
  has_principal_exceptions:Bool, has_condition:Bool, condition:Str`.
* **"the four base collections … plus the eleven the domain layer registers"**
  (`README.md:364-365`) — `sorted(sec_ast.COLLECTIONS)` before `register()` is exactly
  `['iam_bindings', 'new_iam_bindings', 'old_iam_bindings', 'org_policy_rules']`;
  after, 15.
* **"The sorts are a closed set — `Bool`, `Str`, `Int`, `Ip4`, `Cidr`, `Port`, `Proto`,
  `Real`"** and **"fixed-width bitvectors (32, 32, 16 and 8 bits)"** (`README.md:386-390`)
  — `sec_ast.SORTS == ('Bool','Str','Int','Ip4','Cidr','Port','Proto','Real')`,
  `sec_ast.BV_WIDTHS == {'Ip4': 32, 'Cidr': 32, 'Port': 16, 'Proto': 8}`.
* **The tiers** (`README.md:396-400`) — `sec_ast.TIERS == ('proposal','pair','estate')`.
* **"every domain can carry compiled promises … (`iam`, `vpc_firewall`, `hier_firewall`,
  `cloud_armor`, `org_policy`, `vpc_sc`)"** (`README.md:88-89`) —
  `sec_artifact.DOMAINS == ('iam','vpc_firewall','cloud_armor','org_policy','hier_firewall','vpc_sc')`.

### The worked IAM encoding, reproduced end to end (`README.md:409-562`)

Every artifact in this section was regenerated and diffed.

* **The compile output** (`README.md:490-495`). Command:
  `$P -m gcp_grounding compile-requirements examples/walkthrough --snapshot tests/fixtures/gcp/agentic_snapshot.json --out <scratch>/compiled-walkthrough` → `EXIT=0`.
  Output is **byte-identical** to the README's three lines, including
  `grounded=3 ungrounded=0 contradicted=0 unverified=0` and
  `examples/walkthrough/requirements.md:25`.
* **`show_promises.py`** (`README.md:503-513`). `$P show_promises.py <scratch>/compiled-walkthrough`
  → **byte-identical**, including the artifact digest prefix `sha256 8c45d6883945…`,
  `snapshot 2026-07-25T08:00:00Z`, `encoder gcp-sec-encode/1`, the header
  `✓ ENFORCED  [iam/proposal/refute/high]  owner-stays-inside-acme`, the canonical
  s-expression, and both pinned witnesses (`b.member='C', b.role=''` /
  `b.member='A', b.role='roles/owner'`).
* **The three rows** (`README.md:440-442`). `sec_rules.iam_bindings` over a
  `RuleContext(document=json.load(open('examples/walkthrough/policy.json')), document_kind='iam_policy')`
  returns exactly three records with `missing_reason=None`, in the README's order:
  `[0]` `roles/bigquery.dataViewer`→`group:data-eng@acme.example`,
  `[1]` `roles/owner`→`user:alice@acme.example`,
  `[2]` `roles/owner`→`user:mallory@outsider.example`, each with `condition=''` and
  `has_condition=False`.
* **"sorts them by `(role, member)`"** (`README.md:435-437`) — `sec_rules._iam_records`
  ends `records.sort(key=lambda r: (r["role"], r["member"]))` (`sec_rules.py:734`).
* **The extractor's refusal rule** (`README.md:448-454`) — `sec_rules._iam_records`
  (`sec_rules.py:688-735`) returns `((), reason)` naming the offending binding for a
  non-mapping binding, a missing/non-string `role`, a non-list `members`, and **any**
  key outside `role`/`members`/`condition` (the message literally ends
  "— the member-vs-members typo guard").
* **The ground formula** (`README.md:532-538`) — `sec_encode.ground(z3, promise.ast,
  {'iam_bindings': <the three rows>})` produces the same `Or` of three `And`s, in the
  same row order and with the same conjunct order (`Not(SuffixOf(...))` then the role
  equality). The README renders it in SMT-LIB (`str.suffixof`), which is also how the
  `--explain` solver census prints it: `[sec:iam] owner-stays-inside-acme (refute over
  iam_bindings): (let ((a!1 (or (and (not (str.suffixof "@acme.example" "group:data-eng@acme.example")) …`.
* **"The `or` is therefore true"** (`README.md:553`) — `z3.simplify(formula)` → `True`.
* **"`mode: refute` means the obligation … is `Not(formula)` — one line,
  `sec_probes.obligation`, and the only place polarity is ever applied"**
  (`README.md:555-557`) — `sec_probes.obligation` (`sec_probes.py:84-104`) is
  `formula` for `assert_satisfiable` and `z3.Not(formula)` for `refute`, and nothing
  else; `z3.Solver().add(obligation).check()` → `unsat`, i.e. the obligation does not
  hold, as `README.md:557-558` states.

### The walkthrough run (`README.md:816-970`)

Command (README's, with `--requirements` pointed at the scratch compile):

```
$P -m gcp_grounding verify-policy \
    --proposal examples/walkthrough/proposal.tf.json \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json \
    --terraform-state examples/walkthrough/terraform.tfstate \
    --requirements <scratch>/compiled-walkthrough --explain      → EXIT=1
```

* **The recap** (`README.md:898-901`) reproduced verbatim:
  `⚠ [sec:iam] owner-stays-inside-acme: refuted by iam_bindings[1] (google_project_iam_binding.contractor_owner) member='user:mallory@outsider.example' role='roles/owner'`.
* **The whole summary block** (`README.md:904-922`) reproduced line for line — the
  `terraform state on disk`/`promises in force`/`provider`/`proposed change`/`result`
  rows, the `[cli]` layer labels, `a terraform configuration (2 resources): 2
  google_project_iam_binding`, both English change sentences, and the repeated
  violated-promise sentence under `result`.
* **"five green existence verdicts, the resource type counted once per block"**
  (`README.md:946-948`) — the report header reads `grounded=5` and the five are
  `[resource_type]` ×2 (one per block), `[role]` ×2, `[principal]` ×1.
* **"`user:mallory@outsider.example` … abstains rather than blocking, and says why:
  this fixture snapshot is older than the seven-day freshness ceiling, so its
  `principals` table is demoted to `uncaptured`"** (`README.md:950-954`) — the run emits
  `? [principal] … [not decided: 'principals' has uncaptured coverage …]` plus
  `? [staleness] source … captured at '2026-07-25T08:00:00Z', 62 days before now, which
  is past the 7 days freshness limit - every category it supplies is demoted to
  'uncaptured'`, and the `--state-explain` coverage table shows
  `principals  uncaptured  12  0  -  taint=stale`.
* **Exit 1 on one contradicted verdict** (`README.md:962`) — `EXIT=1`,
  `contradicted=1`.

### The settings / provenance surface (`README.md:1028-1310`)

* **Config schema and keys** (`README.md:1033-1048`) — `discovery.CONFIG_SCHEMA ==
  "gcp-grounding-config/1"`; `discovery.CONFIG_KEYS` is exactly
  `{snapshot, precedence, max_age, drift, targets, requirements, provider_schema, schema_policy}`
  and `discovery.TERRAFORM_KEYS` exactly `{state, plan, config_dir}` — every key the
  README's example file uses, and no key it uses is absent.
* **"stopping at the `.git` that contains it"** (`README.md:1053-1054`) —
  `discovery.REPO_MARKER == ".git"`.
* **"refuses the `terraform.tfstate` under a `.terraform/` directory"**
  (`README.md:1113-1114`) — `discovery.BACKEND_DIR == ".terraform"`,
  `discovery.STATE_NAME == "terraform.tfstate"`.
* **The layer order and labels** (`README.md:1086-1090`, `:239-241`) —
  `discovery.ORIGIN_LABELS == ('cli','env','config','auto','default')`, exactly the five
  the README prints as `[cli]`, `[env]`, `[config <path>]`, `[auto]`, `[default]`.
* **"There is deliberately no config-file key and no environment variable for
  `--completeness`"** (`README.md:1154-1156`) — `completeness` is absent from
  `discovery.CONFIG_KEYS` and no `GCP_GROUNDING_COMPLETENESS` exists anywhere in the
  package (17 `GCP_GROUNDING_*` names grepped).
* **"12 settings at defaults: origins, extra, terraform_plan, terraform_dir,
  precedence, drift_policy, completeness, now, provider_schema, schema_policy, targets,
  requirements"** (`README.md:1258-1260`) — `len(discovery.SETTINGS_FIELDS) == 15`, and
  the 12 named are exactly `SETTINGS_FIELDS` minus the three the example sets
  (`primary`, `terraform_state`, `max_age`). The live walkthrough run prints the same
  shape with its own three set.
* **"`[explicit-flag]`, `[config-map]`, `[tf-address]` and `[tf-attributes]` are the
  *how*"** (`README.md:1274`) — all four are in
  `baseline.HOWS == ('explicit-flag','config-map','tool-input','document-name','tf-address','tf-attributes')`;
  `discovery.TARGET_HOW == "config-map"`. The live run printed `[tf-attributes] resolved`.
* **The `--state-explain` block shape** (`README.md:1240-1265`) — the live run emits the
  same header (`state used this run: 2 source(s), 1 target(s), 0 conflicting`), the same
  `sources:` / `coverage:` / `settings:` / `targets:` / `drift:` sections, the same
  coverage columns (`category scope keys dropped reasons`), the same terraform note
  ("a terraform artifact covers only the resources terraform manages, so this scope is
  capped at 'partial' by construction - it is not a capture bug") and the same closing
  `drift: none - no source disagreed about a row that was looked up`.
* **The `[subset]` partial-view message** (`README.md:1186-1191`) — reproduced almost
  verbatim by the live run, including "…whose coverage of this domain is 'partial', and
  a check that reasons from what the baseline does NOT contain cannot tell a real
  widening from a row that view never saw".
* **`baseline:new` / `baseline:unqueried`** (`README.md:1213-1219`) —
  `baseline.STATUS_KINDS` maps `absent → 'baseline:new'` and
  `unqueried → 'baseline:unqueried'`.

### The CLI surface

* **Four subcommands, all as documented.** `gcp-ground --help` lists exactly
  `verify-policy`, `capture-terraform`, `scan-command`, `compile-requirements`, and the
  entry point is `gcp_grounding.cli:main` (`pyproject.toml:19`, and `cli.main` exists
  with signature `(argv: list[str] | None = None) -> int`).
* **Every flag the docs name exists.** Diffing the three docs against all five parsers:
  the only `--…` tokens in the docs that no subcommand defines are `--list` (that is
  `run_demo.sh --list`) and `--member` / `--role` (inside the quoted `gcloud` command in
  demo step 5). 49 flags are defined in total; 30 of them are named somewhere in the
  docs, and none named is missing.
* **Every environment variable the docs name exists.** The docs name 12
  (`GCP_GROUNDING_{SNAPSHOT,PROVIDER_SCHEMA,TF_STATE,TF_PLAN,TF_DIR,PRECEDENCE,MAX_AGE,DRIFT_POLICY,CONFIG,REQUIREMENTS,SCHEMA_POLICY,NOW}`);
  all 12 are read by the package. Five more exist and are not documented in prose but
  **are** documented in `--help` (`GCP_GROUNDING_ORIGINS`, `GCP_GROUNDING_MERGE_SOURCES`,
  `GCP_GROUNDING_BASH_POLICY`, `GCP_GROUNDING_ABSTAIN_NOTES`) or are internal
  (`GCP_GROUNDING_REDACT_SALT`).
* **The `--target` domain list** in `verify-policy --help` is exactly the 19
  `GcpSnapshot` categories (`roles` … `iam_deny_policies`).
* **`--precedence` modes** `api-wins` / `terraform-wins` / `highest-fidelity-wins` /
  `require-agreement` (`README.md:1042`, `:1067`) — all four are documented and
  implemented in `merge.py:143-147`; the default is `highest-fidelity-wins`.
* **`--drift-policy {annotate,block,abstain}`, default `annotate`**
  (`README.md:1044`, `:1069`, `:1082`) — `drift.DRIFT_POLICIES == ('annotate','block','abstain')`,
  `drift.DEFAULT_DRIFT_POLICY == 'annotate'`.
* **`--max-age` default 7 days** (`README.md:1448`, `:1529`) —
  `freshness.MAX_AGE_DEFAULT == timedelta(days=7)`; the live abstention says
  "past the 7 days freshness limit".

### Verdict kinds and check families

Every bracketed family the docs print resolves to a `Verdict(kind=…)` the package
actually emits (AST-extracted from every `Verdict(...)` call site):

| documented | resolves to |
| --- | --- |
| `[firewall_exposure]`, `[firewall_pair]` | `fw_checks._EXPOSURE`, `fw_checks._PAIR` |
| `[firewall_shadow]`, `[firewall_reopen]` | `fw_estate._SHADOW`, `fw_estate._REOPEN` |
| `[iam_escalation]`, `[iam_public]` | literals in `iam_checks.py:293`, `:216` |
| `[iam_scope_diff]` | `iam_scope.KIND` (`iam_scope.py:72`) |
| `[iam_deny_shadow]` | `iam_deny_checks.KIND` |
| `[org_effective]` | `org_effective.VERDICT_KIND` |
| `[tf_attribute]`, `[tf_block]`, `[tf_resource_type]`, `[tf_schema]` | `tf_schema_checks.KIND_ATTRIBUTE` / `KIND_BLOCK` / `KIND_RESOURCE_TYPE` / `KIND_NOTE` |
| `[sec:compile]` | `engine.RULES_KIND` (and the literal in `cli.py:2853`) |
| `[sec:iam]`, `[sec:vpc_firewall]`, `[sec:org_policy]` | `f'sec:{promise.domain}'` over `sec_artifact.DOMAINS` |
| `[subset]`, `[document]`, `[provenance]`, `[staleness]` | literals in `preflight`/`cli`/`freshness` |
| `[baseline:new]`, `[baseline:unqueried]` | `baseline.STATUS_KINDS` |
| `[estate:incomplete]` | `iam_deny_checks.ESTATE_INCOMPLETE` |
| `[role]`, `[principal]`, `[constraint]`, `[resource_type]`, `[network]` | claim kinds in `reasoner.EXISTENCE_KINDS` |
| `[bash-mutation]` | `bash_mutation.py:174` |

The four buckets (`README.md:18-26`, `sec_requirements/README.md:23-24`) are exactly
`core.report.STATUSES == ('grounded','ungrounded','contradicted','unverified')`.

### The requirement authoring format (`sec_requirements/README.md`)

* **Discovery skips** (`:34-36`) — `sec_parse.discover` skips names starting with `.`
  or `_` and the exact names `README.md` / `TEMPLATE.md`, and returns `()` for a missing
  directory (`sec_parse.py:86-104`).
* **Frontmatter keys `domain`, `state`, `mode`, `severity`** (`:43`) —
  `sec_parse._FRONTMATTER_KEYS == ("domain","state","mode","severity")`, and an
  unrecognized key becomes a problem, not a silent default (`sec_parse.py:163-166`).
* **`id:` matches `^[a-z0-9][a-z0-9-]*$`** (`:67`, and `README.md:670`, `:768`, `:2259`)
  — `sec_artifact._ID_RE` is exactly that regex.
* **`mode:` is `assert_satisfiable` | `refute`** (`:68-71`) — `sec_artifact.MODES`.
* **`domain:` is one of the six** (`:72-73`) — `sec_artifact.DOMAINS`, same order.
* **`state:` is `proposal` | `pair` | `estate`** (`:74`) — `sec_ast.TIERS`.
* **`vocab: <kind> <value>` with kind in `role`, `permission`, `principal`,
  `constraint`, `resource_type_ref`** (`:76-79`) —
  `sec_artifact.VOCAB_KINDS == ("role","permission","principal","constraint","resource_type_ref")`,
  and `sec_artifact.py:272-274` rejects anything outside it at load.
* **The whole term language** (`:93-115`) — every keyword listed is implemented in
  `sec_parse._make_node` / `_parse_term` / `_parse_set`, with the documented arities:
  `true`/`false` (0 children), `not` (1), `and`/`or` (≥1), `implies` (2),
  `atmost`/`atleast <int>` (≥1), `forall`/`exists <var> in <collection>` (1),
  and the leaf predicates `in … set[…]`, `cmp <eq|ne|lt|le|gt|ge>`, `prefix`/`suffix`/
  `contains`, `cidr_contains`, `port_in <lo> <hi>`, `cel "…"`; terms `field <var>.<name>`,
  `str`, `int`, `bool`, `ip4`, `cidr`, `port`. `_CMP_OPS` is exactly the six listed, and
  an unknown keyword raises `unknown smt keyword` (`sec_parse.py:434`).
* **"tabs are rejected"** and **"two spaces per nesting level"** (`:81-83`) — enforced in
  `sec_parse._build_smt` / `_build_node`.
* **The artifact is `<doc-slug>.promises.json`** (`:13-14`) — the walkthrough compile
  wrote `requirements.promises.json` from `requirements.md`.
* **Schema tag** — `sec_artifact.SEC_SCHEMA == "gcp-sec-promises/1"`, and a load rejects
  any other value; `README.md:504`'s `encoder gcp-sec-encode/1` is the artifact's own
  encoder stamp.

### The compiler's three rejections (`README.md:727-741`, `:1466-1484`)

Command: `$P -m gcp_grounding compile-requirements tests/fixtures/gcp/sec_requirements
--snapshot tests/fixtures/gcp/agentic_snapshot.json --out <scratch>/compiled` → `EXIT=1`,
as `README.md:1669` documents ("EXPECTED TO EXIT 1").

* **Ungrounded vocabulary** — `✗ [role] requirement:bigquery-reader-only#vocabulary[0]:
  role 'roles/bigquery.reader' does not exist in the snapshot … (did you mean:
  roles/bigquery.admin, roles/bigquery.jobUser, roles/bigquery.dataEditor?)` and
  `⚠ [sec:compile] … — vocabulary is not grounded: roles/bigquery.reader does not exist
  in the snapshot`. This is verbatim the reason `README.md:1680-1681` quotes, and the
  did-you-mean is indeed compile-time output, exactly as `README.md:1681-1682` says.
* **The untranslated sentence stays `unverified`, not dropped**
  (`README.md:201-202`, `sec_requirements/README.md:58-60`) —
  `? [sec:compile] …agentic_promises.md:121: 'Changes must be reviewed by the security
  team before merge.' — no promise block — the sentence was not translated`.
* **"six plain-English promises"** (`README.md:1665`) and **"6 enforcing, 2 not"**
  (`README.md:177`) — the corpus compiles 6 enforced promises
  (`impersonation-sre-only`, `no-open-ssh-rdp-ingress`, `no-primitive-roles-outside-domain`,
  `no-public-principals`, `perimeter-restricts-storage`, `sa-key-creation-disabled`)
  plus one rejected and one untranslated; the hook run reports
  "2 of 8 compiled requirement(s) are not enforcing".

### Exit codes and headline claims

| claim | command | observed |
| --- | --- | --- |
| hook attack "exits 2 (the blocking code) with findings on stderr" (`README.md:1710`) | `verify-policy --hook` on `tests/fixtures/gcp/agentic/iam/A10_owner_to_external.policy.json` with `GCP_GROUNDING_SNAPSHOT` + `GCP_GROUNDING_REQUIREMENTS` | `EXIT=2`, **0 bytes** stdout, 2 132 bytes stderr |
| hook benign "exits 0 in byte-for-byte silence" (`README.md:1711`) | same, on `tests/fixtures/gcp/agentic/benign/iam_policy_conditional.json` | `EXIT=0`, **0 bytes** stdout, **0 bytes** stderr |
| `scan-command` "always exit 0" and headlines `PASSED — NOTHING VERIFIED (1 unchecked)` (`--help`, `README.md:1699-1703`) | `scan-command --command 'gcloud projects add-iam-policy-binding …'` | `EXIT=0`; banner "scan-command classifies shell commands … it VERIFIES NOTHING"; headline `PASSED — NOTHING VERIFIED (1 unchecked) [none]  grounded=0 ungrounded=0 contradicted=0 unverified=1`; one `? [bash-mutation]` |
| `.tf.json` with `--snapshot` alone: `? [document] … nothing was checked`, headline `PASSED — NOTHING VERIFIED`, exit 0 (`README.md:1563-1566`) | `verify-policy examples/walkthrough/proposal.tf.json --snapshot … --no-config` | `EXIT=0`; `PASSED — NOTHING VERIFIED (2 unchecked)`; `? [document] …: document kind was not recognized (top-level keys ['resource']) — nothing was checked` |
| `--schema-policy annotate` demotes the identical finding to a warning at exit 0 (`README.md:1440-1445`, `:1650-1652`) | scenario 4a with `--schema-policy annotate` | `EXIT=0`, `PASSED (8 unchecked)`, the one `[tf_attribute]` line still present |
| adding `--provider-schema` to scenario 1 gains "zero schema noise — its verdict counts are byte-identical with and without the schema" (`README.md:1652-1654`) | scenario 1 run twice, with and without `--provider-schema examples/terraform-schema/provider-schema.json` | both `EXIT=1`, both `grounded=18 ungrounded=0 contradicted=3 unverified=27`; `diff` of the two full stdout reports → **empty** (stronger than the claim) |
| compile exits 1 on a rejected promise (`README.md:1669-1671`) | step 1 above | `EXIT=1`, artifacts still written |
| compile of a clean corpus exits 0 (`README.md:487`) | walkthrough compile | `EXIT=0` |
| `pytest -q tests/ -k gcp` (`README.md:1604`) | `--collect-only` | 4 478 tests collected — the same count as the unfiltered suite, so the documented dev command runs everything |

### Layout, paths and anchors

* **Every repo-relative path the three docs name exists.** 118 distinct paths extracted;
  the only directory-qualified miss is `sec_requirements/compiled` (see D15). The
  illustrative operator paths (`estate/…`, `infra/prod/…`, `policies/…`, `demo/…`) are
  outputs of the commands beside them, not committed files.
* **The Layout section** (`README.md:1576-1597`) — `gcp_grounding/core/` holds exactly
  the vendored Datalog engine, solver detection and report model (`datalog.py`,
  `solver.py`, `report.py`, `log.py`); all fifteen current-state modules it names
  (`facts.py`, `identity.py`, `redact.py`, `provenance.py`, `compare.py`, `merge.py`,
  `drift.py`, `estate.py`, `reconciled.py`, `sources.py`, `freshness.py`,
  `discovery.py`, `baseline.py`, `engine.py`, `explain_state.py`) exist, as does
  `gcp_grounding/tfsource/` with the terraform readers and mappers.
* **All 34 intra-page anchors in `README.md` resolve** to its own headings under
  GitHub's slug rules (the two with a doubled hyphen come from an em dash and are
  correct as written).
* `show_promises.py`, `run_demo.sh`, `sec_requirements/TEMPLATE.md` and
  `tests/mutation_entries.py` all exist; `run_demo.sh` does read `README.md` for
  `--list` (`run_demo.sh:5`, `:28`).

### Named machinery in the "adopt a policy type" and instruction blocks

Every symbol `README.md:592-685` and the two LLM instruction blocks name resolves:

`sec_domains._DENY_RULE_FIELDS`, `sec_domains.COLLECTION_SPECS` (11 specs),
`sec_domains._firewall_records`, `sec_domains._guarded`, `sec_domains._Undecidable`,
`sec_domains.register`, `sec_ast.register_collection`, `sec_ast.CollectionSpec`,
`sec_rules.register_extractor`, `sec_rules.RuleContext`,
`sec_rules.WITNESS_ADDRESS_FIELD` (`== 'address'`), `sec_rules._normalize_extraction`,
`sec_rules.iam_bindings`, `sec_probes.obligation`, `evidence.NotEvaluated`,
`evidence.observed_empty`, `evidence.rows`, `evidence.scalar`, `evidence.examined`,
`sources.load_source`, `reasoner.ground_existence`, `knowledge.GcpSnapshot`,
`registry.PROVIDER_MODULES`, `org_effective.VERDICT_KIND`, `fetch.capture_snapshot`,
`fetch.default_client`.

* **"`sec_domains.register()` … is today the only caller of either registrar in the
  tree"** (`README.md:613-615`) — `register_collection` and `register_extractor` are
  called only from `sec_domains.register()` (plus `sec_ast._ensure_domains`, which calls
  `register()` itself).
* **The evidence floor** (`README.md:574-580`) — `sec_rules._normalize_extraction`
  (`sec_rules.py:662-685`) synthesizes a `missing_reason` for an extractor that returns
  zero records with neither reason set, exactly as described.
* **`examples/terraform-roles/requirements.md`** (`README.md:617-620`) holds one promise
  over `proposed_role_permissions`, and `examples/terraform-roles/proposal_b.tf.json`
  exists as its violating document.

### The provider-schema section (`README.md:1380-1464`)

* **`gcp-provider-schema/1` wrapper** — `provider_schema.WRAPPER_SCHEMA ==
  "gcp-provider-schema/1"`, and `provider_schema._WRAPPER_KEYS == ("schema",
  "captured_at", "provider_versions", "raw")` — exactly the keys
  `README.md:1414-1425` documents, with the wrapper parsed strictly and the raw
  terraform shape read tolerantly (`provider_schema.py:214`, `:238-244`).
* **Three layers** — `--provider-schema` (repeatable), `GCP_GROUNDING_PROVIDER_SCHEMA`
  (`:`-separated), and the `provider_schema` config key: all three exist.
* **`--schema-policy {block,annotate,off}` default `block`** — confirmed in `--help` and
  by the annotate probe above.
* **The four verdict families it yields** (`README.md:1407`) — `tf_attribute`,
  `tf_block`, `tf_resource_type` (plus `tf_schema` for the configured-but-absent
  abstention) all exist as `tf_schema_checks` constants.

### Capture, fetch and the "no network" claims

* **"There is no network code anywhere in the gate itself; capture is one read-only
  script driven by `gcp_grounding.fetch`"** (`README.md:1502-1503`) — `fetch.py` makes no
  HTTP call of its own; it asks the caller for `googleapiclient` discovery Resources
  and, when asked for a default client, reports
  `pip install google-api-python-client` (`fetch.py:145-150`), matching
  `README.md:1508`. The only URL in the file is the `_COMPUTE_LINK_PREFIX` string
  constant used to strip self-links.
* **Every `fetch.capture_snapshot` keyword the README's recipe passes exists**
  (`README.md:1514-1524`): `iam`, `custom_role_parents`, `orgpolicy`,
  `orgpolicy_parent`, `asset`, `asset_scope`, `capture_iam_bindings`, `out_path`.
* **"the `iam_deny_policies` estate table has no fetch path yet"** (`README.md:110-113`)
  — the string `iam_deny_policies` does not occur anywhere in `fetch.py`; it is listed in
  `facts.EXCLUDED_CATEGORIES` with that reasoning spelled out.
* **"the `resource_types` category holds terraform provider type names … never CAI asset
  types"** (`README.md:1531-1535`) — `resource_type_ref` is in
  `reasoner.EXISTENCE_KINDS` and the walkthrough's green
  `[resource_type] … 'google_project_iam_binding' exists in the snapshot` verdicts
  confirm the namespace.
* **`capture-terraform` exit codes** (`--help`) — 0 on a written snapshot even when
  partial, 1 when nothing could be captured, 2 for usage errors only; and
  `--origins-out` "CANNOT be switched off", matching `README.md:1119-1133`.

### The surfaces table (`README.md:72-133`)

Every mechanism the table and the two paragraphs under it name exists:
the `deny_rules` / `deny_rule_exceptions` collections with a per-row
`has_principal_exceptions` flag; the `iam_deny_shadow` interaction check; the v1→v2
containment table restricted to `user:` / `serviceAccount:` / `group:` / `allUsers`
(`iam_deny_checks.py:51`, `:139`); `estate:incomplete` as the named abstention when
`iam_deny_policies` is uncaptured (reproduced live in the walkthrough run); the
`org_effective` fold with `effective_org_policy_bool` / `effective_org_policy_values`
and the `constraint_default` field the fetcher records (`fetch.py:340-342`, validated
in `knowledge.py:570-575`); `goto_next` (`hfw_checks`, `hfw_claims`); `ANY_IDENTITY`
(`vpcsc_claims`, `vpcsc_checks`); and the shell-command classifier reached by
`scan-command` and the hook's `--bash-policy`.

### Scenario corpora named in the demo sections

* `examples/terraform-orgpolicy/cmm_demo.md` holds **exactly eleven** promise ids, and
  they are exactly the eleven `README.md` cites. **Three are not org policies** —
  `egress-firewall-policy-high-strength-vpc-firewall` (`domain: vpc_firewall`),
  `deny-admin-roles` and `iam-deny-service-account-impersonation` (`domain: iam`) —
  exactly as `README.md:2262-2266` states ("one VPC-firewall egress control and two IAM
  controls").
* `examples/terraform-denypolicy/requirements.md` holds **three** promises with the
  modes and tiers `README.md:2571-2585` describes: `every-deny-covers-token-creation`
  (`assert_satisfiable`, iam/proposal), `no-principal-threads-the-guardrail`
  (`refute`, iam/proposal), `sa-key-creation-stays-effectively-enforced`
  (`refute`, `domain: org_policy`, `state: estate`).
* `examples/terraform-masked/requirements.md` holds the single
  `masked-allow-only-known-domains`; `examples/terraform-roles/requirements.md` holds
  the single `no-actas-in-custom-roles`, whose sentence is verbatim
  *"No role may include the permission iam.serviceAccounts.actAs."* and which quantifies
  over `proposed_role_permissions` — all as `README.md:1817-1819` and `:2261-2266` say.
  The corpus's own `note:` states the REST-abstention `README.md:1876-1879` describes.

### Docstring cross-references

**1 458** Sphinx role references across the 79 modules (907 distinct targets). After
adjudication, **1 456** name something that exists. The two that do not are D4 and D5;
eleven more (D12) name real things with an unparseable spelling; three (D9, D10, D11)
name real things at the wrong attribute path.

### Counted claims in module docstrings that held

* `knowledge.py:79-81` — "Nineteen in total: five pre-existing vocabularies, six flat
  vocabularies, eight record tables" → 19 = 5 + 6 + 8, matching `facts.FLAT_CATEGORIES`
  (6) and `knowledge._RECORD_TABLES` (8).
* `facts.py:418` — "The fourteen estate categories a terraform artifact can produce" →
  `len(facts.TF_CATEGORIES) == 14`.
* `estate.py:111-113` — "why it is exactly these four" →
  `len(estate.DEFAULT_EMIT) == 4`.
* `reasoner.py:4-8` — "the five vocabulary categories … plus the ten estate categories"
  → `len(reasoner.EXISTENCE_KINDS) == 15`, and the fifteen names listed in the docstring
  are exactly the fifteen in the tuple.
* `sec_artifact.py:59` — "The six grounding domains" → `len(DOMAINS) == 6`.
* `sec_ast.py:109` — "Seeded with exactly the four base collections" → 4.

---

## Coverage summary

| dimension | examined | findings |
| --- | --- | --- |
| collections / tiers / fields | 15 collections, 74 field-sort pairs | 0 |
| sorts, bitvector widths, tiers, modes, statuses, vocab kinds, domains, origins | 8 closed sets | 0 |
| CLI flags | 49 across 4 subcommands | 0 |
| environment variables | 17 in code, 12 named in prose | 0 |
| config keys | 8 top-level + 3 terraform | 0 |
| verdict kinds / check families | 31 bracketed families in the docs | 0 |
| exit codes | 8 documented codes probed live | 0 |
| explainer reproduction | rows, s-expression, ground formula, obligation, both run outputs | 0 |
| repo paths named by docs | 118 | 1 (D15, expected-by-design) |
| README intra-page anchors | 34 | 0 |
| docstring cross-references | 1 458 (907 distinct) | 2 hallucinated, 3 wrong-path, 11 wrapped |
| docstring line anchors | 16 | 12 drifted |
| counted claims | 12 | 4 stale (D1, D3, D7, D8) + 1 unreconcilable (D13) |

**Bottom line.** Nothing the user-facing documentation promises is fictional: every
function, module, class, flag, environment variable, config key, collection, field,
verdict kind, check family and exit code it names exists and, where probed, behaves as
described — including the whole worked IAM encoding, which reproduces byte-for-byte.
The defects are internal and clerical: two docstring cross-references naming things that
do not exist (`identity.CATEGORY_SPECS`, `gcp_grounding.tfsource.merge`), twelve
drifted `file:line` anchors, four stale counts — of which one, the "six domain
collections" claim, is visible to a requirement author in `sec_requirements/README.md`
and contradicts `README.md` on the same page-turn.
