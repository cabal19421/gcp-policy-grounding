# Audit: every demo scenario and every quoted README fragment against reality

**Task** `audit-demos-and-quotes` of `designs/gcp-codebase-audit.md`.
**Subject** gcp-policy-grounding at `main` `90248ba`.
**Date** 2026-09-25. **Read-only**: nothing outside this file was changed.

## Scope

- `run_demo.sh --list` and **every** scenario it lists (all 24, `w` included).
- Every fenced command in `README.md` (67 commands across 32 ```bash blocks)
  and in `simple_readme.md` (2 commands).
- Every quoted output fragment in both pages: the 17 fenced output blocks that
  quote gate output, plus the inline `*"…"*` and backticked fragments in the
  prose.
- The explainer walkthrough's quoted s-expression, witnesses, minted rows and
  ground formula, against a fresh compile of `examples/walkthrough`.
- Every "scenarios at a glance" row against the runner's step count, the
  section its `(step N)` pointer names, and the commands the arc actually runs.

## Method

A scratch copy of the repo was exported with
`git archive --format=tar HEAD | tar -x` into the task scratchpad; nothing was
run against the working tree. Every command ran with **`env -i` and only
`PATH` set**, `cwd` = the scratch copy, and **exit codes captured directly from
`subprocess.returncode`** (never through a pipe). `.venv/bin/gcp-ground` and
`.venv/bin/python` in the scratch copy are two-line `exec` shims onto the repo
venv's interpreter with `PYTHONPATH` pinned to the scratch copy, so the code
under test is the scratch copy's with z3 present — `gcp_grounding.__file__`
was printed once to confirm
(`…/scratchpad/repo/gcp_grounding/__init__.py`).

Quoted fragments were compared after collapsing whitespace on both sides (the
page hand-wraps output to its column width — README:236 and :924-928 say so)
and treating the page's `…` as a wildcard. The solver-minted-witness `(…)`
masking convention was honoured **only where the page invokes it**
(README:232-233, :588-590).

Because the demos' documented exits turn out to depend on two independent
things — whether z3 is importable, and the **file mtime** of two committed
fixtures — every arc was measured in all four combinations:

| condition | `--list` exit | arcs whose exits diverge from the README |
| --- | --- | --- |
| repo venv (z3 present) + fresh-clone mtimes | 0 | **0 of 24** |
| repo venv (z3 present) + `git archive` mtimes | 0 | 2 of 24 — `4`, `4b` |
| no venv (`python3 -m gcp_grounding`, no z3) + fresh mtimes | 0 | 14 of 24 |
| no venv + `git archive` mtimes | 0 | 16 of 24 |

"Fresh-clone mtimes" = every file's mtime set to now, which is what `git clone`
/ `git checkout` produces. "`git archive` mtimes" = the commit timestamp
(2026-08-27), which is what a release tarball, a `git archive` export, or a
week-old checkout produces.

---

## Findings

| id | severity | location | claim | evidence | proposed fix (NOT applied) |
| --- | --- | --- | --- | --- | --- |
| D1 | broken | `README.md:1632-1633` (rows 4, 4b) and `examples/terraform-schema/provider-schema.json` | rows 4 and 4b are "DENIED", and `./run_demo.sh 4` checks that exit | From the `git archive` scratch copy: `env -i PATH=… bash run_demo.sh 4` → exit **1**, `scenario 4: FAIL — 1 of 1 steps diverged`; the step itself exits **0** with `? [tf_schema] the captured provider schema at …/provider-schema.json is 29 days old (file mtime 2026-08-27T09:39:55+00:00), past the 7 days ceiling … so its findings are demoted to abstentions`, and the `[tf_attribute]` finding is demoted from `✗` to `?`. Same for `4b`. `os.utime(provider-schema.json, None)` alone flips both back to PASS — nothing else changed. The file carries no capture stamp: the freshness ceiling reads its **mtime**. | Give the committed schema an explicit `captured_at` (the reader's own envelope shape, `README.md:1416-1418`), or pin `GCP_GROUNDING_NOW` in the `verify_schema` arc as scenario 6 already pins it. |
| D2 | broken | `README.md:1693-1696` (demo step 4) | "a made-up role fails existence grounding and the report suggests the real name" | `.venv/bin/gcp-ground verify-policy tests/fixtures/gcp/policies/iam_policy_bad.json --snapshot tests/fixtures/gcp/snapshot.json` → exit 1, `grounded=0 ungrounded=0 contradicted=1 unverified=10`, **no `✗` verdict and no did-you-mean anywhere**; `roles/bigquery.reader` reads `? [role] bindings[0].role: snapshot did not capture roles — existence of 'roles/bigquery.reader' is undecidable offline`, because `tests/fixtures/gcp/snapshot.json`'s embedded `captured_at` is `2026-07-18T09:30:00Z`, 69 days past the 7-day ceiling. Exit 1 still comes out — from `⚠ [cel] … condition is never true — dead binding` — so the step looks like it worked. The identical command under `GCP_GROUNDING_NOW=2026-07-19T09:30:00Z` gives `✗ [role] … does not exist in the snapshot … (did you mean: roles/bigquery.jobUser, roles/bigquery.dataViewer?)`. No arc covers this step, so the runner cannot catch it. | Pin `GCP_GROUNDING_NOW` in the step (as steps 12/12a-12d already do) or re-stamp the fixture; the capability itself is intact. |
| D3 | misdocumented | `README.md:1685-1687` (demo step 3) | "Exits 1 with the evidence — the principal provably absent from the snapshot, the violated domain promise, and the escalation warning" | Real output: the promise refutation is there (`⚠ [sec:iam] no-primitive-roles-outside-domain: refuted by iam_bindings[0] … member='user:attacker@evil.example' role='roles/owner'`), but the other two are demoted — `? [principal] bindings[0].members[0]: snapshot did not capture principals — existence of 'user:attacker@evil.example' is undecidable offline` and `? [iam_escalation] snapshot did not capture roles — escalation classes were not decided`. Under `GCP_GROUNDING_NOW=2026-07-26T08:00:00Z` all three appear (`✗ [principal] … does not exist`, `✓ [iam_escalation] … warning`). Same root cause as D2. Note the page **does** state this caveat for the same phenomenon elsewhere (`README.md:950-954`, `:1858-1861`, `:2431-2433`) — step 3 is the one that does not. | Pin the clock for step 3, or add the "over a fresh snapshot" qualifier the page already uses at `:2431-2433`. |
| D4 | misdocumented | `README.md:1290` and `README.md:1293-1295` | the quoted `--state-explain DOMAIN:KEY` output | The `chosen:` line is rendered unconditionally with seven fields — `gcp_grounding/explain_state.py:720-726` emits `source=`, `[kind]`, `origin=`, `locator=`, `captured_at=`, `domain-scope=`, `taint=` — but README:1290 quotes only five, dropping `origin=` and `captured_at=`. Likewise every alternate is always followed by a `record:` line (`explain_state.py:740`), which README:1293-1295 omits. A live drill-down (`--state-explain firewall_rules:projects/acme-prod/global/firewalls/allow-rdp-broad`) prints `chosen: source=… [tfstate] origin=… locator=… captured_at=… domain-scope=partial taint=-` followed by `record: …`. The quoted lines are not lines the tool can print. | Re-capture the block from a real run, or mark the omitted fields with the page's own `…`. |
| D5 | cosmetic | `README.md:2442` | `— e.g. src (…); dst (…); protocol 6; port 443` | The gate prints these witnesses **bare**: `e.g. src 0.0.0.0; dst 35.0.0.0; protocol 6; port 443` (scenario `5f`). The parentheses are the page's mask, not the output's — unlike `[firewall_exposure]`, where `a public source (35.32.0.0) can reach tcp/22 through this rule` really does print them, so `(…)` there is byte-faithful. A reader diffing 5f against their terminal sees a difference the convention does not explain. | Write `src …; dst …` for `[firewall_reopen]`, or say the mask sometimes supplies its own brackets. |
| D6 | cosmetic | `README.md:2613-2629` (12a check listing) | three contiguous `✓` lines presented as "the check listing" | The real listing has `✓ [sec:iam] every-deny-covers-token-creation: the obligation holds over the document — grounded` and `✓ [sec:org_policy] sa-…` **between** the quoted `[org_effective]` and `[sec:iam] no-principal-threads-the-guardrail` lines. The quote is a selection with no `…` marking the gap; each quoted line is individually byte-exact. | Insert the page's own `…` between the selected lines. |
| D7 | cosmetic | `README.md:2037-2044` (9e check listing) | three `✓` lines quoted as printed | Each line really ends with a provenance suffix the quote drops with no `…`: `… no public source reaches a sensitive port [snapshot 2026-07-25T08:00:00Z]`, and for the pair check `… the old set denied [pair scope projects/acme-prod/global/networks/prod-vpc INGRESS] [target projects/acme-prod/global/firewalls/allow-rdp-broad \| source examples/terraform-masked/terraform-after-removal.tfstate \| how tf-address] [snapshot …]`. Dropping the suffix is the single relaxation these three lines need (measured: with suffixes dropped the block matches; with them kept it does not). The same elision applies to `README.md:2439-2504` and `:2613-2629`. | State once that quoted verdict lines are shown without their provenance suffix, or keep the suffixes. |
| D8 | cosmetic | `README.md:459-475` | "`examples/walkthrough/requirements.md` holds one sentence and one block:" followed by the block | The committed ```promise block also carries two `note:` lines (`note: domain membership is read off the member id's suffix…` and `note: the collection is iam_bindings…`) which the quote drops from inside the block. The frontmatter and the file's intro prose are also above the quote, which the page does acknowledge at `:477`. | Quote the block whole, or say the `note:` lines are elided. |
| D9 | note | `README.md:819-821` | "`./run_demo.sh w` runs … the compile of step three above, then the verify below and its REST-policy counterpart" | The runner's arc order is compile → **REST policy** (`step 2/3`) → terraform proposal (`step 3/3`); the sentence lists them the other way round. The page's own `:968` gets it right ("is step two of the arc"). | Swap the two clauses at `:820`. |
| D10 | note | `README.md:1897-1904` (step 9a) | a documented command with a documented exit (1) | No at-a-glance row maps to it, so `run_demo.sh` never checks it — `README.md:1924-1926` says so deliberately. Verified by hand: exit **1**, three findings, and all three fragments the page quotes for it (`:1932`, `:1937-1938`, `:1939-1940`) are byte-exact. | None needed; recorded so the reader knows one documented exit is unguarded. |
| D11 | note | `README.md:2409-2410`, `:968-970` | five arcs (`5b`–`5f`) and arc `w`'s REST step run commands that appear in no fenced block | They are documented in prose instead ("swap the `--proposal` path; everything else is identical"; "is step two of the arc"). All six commands were reconstructed and run; all six behave as the page says. | None needed; recorded as coverage. |
| D12 | note | `run_demo.sh:22-23` | "with no venv present it falls back to `python3 -m gcp_grounding` from this checkout" | On that fallback (system `python3`, no z3) **14 of 24 arcs FAIL** even with fresh mtimes: every DENIED verdict that rests on the solver becomes an abstention — e.g. scenario 3 exits 0 with `? [firewall_exposure] … z3 is not available (solver backend 'builtin') — public exposure was not decided`. The comment offers the fallback without saying the documented exits need z3. | Say the fallback runs but that the documented exits assume z3, or have the runner name the backend it resolved. |
| D13 | note | `simple_readme.md:91-95` | "A `.tf.json` or `.tf` proposal REQUIRES a current-state or provider-schema option" | True, but the consequence is unstated: with `--snapshot` alone the run **exits 0**, headlined `PASSED — NOTHING VERIFIED (2 unchecked)` with `? [document] …: document kind was not recognized (top-level keys ['resource']) — nothing was checked`. `README.md:1558-1567` states exactly that and reproduces byte-exactly. A reader of the short version could take "REQUIRES" to mean the tool refuses. | Carry the one clause from `README.md:1563-1566` into the short version. |

### The two root causes, stated once

D1, D2 and D3 are one mechanism: **a documented output is only true within
7 days of a fixture's capture time**, and the demo corpus supplies that time in
two different ways.

1. **Embedded `captured_at`** — `tests/fixtures/gcp/snapshot.json`
   (2026-07-18), `tests/fixtures/gcp/agentic_snapshot.json` (2026-07-25),
   `examples/terraform-orgpolicy/snapshot.json` (2026-07-25),
   `examples/terraform-denypolicy/snapshot.json` (2026-07-18). These are frozen
   in file content, so they are stale for **every** reader today. Scenarios
   5 and 6 handle this by pinning `GCP_GROUNDING_NOW`; demo steps 3 and 4 do
   not, which is D2 and D3.
2. **File mtime** — `examples/*/terraform.tfstate` and
   `examples/terraform-schema/provider-schema.json` carry **no** capture stamp,
   so the ceiling reads their mtime. In a fresh clone that is "now" and the
   documented output holds; in a tarball, a `git archive` export, or a checkout
   more than a week old it does not. That is D1, and it is why one quoted
   figure (`README.md:2058`/`:2073`, `unchecked=4`) reads `unchecked=6` from an
   archive copy and `unchecked=4` from a fresh clone — measured both ways, and
   confirmed by `GCP_GROUNDING_NOW=2026-08-27T12:00:00Z` → `unchecked=4` vs
   `GCP_GROUNDING_NOW=2026-09-25T12:00:00Z` → `unchecked=6`. **The README is
   correct here**; the reproducibility is what is fragile.

---

## Verified true

Everything below was checked and **held**, with the evidence that established it.

### The runner and the scenario tables

- **V1 — `bash run_demo.sh --list` exits 0 and enumerates 24 scenarios**, each
  with an arc. Labels: `1 2a 2b 3 3b 3c 3d 4 4b 4c 4d 5 5a 5b 5c 5d 5e 5f 5g
  6 6a 6b 6c w`. No `(no arc is wired for this scenario)` line was printed and
  the exit was 0, which is the runner's own proof that the README table and the
  arcs agree (`run_demo.sh:list_scenarios`).
- **V2 — all 24 arcs PASS** with z3 present and fresh-clone mtimes: every
  step's observed exit equals the exit the README documents for it
  (`24/24`). Sum: 43 steps.
- **V3 — the step counts agree.** For every row, the count `--list` prints
  equals the number of steps the arc actually runs:

  | row | README line | `--list` steps | steps run | verdict | `(step N)` → section | README line(s) of the commands run |
  | --- | --- | --- | --- | --- | --- | --- |
  | 1 | 1625 | 2 | 2 | PASS | 7 → README:1724 | 153/1673 + 157/1764 |
  | 2a | 1626 | 2 | 2 | PASS | 8 → README:1804 | 1825 + 1829 |
  | 2b | 1627 | 2 | 2 | PASS | 8 → README:1804 | 1825 + 1837 |
  | 3 | 1628 | 1 | 1 | PASS | 9 → README:1881 | 1908 |
  | 3b | 1629 | 1 | 1 | PASS | 9 → README:1881 | 1917 |
  | 3c | 1630 | 2 | 2 | PASS | 9 → README:1881 | 2009 + 2014 |
  | 3d | 1631 | 2 | 2 | PASS | 9 → README:1881 | 2009 + 2023 |
  | 4 | 1632 | 1 | 1 | PASS¹ | 10 → README:2117 | 2141 |
  | 4b | 1633 | 1 | 1 | PASS¹ | 10 → README:2117 | 2149 |
  | 4c | 1634 | 1 | 1 | PASS | 10 → README:2117 | 2156 |
  | 4d | 1635 | 1 | 1 | PASS | 10 → README:2117 | 2239 |
  | 5 | 1636 | 2 | 2 | PASS | 11 → README:2255 | 2291 + 2296 |
  | 5a | 1637 | 2 | 2 | PASS | 11 → README:2255 | 2291 + 2313 |
  | 5b | 1638 | 2 | 2 | PASS | 11 → README:2255 | 2291 + prose (README:2412) |
  | 5c | 1639 | 2 | 2 | PASS | 11 → README:2255 | 2291 + prose (README:2419) |
  | 5d | 1640 | 2 | 2 | PASS | 11 → README:2255 | 2291 + prose (README:2423) |
  | 5e | 1641 | 2 | 2 | PASS | 11 → README:2255 | 2291 + prose (README:2427) |
  | 5f | 1642 | 2 | 2 | PASS | 11 → README:2255 | 2291 + prose (README:2434) |
  | 5g | 1643 | 2 | 2 | PASS | 11 → README:2255 | 2291 + 2520 |
  | 6 | 1644 | 2 | 2 | PASS | 12 → README:2539 | 2593 + 2598 |
  | 6a | 1645 | 2 | 2 | PASS | 12 → README:2539 | 2593 + 2639 |
  | 6b | 1646 | 2 | 2 | PASS | 12 → README:2539 | 2593 + 2722 |
  | 6c | 1647 | 2 | 2 | PASS | 12 → README:2539 | 2593 + 2795 |
  | w | 1648 | 3 | 3 | PASS | (none) — "How the gate thinks", README:294/816 | 486 + prose (README:968) + 887 |

  ¹ with a fresh provider-schema mtime; see **D1**.
- **V4 — every `(step N)` pointer resolves** to the `### N.` section that
  documents that scenario; all six numbered sections (7, 8, 9, 10, 11, 12)
  exist and none is dangling. Row `w` names "How the gate thinks" instead,
  which exists at README:294 with the walkthrough at README:816.
- **V5 — every proposal path named in the table exists on disk** (25 paths
  across 24 rows; row 4d names one path plus the phrase "no `--provider-schema`").
- **V6 — every command the runner runs is a command the page documents.**
  Signature-matched (subcommand + sorted flag/value pairs + positionals) against
  all 67 fenced bash commands: 37 of 43 steps match a fenced command exactly;
  the other 6 are the prose-documented ones of D11.
- **V7 — every "Expect" cell matches the observed run.** 24/24 decisions agree
  (DENIED/APPROVED), and every promise id and `[check_kind]` named in an Expect
  cell appears in that scenario's output — 21 identifier mentions across 14
  rows, 20 distinct, all of them:
  `masked-allow-only-known-domains`, `[iam_scope_diff]`, `[tf_attribute]`,
  `[tf_schema]`, `compute-disable-serialport-access`, `vm-public-ip-gcp`,
  `run-allowed-ingress-internal-loadbalancing`, `cloudrun-ingress-non-public`,
  `vpc-externally-peered-vpc-gcp`, `compute-disable-internet-neg`,
  `public-access-prevention`, `security-contact-gcp`, `deny-admin-roles`,
  `iam-deny-service-account-impersonation`,
  `egress-firewall-policy-high-strength-vpc-firewall`, `[firewall_reopen]`,
  `[iam_deny_shadow]`, `sa-key-creation-stays-effectively-enforced`,
  `owner-stays-inside-acme`, `source_ranges`.
- **V8 — `simple_readme.md`'s 24-row table agrees with the README table and
  with `--list`, label for label** (all three lists compared element-wise). Every
  row's stated verdict matches the observed decision and every identifier it
  names appears in that scenario's output (24/24, 0 missing). `w`'s "DENIED
  twice" matches the arc's two exit-1 steps.
- **V9 — `run_demo.sh`'s own modes**: `--help` exit 0, no argument exit **2**
  with the usage on stderr, `--nope` exit **2**, `99` exit **2** with
  `run_demo.sh: no scenario 99 in the README table. Try --list.`

### The quoted output blocks

17 fenced blocks in the two pages quote gate output. **14 reproduce verbatim**
(modulo the page's hand-wrapping and its own declared `…`); the remaining 3 are
D5/D6/D7 above and each reproduces once that one elision is allowed.

| id | block | command | result |
| --- | --- | --- | --- |
| Q1 | README:167-230 — the quick-start recap + summary | `run_demo.sh 1` | verbatim |
| Q2 | README:490-495 — the walkthrough compile report | `compile-requirements examples/walkthrough …` | verbatim |
| Q3 | README:503-514 — `show_promises.py demo/compiled-walkthrough` | as written | verbatim |
| Q4 | README:897-922 — the walkthrough verify recap + summary | README:887 | verbatim |
| Q5 | README:2037-2044 — the 9e check listing | `run_demo.sh 3c` | **D7** (provenance suffixes) |
| Q6 | README:2057-2074 — the 9e recap + summary, `unchecked=4` | `run_demo.sh 3c` | verbatim (fresh clone) |
| Q7 | README:2083-2111 — the 9f recap + summary | `run_demo.sh 3d` | verbatim |
| Q8 | README:2169-2194 — the 10a recap | `run_demo.sh 4` | verbatim |
| Q9 | README:2212-2220 — the 10b `[tf_attribute]` finding | `run_demo.sh 4b` | verbatim |
| Q10 | README:2245-2253 — the 10d `[tf_schema]` abstention | `run_demo.sh 4d` | verbatim |
| Q11 | README:2321-2390 — the 11b recap | `run_demo.sh 5a` | verbatim |
| Q12 | README:2438-2505 — the egress-world recap | `run_demo.sh 5f` | **D5** (`(…)` brackets) |
| Q13 | README:2613-2629 — the 12a check listing | `run_demo.sh 6` | **D6** (selection) |
| Q14 | README:2652-2701 — the 12b recap | `run_demo.sh 6a` | verbatim |
| Q15 | README:2737-2769 — the 12c recap | `run_demo.sh 6b` | verbatim |
| Q16 | README:2813-2856 — the 12d recap | `run_demo.sh 6c` | verbatim |
| Q17 | simple_readme:81-89 — the result rows | simple_readme:61 | verbatim |

### The explainer walkthrough

Every artifact the "How the gate thinks" section quotes was regenerated from a
fresh compile of `examples/walkthrough` and compared **byte for byte**:

- **README:439-443 — the three minted rows.** `sec_rules._iam_records` over
  `examples/walkthrough/policy.json` returns exactly
  `iam_bindings[0] role='roles/bigquery.dataViewer' member='group:data-eng@acme.example' condition='' has_condition=False`,
  `[1] role='roles/owner' member='user:alice@acme.example' …`,
  `[2] role='roles/owner' member='user:mallory@outsider.example' …`, in that
  order, with `missing_reason=None` — identical to the page modulo its column
  padding. The `(binding, member)` flattening and the `(role, member)` sort the
  page describes are what produce that order.
- **README:511 — the compiled s-expression.** The artifact's stored
  `smt.sexpr` is
  `(exists ((b iam_bindings)) (and (not (suffix b.member "@acme.example")) (eq b.role "roles/owner")))`
  — string-equal to the quoted line, `not` before `eq` exactly as the page
  explains at `:516-518`.
- **README:512-513 — the two pinned witnesses.** The artifact's
  `witnesses.positive` is `{b.member: 'C', b.role: ''}` and
  `witnesses.negative` is `{b.member: 'A', b.role: 'roles/owner'}`, both
  `origin: z3-model` — rendering to the quoted
  `compliant witness (z3-model): b.member='C', b.role=''` and
  `violating witness (z3-model): b.member='A', b.role='roles/owner'`.
- **README:532-539 — the ground formula.** `sec_encode.ground(z3, ast,
  {"iam_bindings": rows}).sexpr()` is **byte-identical to the quoted block,
  including its indentation** — the three-armed `or`, one `and` per row, with
  every `field` already a literal.
- **README:555-562 — the verdict.** `sec_probes.obligation(z3, formula,
  "refute")` is `Not(<that or>)`, and it does not hold
  (`z3.Solver().add(Not(obl)).check()` is `sat`, i.e. the obligation is
  refutable) — so the promise is `contradicted`, as the page says.
- **README:414-432, :826-856, :865-882 — the three quoted files**
  (`policy.json`, `terraform.tfstate`, `proposal.tf.json`) are byte-identical
  to the committed files (modulo the trailing newline) and JSON-equal.

### The non-terraform demo steps (0–6)

- **Step 1** (`compile-requirements tests/fixtures/gcp/sec_requirements`) exits
  **1** by design, as documented, and still writes the artifacts.
- **Step 2** (`show_promises.py demo/compiled`) shows both stated negatives
  byte-exactly: `? NOT ENFORCED  [iam/proposal/refute/high]
  untranslated-security-review-before-merge` and `✗ REJECTED … bigquery-reader-only`
  with `reason: vocabulary is not grounded: roles/bigquery.reader does not
  exist in the snapshot` — the exact string README:1680-1681 quotes. The 6
  enforcing + 2 not matches the summary row README:177 quotes.
- **Step 5** (`scan-command`) exits 0; the banner names the subcommand as
  audit-only (`scan-command classifies shell commands against curated mutation
  tables; it VERIFIES NOTHING and approves nothing — enforcement is
  verify-policy --hook's --bash-policy (default: block).`) and the report
  headlines **`PASSED — NOTHING VERIFIED (1 unchecked)`** — the exact phrase
  README:1702 quotes.
- **Step 6, the hook pair.** Driven through a real pipe with the exact
  `PostToolUse` envelope the page prints: the attack exits **2** with **0 bytes
  on stdout and 2069 bytes on stderr**; the benign edit exits **0** with **0
  bytes on stdout and 0 bytes on stderr** — byte-for-byte silence, as claimed.

### The two "variations worth showing live" (README:1650-1654)

- **`--schema-policy annotate` on scenario 4**: exit **0**, and the finding is
  the identical sentence demoted from `✗` to `?`, the gate itself supplying the
  page's word — `[schema-policy 'annotate': demoted to a warning — 'terraform
  plan' under the captured provider would still refuse it]`.
- **`--provider-schema` added to scenario 1**: the machine report is **byte-identical**
  with and without it (12540 bytes both ways), counts included
  (`grounded=18 ungrounded=0 contradicted=3 unverified=29`), and no `[tf_schema]`
  verdict appears. Only three narrative rows differ — the `provider_schema`
  settings row, the defaults count (12 → 11), and the `provider` summary row.

### Commands, flags and paths

- **V10 — all 21 distinct long flags** used in the two pages' bash fences are
  real `gcp-ground` flags, checked against `--help` for the tool and for all
  four subcommands (`verify-policy`, `compile-requirements`, `scan-command`,
  `capture-terraform`): `--bash-policy --command --completeness --drift-policy
  --explain --format --hook --max-age --origins --out --precedence --proposal
  --provider-schema --requirements --schema-policy --snapshot --state-explain
  --target --terraform-dir --terraform-plan --terraform-state`. Zero unknown.
- **V11 — every repo path a demo command names exists.** The only absent paths
  are the ones the page says you create (`.venv/bin/*`, `demo/*`) and the
  template paths of the adoption sections (`policies/prod-iam.json`,
  `estate/*`, `infra/prod/*`, `proposal.json`, `/tmp/prod.tfstate`), which those
  sections present as your-repo placeholders, not demo inputs.
- **V12 — README:1558-1567's terraform-routing rule reproduces byte-exactly.**
  A `.tf.json` with `--snapshot` alone and no sibling state
  (`examples/terraform-schema/proposal_ok.tf.json`): exit **0**, headline
  `PASSED — NOTHING VERIFIED (2 unchecked)`, and `? [document]
  examples/terraform-schema/proposal_ok.tf.json: document kind was not
  recognized (top-level keys ['resource']) — nothing was checked` — all three
  quoted elements. Form 1 (a rendered plan, `plan_base.json`) needs no such
  option: exit 0, `grounded=17`. And a `.tfstate` passed as a proposal is
  refused: exit 1, `✗ [state:not-a-proposal] …: this is Terraform state, not a
  proposed change.`
- **V13 — README:1032-1049's config example is valid.**
  `discovery.parse_config` accepts it with **zero problems** and maps every key
  to a real settings field (`primary`, `provider_schema`, `terraform_state`,
  `terraform_plan`, `terraform_dir`, `precedence`, `max_age`, `drift_policy`,
  `targets`); `discovery.discover` finds it by walking up from a file beneath it.
- **V14 — README:1119-1129's two-file claim holds.** `capture-terraform
  examples/terraform-masked --out demo/capture-probe.json` exits 0 and reports
  `wrote snapshot demo/capture-probe.json` / `wrote sidecar
  demo/capture-probe.origins.json`; both exist and the sidecar declares the
  view PARTIAL, as the page says.
- **V15 — TTY-only colour** (README:278-286). A piped `--explain` run carries
  **0** ESC bytes; the plain bytes this page quotes are what came out.

### Inline quoted fragments in the prose

- **Scenario 9a's three italic quotes are byte-exact**: `a public source (…)
  can reach tcp/3389 through this rule` (real: `(35.32.0.0)`, the declared
  mask), `unreachable — every packet this rule matches is already decided by
  higher-precedence rule(s) deny-external-rdp; the rule has no effect`, and
  `this deny at priority 900 makes the existing allow 'allow-rdp-broad' at
  priority 1000 unreachable`. 9a exits **1** with exactly three findings, as
  README:1928 says.
- **README:1950's *negative* claim holds**: there is no
  `you removed deny-external-rdp` line anywhere in scenario 3's output.
- **README:2431-2433's qualifier holds**: "Over a fresh snapshot the outsider
  also draws the `✗ [principal] … does not exist in the snapshot` hallucination
  block" — under `GCP_GROUNDING_NOW=2026-07-26T08:00:00Z`, scenario 5e prints
  `✗ [principal] google_project_iam_binding.contractor_owner.members[0]:
  principal 'user:mallory@outsider.example' does not exist in the snapshot
  (captured 2026-07-25T08:00:00Z)`.
- **The illustrative message templates all exist verbatim in the code** (these
  are quoted for a hypothetical estate, so they were resolved against the
  emitters rather than against a run):

  | README | emitter |
  | --- | --- |
  | `:570` `iam_bindings[0].member is missing from the record — not decided` | `sec_encode.py:371` |
  | `:1183-1184` `new⊆old holds: all N grants in the new policy are already granted by the old policy` | `constraints.py:534-535` |
  | `:1186-1191` `new⊈old: … — NOT a block: the baseline came from '…', whose coverage of this domain is '…', and a check that reasons from what the baseline does NOT contain cannot tell a real widening from a row that view never saw` | `constraints.py:550` + `engine.py:764-768` |
  | `:1214-1215` `… COMPLETELY and holds no such row, so this is a new resource with no predecessor to compare it against` | `baseline.py:1340-1343` |
  | `:1218-1219` `… every source covering … is partial, and absence within a partial capture is NOT evidence of absence` | `baseline.py:1352-1354` |
  | `:1245-1246` `a terraform artifact covers only the resources terraform manages, so this scope is capped at 'partial' by construction - it is not a capture bug` | `explain_state.py:330-332` |
  | `:1564` `? [document] … nothing was checked` | `preflight.py:255-256` (`Verdict("unverified", "document", …)`) |
  | `:271-272` `narrows source ranges from … to …` | `cli.py:4223-4224` + `_DELTA_LISTS["source_range"] = "source ranges"` |
  | `:272` `sets enforce=false (was true)` | `cli.py:4216` + `_value_text` (`cli.py:4131-4132`) lower-cases booleans |
  | `:272-274` `adds principal://… to the exceptionPrincipals of the deny rule denying iam.serviceAccounts.getAccessToken` | `cli.py:4220` + `_DELTA_LISTS["exception_principal"]` + `_deny_suffix` (`cli.py:4265-4274`) |
  | `:269-270` `deletes the deny policy denying iam.serviceAccounts.getAccessToken … to principalSet://goog/public:all` | produced live by scenario `6b`, which is where the page says to look |

  Of those four change-effect shapes, only the deletion is exercised by a
  committed demo — the page only claims that one is (`:270`, "in scenario 6b
  below"); the other three are illustrations of the template, and the templates
  are real.

### The state-explain block (README:1239-1266)

The hypothetical `--state-explain` transcript was compared field-set by
field-set against the renderer and against a live run. Everything checks out
except D4: `sources:` rows carry exactly
`[kind] source_id origin= captured_at= age= scope= domains=[…] facts=` in that
order (`explain_state.py:406-411`); the `coverage:` table's
`category / scope / keys / dropped / reasons` columns, the `settings:` block's
one-row-per-set-setting plus the single `N settings at defaults:` line, the
`targets:` block and `drift: none - no source disagreed about a row that was
looked up` all appear byte-exactly in real runs. The `# …` annotations at
`:1241`, `:1250`, `:1254` and `:1261` are the page's own margin notes, not
output; nothing on the page says so, but the comment styling makes it plain.

---

## Reproduction

```
git archive --format=tar HEAD | tar -x -C <scratch>/repo
# .venv/bin/{python,gcp-ground} in <scratch>/repo are exec shims onto the repo
# venv's interpreter with PYTHONPATH=<scratch>/repo
env -i PATH=<PATH> bash run_demo.sh --list          # from <scratch>/repo
env -i PATH=<PATH> bash run_demo.sh <label>         # for each of the 24 labels
```

Measurements were taken on 2026-09-25 with z3 5.0.0 and CPython 3.14.7. The
`git archive` copy reproduces D1 directly; `os.utime` over the tree reproduces
the fresh-clone condition.
