# gcp-policy-grounding

A **neuro-symbolic grounding gate** for Google Cloud policy changes — IAM
allow/deny policies, Organization Policy, VPC and hierarchical firewalls,
Cloud Armor, VPC Service Controls, and the Terraform that generates all of
them. It catches the policy analog of code hallucination — an LLM (or a human)
confidently writing `roles/bigquery.reader` (doesn't exist) instead of
`roles/bigquery.dataViewer`, binding a service account nobody created, putting
list values on a boolean org-policy constraint — and the provably dangerous
change a linter can't see: a firewall allow inserted ahead of the deny that
used to cover it, a perimeter quietly flipped to dry-run, `roles/owner`
granted outside your domain.

Every claim a policy makes lands in one of four honest buckets:

- **grounded** — the referenced role/permission/principal/constraint exists in
  the knowledge-base snapshot (stamped with the snapshot's `captured_at`);
- **ungrounded** — it does not exist (with a nearest-name suggestion);
- **contradicted** — it exists but is used wrongly (list value on a boolean
  constraint, an IAM condition that is provably never true);
- **unverified** — the snapshot can't answer (not captured, unsupported CEL) —
  stated honestly, never guessed.

Existence questions are decided by a Datalog pass over a frozen JSON snapshot
of the GCP estate (offline, deterministic, no credentials). Satisfiability and
comparison questions — "is this CEL condition ever true?", "does the new policy
grant a strict subset of the old one?" — go to **z3** when installed, and
degrade to explicit `unverified` when not.

## What it checks — supported policy surfaces

| Surface | Documents read | Checks |
| --- | --- | --- |
| **IAM allow policies** | policy JSON, terraform | role/permission/principal existence with did-you-mean; CEL condition satisfiability (dead bindings); escalation-class warnings; public-principal blocking; new⊆old widening against a baseline |
| **IAM deny policies** (v2) | deny-policy JSON, terraform | denied-permission existence; per-rule flattening into the `deny_rules` / `deny_rule_exceptions` promise collections (permission exceptions subtracted before rows exist, principal carve-outs kept visible); the allow×deny interaction (`iam_deny_shadow`): masked grants warned inert, exception threading named, a deny removal that wakes a dormant escalation grant blocked |
| **Organization Policy** | v1 + v2 JSON, terraform | constraint existence; boolean/list value-type contradictions; enforce-flip detection; all three disablement spellings; the effective-state fold over the captured hierarchy (`org_effective`): inert and blast-radius findings, estate-tier `effective_org_policy_*` collections for promises |
| **VPC firewall rules** | firewall JSON, terraform | world-open exposure via the packet algebra (CIDR/port/protocol bit-vectors); pair non-enlargement; estate-level shadowing and re-opening by priority |
| **Hierarchical firewall policies** | policy JSON, terraform | cross-level evaluation order and `goto_next`; a folder allow re-opening an org deny; placement and replacement |
| **Cloud Armor** | security-policy JSON, terraform | priority-order bypass; default-rule removal; match-expression grounding over the offline-decidable subset |
| **VPC Service Controls** | perimeter / access-level JSON, terraform | perimeter shrink; restricted-service removal; ingress/egress widening (`ANY_IDENTITY`, wildcards); dry-run flips; ghost access levels |
| **Custom roles** | role JSON, terraform | every included permission must exist in the estate's enumeration; a predefined→custom swap is scope-diffed against the binding's current grant (extras drawn as warnings, never blocks) |
| **Provider schema** (terraform) | `.tf` / `.tf.json` / plan JSON, plus a locally captured `terraform providers schema -json` | every `google_*` block's attributes and nested blocks must exist in the captured provider's schema (did-you-mean on a miss); attribute-vs-block and scalar-vs-list shape contradictions; `dynamic` blocks, computed attributes and resource types absent from the capture abstain by name (a type may live in an uncaptured provider); strictness via `--schema-policy` |
| **Shell commands** | `gcloud` `gsutil` `bq` `terraform` `kubectl` `curl` text | state-mutation classification (audit via `scan-command`, blocking via the hook's `--bash-policy`) |

Every surface gets the same four-bucket honesty contract, and every domain can
carry compiled promises from your requirements (`iam`, `vpc_firewall`,
`hier_firewall`, `cloud_armor`, `org_policy`, `vpc_sc`).

Two of those rows deserve a sentence more, because they are judgments most
gates cannot make. **The IAM-deny pair**: every deny policy under review
flattens into `deny_rules` — one row per *effective* (rule, denied-principal,
denied-permission) combination, with `exceptionPermissions` subtracted on the
normalized short form *before* rows exist, so a clawed-back denial never
satisfies a promise — plus `deny_rule_exceptions`, one row per principal
carve-out (principal exceptions are never a string subtraction: an exception
can carve one subject out of `public:all`, so they stay visible as rows and as
a per-row `has_principal_exceptions` flag). Beside the collections, the
`iam_deny_shadow` checks decide the allow×deny *interaction*: a grant fully
covered by a deny rule is warned as inert rather than blocked (GCP lands the
grant; nothing becomes reachable), a grant threading a rule's exception is
named — and blocked when the threading member is public — and a deny
deletion or narrowing that wakes a dormant escalation-class grant is
contradicted outright. The honest limits, stated rather than papered over:
principal coverage is decided by a small curated v1→v2 containment table
(`user:` / `serviceAccount:` / `group:` / `allUsers`); group *membership* is
not captured in any snapshot category, `denialCondition` satisfiability is
not reasoned about, and uncurated `principalSet://` spellings all abstain by
name; and the `iam_deny_policies` estate table has no fetch path yet, so the
estate-side interaction over a snapshot without it yields one
`estate:incomplete` abstention saying the allow×deny interaction was not
decided — never a silent assumption that no deny policy exists.

**The effective org-policy fold** (`org_effective`): a per-document read
answers "what does this policy say", never "what is actually enforced at this
node once the org, the folders and this change compose". The fold answers the
second question — boolean constraints nearest-set-wins, list constraints
replace or inherit-union, `reset` restoring the constraint's managed default
(decidable only from the optional `constraint_default` field the fetcher now
captures) — over the proposal's node and every captured descendant, and
surfaces it two ways: the estate-tier `effective_org_policy_bool` /
`effective_org_policy_values` collections promises quantify over, and one
built-in finding per (node, constraint) — INERT when the change restates what
is already in force (loud, because a guardrail that changes nothing is a
signal reviewers need), or the blast radius enumerating exactly the nodes
whose effective state changes with a before→after summary each. Its honest
limits: the fold refuses by name whenever the capture may not license it —
`org_policies` or `resource_hierarchy` uncaptured or incomplete, a condition
anywhere on the folded chain, a fold bottoming out at a managed default the
snapshot did not record, type confusion, a broken or cyclic parent chain —
and the universe is proposal-scoped: it judges the constraints and subtree
the change actually touches, never an estate-wide sweep.

## Quick start

Sixty seconds from clone to a blocked terraform change, fully offline:

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'

# compile the bundled plain-English security promises into enforced rules
# (EXITS 1 by design: the corpus includes a deliberately rejected document)
.venv/bin/gcp-ground compile-requirements tests/fixtures/gcp/sec_requirements \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json --out demo/compiled

# judge a terraform change that violates them — every input named by its flag
.venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform/main.tf.json \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json \
    --terraform-state examples/terraform/terraform.tfstate \
    --requirements demo/compiled \
    --explain
```

Exit code 1, and the last lines on your terminal are the verdict:

```text
decision recap: DENIED (exit 1) — because:
  ⚠ [firewall_exposure] google_compute_firewall.allow_ssh_world: a public
      source (…) can reach tcp/22 through this rule
  ⚠ [sec:vpc_firewall] no-open-ssh-rdp-ingress: refuted by
      proposed_firewall_rules[1] (google_compute_firewall.allow_ssh_world) …
(the full narrative is above, before the report)

summary — what just happened:
  terraform state on disk : examples/terraform/terraform.tfstate [cli]
  promises in force       : 6 enforcing, 2 not — from demo/compiled [cli]
      (impersonation-sre-only, no-open-ssh-rdp-ingress,
      no-primitive-roles-outside-domain, no-public-principals,
      perimeter-restricts-storage, +1 more)
  provider                : no schema configured — resource shapes not checked
  proposed change         : examples/terraform/main.tf.json — a terraform
      configuration (8 resources): 3 google_compute_firewall,
      2 google_project_iam_binding,
      1 google_access_context_manager_service_perimeter,
      1 google_compute_security_policy, 1 google_org_policy_policy
  result                  : DENIED (exit 1)
    it violated these promises: no-open-ssh-rdp-ingress,
      no-primitive-roles-outside-domain
    blocked by 1 built-in finding: [firewall_exposure]
```

(the `(…)` holds a solver-minted example address — e.g. `(35.32.0.0)` — not a
constant of the rule, so nothing should pin it; the `…` elsewhere covers the
recap's third deny line, an `[sec:iam]` refutation, and the tail of two rows
this page wraps — every summary row is one line on your terminal)

The summary is the closing block of every `--explain` run: each input row
names the settings layer that supplied it — `[cli]`, `[env]`, `[config
<path>]`, `[auto]`, `[default]`, the same labels `--state-explain` prints —
and the result row is last, so the decision stays the final word.

— the violated promise is one of six English sentences compiled from
`tests/fixtures/gcp/sec_requirements/`, and the refutation names the exact
terraform block to fix. The full walkthrough, including what each flag is and
every other act (hallucination did-you-mean, shell-command scanning, hook
mode), is under **Running the demo** below.

## The three inputs

### 1. What the engine compares

You hand the tool up to **four artifacts** (the quick start names each with a
flag: `--proposal`, `--snapshot`, `--terraform-state`, `--requirements`), but
the engine reads them as **three inputs** — because the API snapshot and the
terraform files are not separate inputs, they are two *suppliers of the same
input*, the current state, deliberately merged and cross-checked so their
disagreement is itself a finding (drift). Every answer comes out of comparing
the three, and the report says which of them each answer came from.

```text
      PROPOSAL                    CURRENT                       RULES
  the edit under review       what exists now              what must hold
  ---------------------      -----------------            ----------------
  .policy.json               api snapshot (fetched)       built-in claim checks
  org policy json            terraform state (.tfstate)   built-in document checks
  terraform plan json        terraform plan prior state   built-in pair checks
  .tf / .tf.json             terraform config (.tf)       compiled requirements
             \                       |                          /
              \                      |                         /
               +--------->  the grounding engine  <-----------+
                                     |
                        one report + provenance per answer
```

- The **proposal** is the document or terraform file the agent just wrote — the
  thing under review. It is the only input the tool ever reads from the edit.
- The **current** state is what exists now, before the edit lands. Without it
  the tool can say "this role does not exist" but never "this change grants
  something that was not granted before".
- The **rules** are the built-in checks that ship with the package, plus any
  promises compiled from your requirements directory with
  `gcp-ground compile-requirements`.

### 2. Two overlapping ways to get the current state

There are two suppliers for the current side, and you are meant to use both.

|                  | API snapshot                          | terraform on disk                       |
| ---------------- | ------------------------------------- | --------------------------------------- |
| what it sees     | the whole estate, however it was made | only what terraform manages             |
| what it needs    | credentials, plus a capture step      | nothing — the files are already there   |
| how current      | as current as your last capture       | exactly as current as your last `apply` |

The API fetchers see everything, including resources nobody wrote terraform
for, but they need credentials and somebody has to run the capture. Terraform
on disk needs neither: the state file is sitting in the repo (or one
`terraform state pull` away), and it is exactly as current as your last apply.
What it cannot do is see anything outside terraform's own world.

They overlap **deliberately**. Where both answer for the same row, a
disagreement between them is not noise to be resolved away — it is a finding in
its own right, reported as drift, with the losing record kept whole.

### 3. Pointing the tool at terraform

Drop one `.gcp-grounding.json` at the root of the repo:

```json
{
  "schema": "gcp-grounding-config/1",
  "snapshot": "estate/api-snapshot.json",
  "provider_schema": "estate/provider-schema.json",
  "terraform": {
    "state": ["infra/prod/terraform.tfstate"],
    "plan": ["infra/prod/plan.json"],
    "config_dir": ["infra/prod"]
  },
  "precedence": "highest-fidelity-wins",
  "max_age": "7d",
  "drift": "annotate",
  "targets": {
    "policies/prod-iam.json": "iam_bindings://cloudresourcemanager.googleapis.com/projects/acme-prod"
  }
}
```

Every relative path resolves against the config file's own directory, never
against the working directory the tool happened to be started in. The file is
**discovered by walking up from the file being checked** (stopping at the `.git`
that contains it), so one file at the repo root covers every edit anywhere in
the tree — and a monorepo can put a second one deeper down for a subtree that
has its own state.

The same settings as flags, when you would rather be explicit:

```bash
gcp-ground verify-policy policies/prod-iam.json \
  --snapshot estate/api-snapshot.json \
  --provider-schema estate/provider-schema.json \
  --terraform-state infra/prod/terraform.tfstate \
  --terraform-plan infra/prod/plan.json \
  --terraform-dir infra/prod \
  --precedence highest-fidelity-wins \
  --max-age 7d \
  --drift-policy annotate
```

and the environment variables, for CI, where there is no file to edit:

```bash
export GCP_GROUNDING_SNAPSHOT=estate/api-snapshot.json
export GCP_GROUNDING_PROVIDER_SCHEMA=estate/provider-schema.json
export GCP_GROUNDING_TF_STATE=infra/prod/terraform.tfstate
export GCP_GROUNDING_TF_PLAN=infra/prod/plan.json
export GCP_GROUNDING_TF_DIR=infra/prod
export GCP_GROUNDING_PRECEDENCE=highest-fidelity-wins
export GCP_GROUNDING_MAX_AGE=7d
export GCP_GROUNDING_DRIFT_POLICY=annotate
export GCP_GROUNDING_CONFIG=/checkout/.gcp-grounding.json
```

Flags beat the environment, the environment beats the config file, and the
config file beats what was auto-detected. Once any current-state source is
configured, `--state-explain` (below) prints which layer supplied every one of
them; with no current-state source at all it collapses to the single "none
configured" line and prints no settings block.

A malformed value is handled differently by layer, on purpose: typo'd as a
flag or an environment variable it is a hard usage error (exit 2) naming the
token, but a malformed config FILE is refused **whole** — never partially
applied — and the run continues on the defaults, reporting the refusal as
non-blocking `? [provenance]` notes in the report body. A refused config still
counts as "the operator wrote a config": auto-detection of a sibling
`terraform.tfstate` is suppressed exactly as it is for a config that parsed.

**No terraform binary is ever invoked.** The tool reads the files directly:
state files, `terraform show -json` output, plan JSON, terraform JSON
configuration (`.tf.json`) and raw HCL (`.tf`). It never shells out and never
makes a network call, which is also why it is safe on a PostToolUse hook.

With a remote backend (`gcs`, `s3`) there is no local state to read. Pull it
into a file and point at that:

```bash
terraform state pull > /tmp/prod.tfstate
gcp-ground verify-policy policies/prod-iam.json --terraform-state /tmp/prod.tfstate
```

The tool deliberately **refuses** the `terraform.tfstate` under a `.terraform/`
directory. With a remote backend that file holds only the backend configuration
`terraform init` recorded — it has no `resources` array at all, which is
byte-indistinguishable from a clean, empty estate. Reading it would produce a
confident "there are no firewall rules" from a file that never described any.

**The sidecar travels with the snapshot.** `capture-terraform` writes two files,
and the second one is not optional:

```bash
gcp-ground capture-terraform infra/prod --out estate/terraform-snapshot.json
```

```text
estate/terraform-snapshot.json          the snapshot
estate/terraform-snapshot.origins.json  the sidecar: says this view is PARTIAL
```

The sidecar is the only thing that tells every later command that this snapshot
covers only what terraform manages. It is picked up automatically when it sits
beside the snapshot, and named with `--origins` when it does not:

```bash
gcp-ground verify-policy policies/prod-iam.json \
  --snapshot estate/terraform-snapshot.json \
  --origins estate/terraform-snapshot.origins.json \
  --target iam_bindings://cloudresourcemanager.googleapis.com/projects/acme-prod
```

Copy the snapshot without it and it is byte-indistinguishable from a full API
capture — so the tool treats its coverage as `undeclared` rather than complete.
That is honest, and it costs you every new-resource answer (see §5). It holds
whether or not any other source is configured. The only way to license absence
reasoning for a snapshot with no sidecar is to say so explicitly, per run:

```bash
gcp-ground verify-policy policies/prod-iam.json \
  --snapshot estate/api-snapshot.json --completeness complete
```

There is deliberately no config-file key and no environment variable for
`--completeness`, because an accidental completeness claim is exactly the
failure the sidecar exists to prevent.

### 4. The completeness boundary, in practice

**This is the paragraph to read if you read only one.**

A terraform view answers *what your terraform declares*. It never answers *what
exists in your project*. Clickops resources, other pipelines, other workspaces
and other state files are all invisible to it — not reported as missing, simply
outside the frame.

So a rule of the form *no firewall rule **anywhere** allows the open range on
port 22* **cannot be discharged from terraform alone**, and the tool will say
`unverified` rather than pass it. A rule that quantifies over a whole domain
needs a source that enumerated that domain.

Concretely, over a terraform-only current state:

- you still get `grounded` when a change **adds nothing** — and that stays true
  over a partial view, because new ⊆ (what terraform showed) ⊆ reality;
- you get `unverified` instead of `contradicted` when a change **looks like a
  widening**, because the thing it appears to add might already exist outside
  terraform.

Side by side, the two messages you will actually see:

```text
✓ [subset] new⊆old holds: all 3 grants in the new policy are already granted by
  the old policy

? [subset] new⊈old: the new policy grants roles/storage.objectViewer to
  serviceAccount:etl-runner@acme-prod.iam.gserviceaccount.com, which the old policy
  does not — NOT a block: the baseline came from 'infra/prod/terraform.tfstate',
  whose coverage of this domain is 'partial', and a check that reasons from what
  the baseline does NOT contain cannot tell a real widening from a row that view
  never saw
```

And the boundary is judged **per source, per entry**: when a baseline entry's
document came from a source that declared itself complete (an API capture with
`completeness: complete`, or a merged category whose contributors all agree),
a widening finding against that entry **survives** as a block even while other
categories stay partial — the coverage that governs each entry is the stronger
of the merged category scope and the owning source's own declaration. Declaring
a source complete is therefore exactly as consequential as it sounds, and it is
never inferred.

The first is a pass you can rely on. The second is not a pass and not a block —
it is the tool saying it was not entitled to the finding. Capture an API
snapshot to turn those into hard blocks.

### 5. New resource versus never looked

These are the two abstentions you will see most, and they are not the same
thing. Quoted from the code:

```text
? [baseline:new]
  ... COMPLETELY and holds no such row, so this is a new resource with no
  predecessor to compare it against

? [baseline:unqueried]
  ... was NOT looked up: every source covering ... is partial, and absence
  within a partial capture is NOT evidence of absence
```

`baseline:new` means the tool **looked**, with a source that enumerated the
domain completely, and there genuinely is no predecessor. That is normal: it is
what every new resource looks like.

`baseline:unqueried` means it **did not look** — either no configured source
covers that domain at all, or every source that does is `partial` or
`undeclared`. That is a configuration gap, not a property of your change, and
the message names the covering sources so you can see which one to fix.

### 6. Reading provenance

```bash
gcp-ground verify-policy policies/prod-iam.json --state-explain
```

prints, to stderr, everything the run's answers rested on:

```text
state used this run: 2 source(s), 1 target(s), 0 conflicting
sources:                                    # every source read, highest fidelity first
  [tfstate] infra/prod/terraform.tfstate origin=infra/prod/terraform.tfstate
      captured_at=2026-08-04T21:57:38Z age=0 hours scope=undeclared
      domains=[firewall_rules=partial, iam_bindings=partial, org_policies=partial] facts=9
    note: a terraform artifact covers only the resources terraform manages, so this
          scope is capped at 'partial' by construction - it is not a capture bug
  [unattributed] estate/api-snapshot.json origin=estate/api-snapshot.json
      captured_at=2026-07-18T09:30:00Z age=17 days scope=undeclared
      domains=[firewall_rules=partial, iam_bindings=partial, roles=undeclared] facts=37
  coverage:                                 # per-domain completeness, merged
    category                              scope       keys  dropped  reasons
    firewall_rules                        partial        4        0  -
    iam_bindings                          partial        1        0  -
settings:                                   # every setting, and WHICH layer supplied it
  primary = estate/api-snapshot.json [config /checkout/.gcp-grounding.json]
  terraform_state = infra/prod/terraform.tfstate [cli]
  precedence = - [default]
  max_age = 7d [env]
targets:                                    # which source won, and HOW the row was matched
  iam_bindings //cloudresourcemanager.googleapis.com/projects/acme-prod
      -> estate/api-snapshot.json [explicit-flag]
      resolved - a current counterpart was found and compared against
drift: none - no source disagreed about a row that was looked up
```

`[explicit-flag]`, `[config-map]`, `[tf-address]` and `[tf-attributes]` are the
*how*: "the terraform address matched" and "the name matched after self-link
normalisation" are very different levels of confidence, and you should be able
to see which one you got.

Give the flag a `DOMAIN:KEY` to drill into one target instead — the winning
record, every losing alternate with the reason it lost, and the fields they
differ on:

```bash
gcp-ground verify-policy policies/prod-iam.json \
  --state-explain iam_bindings://cloudresourcemanager.googleapis.com/projects/acme-prod
```

```text
state fact iam_bindings //cloudresourcemanager.googleapis.com/projects/acme-prod:
  chosen: source=estate/api-snapshot.json [unattributed] locator=- domain-scope=partial taint=-
    record: {'bindings': [...]}
  alternates: 1
    alternate: source=infra/prod/terraform.tfstate locator=google_project_iam_binding.owner
      reason=lost to 'estate/api-snapshot.json' under precedence 'api-wins'; the losing
             record is kept WHOLE so a pair check can be re-run against it
  differences:
    none - no comparable field difference was recorded for this key
```

The same content is machine-readable: when a current-state source is configured,
`--format json` adds a `state` key to the report document holding the whole
provenance block.

```bash
gcp-ground verify-policy policies/prod-iam.json --format json --terraform-state infra/prod/terraform.tfstate
```

No source configured means no `state` key at all — which is how a consumer tells
"every configured source failed" (`state.sources` is empty) from "state was
never switched on".

This surface exists for one reason: a guardrail whose inputs cannot be audited
will not be trusted, and a guardrail nobody trusts gets switched off.

### 7. What this still does not mean

A pass means the claims in this document **grounded against the state the tool
actually had** — the snapshot you gave it, at the coverage that snapshot
declared, at the freshness it was captured with. It never means the policy is
safe. A rule nobody wrote is a rule nobody checked, and an estate nobody
captured is an estate nobody looked at.

Secrets in terraform state are redacted at load time, at the boundary where the
value is read, and never reach a finding, a report or a log line. Two different
secrets never render identically either — a constant mask would make two
sources' sensitive fields compare equal and silently suppress the drift finding
between them.

## The pieces, in one sentence

Four artifacts in your hands, three inputs to the engine — the snapshot and
the terraform files both feed the *current* side:

- The **API snapshot** is what is currently live plus an inventory of what is
  real: half of it lists the names that exist (every role and permission GCP
  defines, your org's policy constraints, every account that appears anywhere
  in your estate — what lets the tool call a name *fake* and suggest the real
  one), and half records how things are configured right now (current grants,
  firewall rules, perimeter settings — what lets it say *this change grants
  something that was not granted before*).
- The **terraform** files are your current state as captured in IaC — exactly
  as fresh as your last `apply`, covering only what terraform manages, and
  deliberately never trusted as the whole picture.
- The **requirements** are your plain-English promises in `sec_requirements/`,
  compiled by `compile-requirements` into solver-checked rules, each proven
  non-vacuous and pinned with a concrete compliant and violating example.
- The **proposal** is the document or terraform change being judged.

Every run is one sentence: *judge the proposal, against current state (API +
terraform, cross-checked), under the rules (built-ins + compiled promises),
and report every answer with its provenance.*

## Why the API snapshot, when everything is terraform

Even in a shop where every change is applied through terraform, the snapshot
carries two things terraform structurally cannot:

- **Terraform records what you wrote, not which names are real.** Your state
  file contains the role names you happened to use; it is not a catalog of the
  names that exist. Only the snapshot's inventory can prove a typo'd role or a
  made-up account is fiction — and people and groups never live in terraform at
  all, they come from your identity system.
- **"Everything goes through terraform" is a policy, not a law of physics** —
  and it is exactly the policy an out-of-band change violates: a console
  break-glass, a script, a compromised credential running `gcloud`. None of it
  ever appears in your state file. With both sources configured, the tool
  *checks* your IaC-only policy instead of assuming it: any divergence between
  terraform's view and the live estate surfaces as drift, naming both sides.
- **Proving absence needs a complete list.** "No existing rule already allows
  this" is only sound over a source entitled to say *and there is nothing
  else*. Terraform is deliberately capped below that, so estate-wide negative
  reasoning abstains without the snapshot.

Terraform-only is still a legitimate reduced mode: your compiled promises fire
on every proposal (they judge the proposal's own content and need no snapshot
at evaluation time), and comparisons against terraform-managed resources work.
What you give up is hallucination-blocking and absence reasoning — the tool
will say so honestly (`PASSED — NOTHING VERIFIED`) rather than pretend.

## The provider schema: judging against the provider that actuates

The estate snapshot knows which *names* are real — roles, permissions,
principals, constraints. It knows nothing about the *provider's* vocabulary:
whether `google_compute_firewall` spells its source filter `source_ranges` or
`src_ranges` is a fact about the terraform provider build pinned in your
checkout, and the tool that enforces it is `terraform plan` — at plan time, in
CI, after the push. The gate closes that gap from a file: **terraform tells
you at plan time, in CI, after the push; the gate tells you at write time,
from a file — in the same report as the rule's ports and ranges.**

**What you supply.** One local command, no credentials, run in the checkout
where `terraform init` has already run (the schema is read out of the provider
binary init installed — nothing is fetched):

```bash
terraform providers schema -json > provider-schema.json
```

The gate itself never runs terraform and never touches the network — this
feature is consumption-only, which is why the capture is yours. The division
of labour:

|                 | capture (yours)                        | check (the gate's)                        |
| --------------- | -------------------------------------- | ----------------------------------------- |
| when it runs    | once per provider bump — refresh when `.terraform.lock.hcl` changes | every `verify-policy` run, hook included |
| what it needs   | an init'd checkout — local, credential-free | the captured file — no terraform binary, no network |
| what it yields  | `provider-schema.json`                 | `[tf_attribute]` / `[tf_block]` / `[tf_resource_type]` verdicts |

**The version, honestly.** The raw `terraform providers schema -json` output
is keyed by provider *address* and carries no provider *version*, so the gate
records the version as unknown: messages say "the captured provider schema"
and never invent a release number, and freshness keys on the file's own
modification time. To put on record what you actually know, wrap the same
output in the `gcp-provider-schema/1` envelope — one line:

```bash
terraform providers schema -json | python3 -c 'import json,sys,datetime as d; print(json.dumps({"schema":"gcp-provider-schema/1","captured_at":d.datetime.now(d.timezone.utc).isoformat(),"raw":json.load(sys.stdin)}))' > provider-schema.json
```

`captured_at` then drives freshness instead of the mtime, and an optional
`provider_versions` map (copy the pins from `.terraform.lock.hcl`) is quoted
in findings when present — only where truly known, never guessed. The
wrapper's own keys are parsed strictly (a typo'd `captured_at` must not
silently disarm the freshness check); the raw terraform shape inside it is
read tolerantly, because that format is terraform's to evolve.

**Configurability.** Off by absence: configure nothing and nothing changes,
byte for byte. The schema rides the standard three layers —
`--provider-schema PATH` (repeatable, one file per provider, so `google` and
`google-beta` can each contribute), `GCP_GROUNDING_PROVIDER_SCHEMA`, and the
`provider_schema` key of `.gcp-grounding.json` — and `--state-explain` reports
which layer supplied it. Strictness is `--schema-policy` (env
`GCP_GROUNDING_SCHEMA_POLICY`, config key `schema_policy`):

- `block` — the default: findings keep their honest statuses, so an unknown
  attribute (`ungrounded`) or a shape mismatch (`contradicted`) fails the
  gate. The default is `block` because `terraform plan` would hard-fail the
  same attribute anyway — refusing at write time blocks nothing that could
  ever have applied;
- `annotate` — the same findings demoted to `unverified` warnings, for
  hook-side gentleness: an `unverified` never blocks and is silent in hook
  mode unless `--abstain-notes` is on. The intended pattern is
  hook-annotates-while-CI-blocks: export
  `GCP_GROUNDING_SCHEMA_POLICY=annotate` where the hook runs, let CI run with
  the `block` default;
- `off` — the captured schema is ignored.

A schema past the freshness ceiling (`--max-age`, default 7 days) demotes to
loud abstention like any other stale source: every finding it would have made
becomes an `unverified` naming the age and the recapture command, because a
vocabulary nobody recaptured cannot block. Configuring a policy while
supplying no schema is the one loud non-finding: the run abstains by name
("N google_* resource block(s) were NOT judged against any provider schema")
rather than passing in a silence indistinguishable from coverage.

**What the schema cannot express abstains by name.** A `dynamic` block is
expanded at plan time, so what it generates is not in the configuration — not
judged, said so. A value written under a purely *computed* attribute is the
provider's territory — named, not guessed (on a real plan document, computed
attributes are the provider's own output and are read silently). And what the
schema cannot even see — `conflicts_with`, `exactly_one_of`, server-side
validation of *values* — is never simulated: the captured schema decides names
and shapes, nothing else, and the honesty contract holds at that boundary
exactly as it does at every other.

## Authoring promises: what the compiler proves, what you review

Writing a promise — by hand, or drafted by the optional LLM assist — does not
mean writing tests for it. Per promise, at compile time, automatically:

1. **Grammar and types** — sorts, bounds, unknown keywords: honest rejection.
2. **Vocabulary grounding** — every role, permission, principal and constraint
   the promise *names* is checked against the estate snapshot; a hallucinated
   name fails to compile, with a did-you-mean.
3. **Satisfiability, proven** — the solver confirms some record *could*
   violate the rule; a rule that can never fire is rejected.
4. **Non-tautology, proven** — some record *could* comply; a rule that forbids
   nothing is rejected as vacuous. A vacuous security rule is worse than none,
   because it reads as coverage.
5. **Auto-generated test vectors** — the compiler extracts a concrete
   compliant example and a concrete violating example from the solver's own
   models and pins them into the artifact as literals. They are re-classified
   on every recompile and at every load, forever: if a solver upgrade, an
   edit, or tampering ever changes what the formula decides, the pinned
   witnesses stop classifying and the rule **refuses to load** rather than
   silently meaning something else.
6. **Independence probing** across promises, and the `--check` CI drift gate.

Two things remain yours, because no prover can do them:

- **Semantic fidelity.** Does the formula mean what your English sentence
  says? The pinned witnesses are the designed review surface — read the
  violating example and ask "is *this* what I meant to forbid?"
  (`show_promises.py` renders sentence, rule and witnesses side by side.)
- **End-to-end acceptance, if you want it.** One violating document and one
  benign document per promise, asserted to block and pass — the pattern the
  bundled promises' own tests use, a few lines per case. It is the only layer
  that catches "compiled, meaningful, but the extractor never feeds it the
  records I assumed."

## Capturing the API snapshot from a live estate

There is no network code anywhere in the gate itself; capture is one read-only
script driven by `gcp_grounding.fetch`, run wherever credentials live, on
whatever schedule you like:

```bash
gcloud auth application-default login       # or a service-account key
pip install google-api-python-client        # the one optional dependency
```

```python
from gcp_grounding import fetch

fetch.capture_snapshot(
    # the inventory of what is real (hallucination-blocking):
    iam=fetch.default_client("iam"),
    custom_role_parents=["organizations/YOUR_ORG_ID"],
    orgpolicy=fetch.default_client("orgpolicy"),
    orgpolicy_parent="organizations/YOUR_ORG_ID",
    asset=fetch.default_client("cloudasset"),
    asset_scope="organizations/YOUR_ORG_ID",
    capture_iam_bindings=True,              # ...and the live grants
    out_path="estate/api-snapshot.json",
)
```

Viewer-tier IAM roles suffice; only the categories you configure are captured
(everything else honestly answers "not captured" rather than "absent"), and a
snapshot older than the freshness ceiling (7 days by default) demotes itself —
staleness can never silently bless a deleted role. One namespace note for
hand-authored snapshots: the `resource_types` category holds **terraform
provider type names** (`google_compute_firewall`), never CAI asset types
(`compute.googleapis.com/Instance`) — it is what terraform proposals are
grounded against, and filling it with asset-type strings would make every real
terraform type in a proposal read as a hallucinated `ungrounded` block.

## Proposing a terraform change — agent or human

The proposal is always just the positional file argument; the gate neither
knows nor cares whether an agent or a human wrote it. For terraform changes it
accepts three forms, best first:

```bash
# 1. A rendered plan — resolved values, the form CI should use:
terraform plan -out change.plan && terraform show -json change.plan > proposal.json
gcp-ground verify-policy proposal.json --snapshot estate/api-snapshot.json

# 2. Terraform JSON configuration (.tf.json), as edited in the repo
gcp-ground verify-policy infra/prod/iam.tf.json --snapshot estate/api-snapshot.json \
    --terraform-state infra/prod/terraform.tfstate

# 3. Raw HCL (.tf) — read by a deliberately small built-in parser; anything it
#    cannot resolve (module magic, interpolations) abstains loudly
gcp-ground verify-policy infra/prod/iam.tf --snapshot estate/api-snapshot.json \
    --terraform-state infra/prod/terraform.tfstate
```

Forms 2 and 3 REQUIRE a current-state or provider-schema option (any of
`--terraform-state` / `--terraform-plan` / `--terraform-dir` /
`--provider-schema`, a config-file equivalent, or the auto-detected sibling
`terraform.tfstate`): the terraform configuration routes live on the engine
path, which only a configured current state or schema selects. With
`--snapshot` alone, a `.tf.json` or `.tf` document is not judged — the run
says so honestly (`? [document] … nothing was checked`, headline `PASSED —
NOTHING VERIFIED`, exit 0) rather than passing silently, but nothing is
checked. Form 1 needs no such option: rendered plan JSON is recognized on
every path.

Agents hit the same gate through hook mode automatically on every file edit;
humans and CI call it directly as above. A `.tfstate` file is refused as a
proposal — state describes what *is*, not what is *proposed*, and judging it
as a change would approve the past instead of the future.

## Layout

- `gcp_grounding/core/` — vendored grounding core (Datalog engine, solver
  detection, four-bucket report model), copied verbatim from the
  [harness](https://github.com/cabal19421/harness) grounding engine; see each
  file's header for provenance. **Do not edit** — domain logic only
  instantiates it.
- `gcp_grounding/` — the GCP domain: snapshot knowledge base, claim extractors
  (IAM / org-policy JSON, Terraform plan JSON), Datalog reasoner, z3 constraint
  layer, report renderer, end-to-end preflight, CLI, changed-file gate, live
  snapshot fetchers. The current-state side lives in `facts.py`, `identity.py`,
  `redact.py`, `provenance.py`, `compare.py`, `merge.py`, `drift.py`,
  `estate.py`, `reconciled.py`, `sources.py`, `freshness.py`, `discovery.py`,
  `baseline.py`, `engine.py` and `explain_state.py`, with the terraform readers
  and mappers under `gcp_grounding/tfsource/`.
- `sec_requirements/` — the default requirements directory: markdown
  requirement documents (there is a `TEMPLATE.md`), which
  `gcp-ground compile-requirements` turns into `*.promises.json` artifacts.
- `tests/` — offline test suite; fixtures under `tests/fixtures/gcp/`. No
  network, no GCP credentials. z3-only assertions are not skipped when z3 is
  missing: the suite BRANCHES on the capability and asserts the honest
  degradation instead.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest -q tests/ -k gcp
```

## Running the demo

Everything below is fully offline — frozen fixture snapshots, no credentials,
no network. Run from the repo root after the Development setup above.

### The scenarios at a glance

| # | Scenario | Proposal | Expect |
| --- | --- | --- | --- |
| 1 | A violating terraform diff: world-open SSH + `roles/owner` to an outsider (step 7) | `examples/terraform/main.tf.json` | DENIED — two promises VIOLATED, each refutation naming its block |
| 2a | Custom-role swap meant to reduce scope; the accidental extra permission is harmless (step 8) | `examples/terraform-roles/proposal_a.tf.json` | APPROVED — with the `[iam_scope_diff]` warning naming the extra permission |
| 2b | The same swap, but the extra permission is `iam.serviceAccounts.actAs` (step 8) | `examples/terraform-roles/proposal_b.tf.json` | DENIED — the permission promise VIOLATED, custom-role block named |
| 3 | Masked deny removed — the dormant allow wakes up world-open (step 9) | `examples/terraform-masked/proposal.tf.json` | DENIED — exposure + shadow verdicts |
| 3b | The benign counterpart: deleting the dead allow instead (step 9) | `examples/terraform-masked/cleanup.tf.json` | DENIED — the restated deny still reads as killing the allow the state carries; deletion-awareness needs the pair tier's old-set-versus-new-set comparison, and this shape derives no baseline target for it to run against |
| 3c | Conditional approval: the deny's removal has applied, and the woken allow is narrowed to exactly the two audited partner ranges (step 9) | `examples/terraform-masked/narrowed.tf.json` | APPROVED — `masked-allow-only-known-domains` holds (the subset obligation grounds), with the exposure and pair checks green beside it |
| 3d | The smuggle: the two audited ranges plus one unaudited /28 (step 9) | `examples/terraform-masked/narrowed_extra.tf.json` | DENIED — `masked-allow-only-known-domains` VIOLATED, the refutation naming `source_range='10.198.52.0/28'`; both built-ins pass, only the promise catches it |
| 4 | The attribute the provider doesn't know: `src_ranges` for `source_ranges` (step 10) | `examples/terraform-schema/proposal_typo.tf.json` | DENIED — `[tf_attribute]` ungrounded, with the did-you-mean naming `source_ranges` |
| 4b | Version skew: an attribute absent from the captured provider schema (step 10) | `examples/terraform-schema/proposal_newer.tf.json` | DENIED — same finding, carrying the recapture guidance instead of a suggestion |
| 4c | The clean counterpart (step 10) | `examples/terraform-schema/proposal_ok.tf.json` | APPROVED — every attribute is in the captured schema, so the family stays silent |
| 4d | Policy configured, schema omitted (step 10) | `examples/terraform-schema/proposal_ok.tf.json`, no `--provider-schema` | APPROVED — with one honest `[tf_schema]` abstention naming what was not judged and the capture command |
| 5 | The org-policy rollback, compliant estate: eleven catalogue-named promises in force (step 11) | `examples/terraform-orgpolicy/base.tf.json` | APPROVED — all eleven promises hold |
| 5a | Serial console re-enabled + a VM allowed an external IP (step 11) | `examples/terraform-orgpolicy/proposal_serial_and_publicip.tf.json` | DENIED — `compute-disable-serialport-access` + `vm-public-ip-gcp` VIOLATED |
| 5b | Cloud Run ingress opened to `all` (step 11) | `examples/terraform-orgpolicy/proposal_run_ingress_public.tf.json` | DENIED — `run-allowed-ingress-internal-loadbalancing` + `cloudrun-ingress-non-public` VIOLATED |
| 5c | External VPC peering allowed + internet-NEG enforcement dropped (step 11) | `examples/terraform-orgpolicy/proposal_peering_and_neg.tf.json` | DENIED — `vpc-externally-peered-vpc-gcp` + `compute-disable-internet-neg` VIOLATED |
| 5d | Public-access prevention off + an outside contact domain (step 11) | `examples/terraform-orgpolicy/proposal_storage_contacts.tf.json` | DENIED — `public-access-prevention` + `security-contact-gcp` VIOLATED |
| 5e | `roles/owner` to an outsider + a token-creator grant (step 11) | `examples/terraform-orgpolicy/proposal_admin_impersonation.tf.json` | DENIED — `deny-admin-roles` + `iam-deny-service-account-impersonation` VIOLATED |
| 5f | An egress allow to `0.0.0.0/0` (step 11) | `examples/terraform-orgpolicy/proposal_egress_world.tf.json` | DENIED — `egress-firewall-policy-high-strength-vpc-firewall` VIOLATED, beside the built-in `[firewall_reopen]` |
| 5g | The benign counterpart: the ingress allowlist tightened (step 11) | `examples/terraform-orgpolicy/proposal_benign.tf.json` | APPROVED — a narrowing violates nothing; all eleven still hold |
| 6 | The deny that guarded the estate, compliant: guardrail + the dormant grant it masks + the org-policy restatement (step 12) | `examples/terraform-denypolicy/plan_base.json` | APPROVED — all three promises hold; the masked-grant warning and the INERT org finding recorded |
| 6a | The carve-out: payroll CI added to the guardrail's `exceptionPrincipals` (step 12) | `examples/terraform-denypolicy/plan_threading.json` | DENIED — both deny promises VIOLATED, the escaping (principal, permission) quoted verbatim; the threading warning beside them |
| 6b | The removal: a rendered plan deleting the deny policy — the dormant grant wakes (step 12) | `examples/terraform-denypolicy/plan_remove_deny.json` | DENIED — `[iam_deny_shadow]` contradicted, naming the woken grant and its escalation class; the promises abstain by name |
| 6c | The hygiene sweep: a folder-level `reset` that reads as a no-op (step 12) | `examples/terraform-denypolicy/plan_reset_payments.json` | DENIED — `sa-key-creation-stays-effectively-enforced` refuted over the effective collection, naming the folder node and the block |

Two variations worth showing live: rerun 4 with `--schema-policy annotate`
(the identical finding demoted to a warning at exit 0 — the hook-warns-while-
CI-blocks pattern), and add `--provider-schema` to scenario 1's command (a
valid configuration gains zero schema noise — its verdict counts are
byte-identical with and without the schema).

Steps 0–6 below are the non-terraform acts: the acceptance suite, compiling
the promises, the REST attack, the hallucination did-you-mean, shell-command
scanning, and the hook pair (attack blocks, benign is byte-silent).

```bash
# 0. The acceptance proof: the entire suite, including the agentic sessions
#    driven through the real hook and the armed mutation contract (~100s).
.venv/bin/python -m pytest -q tests/

# 1. Compile the demo security requirements — six plain-English promises —
#    into enforced rules. Vocabulary is grounded against the estate snapshot,
#    each formula is proven satisfiable AND non-tautological with z3, and a
#    compliant + violating witness pair is minted and pinned per promise.
#    EXPECTED TO EXIT 1: the corpus deliberately includes a booby-trapped
#    document naming the hallucinated roles/bigquery.reader, and a rejected
#    promise fails the compile loudly — that is the CI contract working.
#    The artifacts (including the rejection record) are still written.
.venv/bin/gcp-ground compile-requirements tests/fixtures/gcp/sec_requirements \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json --out demo/compiled

# 2. Read the promises back: English sentence -> enforcement status ->
#    compiled SMT rule -> pinned witnesses. Note the honest negatives: the
#    untranslated prose sentence stays NOT ENFORCED, and the promise naming
#    the hallucinated roles/bigquery.reader shows as REJECTED with the
#    compile's reason ("vocabulary is not grounded: roles/bigquery.reader
#    does not exist in the snapshot"). The did-you-mean suggestions are
#    step 1's compile-time output — the artifact carries the reason alone.
python3 show_promises.py demo/compiled

# 3. Block an attack: roles/owner granted to an external attacker. Exits 1
#    with the evidence — the principal provably absent from the snapshot,
#    the violated domain promise, and the escalation warning.
.venv/bin/gcp-ground verify-policy \
    tests/fixtures/gcp/agentic/iam/A10_owner_to_external.policy.json \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json \
    --requirements demo/compiled --explain

# 4. Hallucination with remediation: a made-up role fails existence
#    grounding and the report suggests the real name.
.venv/bin/gcp-ground verify-policy tests/fixtures/gcp/policies/iam_policy_bad.json \
    --snapshot tests/fixtures/gcp/snapshot.json

# 5. The side-door channel, both halves. A state-mutating gcloud invocation
#    bypasses the document gate entirely, so `scan-command` CLASSIFIES it
#    against the curated mutation tables and says so honestly — the banner
#    names the subcommand as audit-only and the report headlines
#    "PASSED — NOTHING VERIFIED (1 unchecked)", because nothing here verifies
#    or approves anything. Enforcement is the OTHER half: in hook mode
#    (the channel step 6 drives), --bash-policy (default: block) BLOCKS the
#    same command before it executes.
.venv/bin/gcp-ground scan-command --command \
    'gcloud projects add-iam-policy-binding acme-prod --member=user:x@evil.example --role=roles/owner'

# 6. Hook mode — the exact PostToolUse event the editor agent sends on a file
#    edit. The attack exits 2 (the blocking code) with findings on stderr;
#    a benign edit exits 0 in byte-for-byte silence.
printf '{"hook_event_name":"PostToolUse","tool_name":"Write","tool_input":{"file_path":"%s"}}' \
    "$PWD/tests/fixtures/gcp/agentic/iam/A10_owner_to_external.policy.json" \
  | GCP_GROUNDING_SNAPSHOT=tests/fixtures/gcp/agentic_snapshot.json \
    GCP_GROUNDING_REQUIREMENTS=demo/compiled \
    .venv/bin/gcp-ground verify-policy --hook; echo "exit=$?"

printf '{"hook_event_name":"PostToolUse","tool_name":"Write","tool_input":{"file_path":"%s"}}' \
    "$PWD/tests/fixtures/gcp/agentic/benign/iam_policy_conditional.json" \
  | GCP_GROUNDING_SNAPSHOT=tests/fixtures/gcp/agentic_snapshot.json \
    .venv/bin/gcp-ground verify-policy --hook; echo "exit=$?"
```

### 7. The terraform finale: every input named by its flag

The last step replays the whole pipeline over terraform. `examples/terraform/`
holds the clean infrastructure (`base.tf.json`, with `terraform.tfstate` as its
applied state) and `main.tf.json` — the same configuration after an agent, or a
hurried human, added exactly two blocks:

```diff
 main.tf.json, against base.tf.json — the two added blocks
+"allow_ssh_world": {
+  "allow": [{"ports": ["22"], "protocol": "tcp"}],
+  "direction": "INGRESS",
+  "name": "allow-ssh-from-anywhere",
+  "network": "projects/acme-prod/global/networks/prod-vpc",
+  "priority": 800,
+  "project": "acme-prod",
+  "source_ranges": ["0.0.0.0/0"]        <- tcp/22 open to the world
+}
...
+"contractor_owner": {
+  "members": ["user:mallory@outsider.example"],
+  "project": "acme-prod",
+  "role": "roles/owner"                 <- roles/owner to an outsider
+}
```

One command grounds the change, and each of the five inputs is one flag:

- `--snapshot` — the API snapshot: what is real and live in the estate;
- `--terraform-state` — the current state as captured in IaC;
- `--requirements` — the promises compiled from `sec_requirements` (step 1
  wrote them to `demo/compiled`);
- `--proposal` — the proposed change, agent- or human-authored;
- `--explain` — the decision narrative.

```bash
# 7. The terraform finale. EXPECTED TO EXIT 1: the two added blocks are the
#    finding. (Run step 1 first — --requirements reads what it compiled.)
.venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform/main.tf.json \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json \
    --terraform-state examples/terraform/terraform.tfstate \
    --requirements demo/compiled \
    --explain
```

What you see, in the narrative's own reading order: **what was proposed** — the
document as `a terraform configuration (8 resources)`, one line per resource
address; the decision — **DENIED (exit 1)**, on BOTH violating blocks at once.
The compiled promise `no-open-ssh-rdp-ingress` is **VIOLATED** — the stanza
quotes its English sentence, *"No ingress firewall rule may allow tcp/22 or
tcp/3389 from 0.0.0.0/0."*, and its refutation names the terraform block to
edit (`google_compute_firewall.allow_ssh_world`) — and `[firewall_exposure]`
names the same block as reachable on tcp/22 from a public source. The owner
grant violates `no-primitive-roles-outside-domain` the same way: its refutation
reads `refuted by iam_bindings[1] (google_project_iam_binding.contractor_owner)
member='user:mallory@outsider.example' role='roles/owner'` — the block, the
member and the role, rebuilt from the proposal's own terraform claims. Four of
the six promise domains are exercised by this run — the firewall and iam
promises refute, the perimeter promise reports that it *holds*, and so does
`sa-key-creation-disabled`, because the proposal's `no_sa_keys` block enforces
the constraint. (The remaining two domains, `cloud_armor` and `hier_firewall`,
have no promise in the demo corpus and nothing in this proposal exercises
them.) The owner grant still
draws the `[iam_escalation]` warning on `contractor_owner` (roles/owner to
`user:mallory@outsider.example`), and the `[subset]` widening note stays
honestly unverified: the baseline came from terraform state, terraform
enumerates only what terraform manages, and a never-complete baseline "cannot
tell a real widening from a row that view never saw" — the gate's own words —
instead of manufacturing certainty. What still abstains, stated rather than
papered over: pair-tier promises (they need the old/new pair this run does not
supply), and every shape the conservative terraform extraction refuses to
guess at — a block whose `count`/`for_each` multiplicity is undecided, an
org-policy rule set through `allow_all`/`deny_all`, a condition-mentioning
promise over a binding whose condition the claims could not pin — each is a
named abstention, never a fabricated row, because a fabricated row could
fabricate a refutation.

### 8. Scenario two: the custom-role swap

An operator swaps a binding's predefined role for a custom role defined in the
same change, intending to reduce its permission scope — but the custom role
accidentally includes one permission the predefined role never granted. In
case A that extra permission has no consequence, and in case B it violates a
compiled promise. `examples/terraform-roles/` holds the pieces: `base.tf.json`
grants `roles/bigquery.dataViewer` (four snapshot-enumerated permissions) to
`group:data-eng@acme.example`, `terraform.tfstate` is that binding as current
state, and each proposal swaps in `projects/acme-prod/roles/dataViewerScoped` —
three of the predefined role's four permissions plus exactly one extra
(`bigquery.jobs.create` in `proposal_a.tf.json`; `iam.serviceAccounts.actAs`,
an escalation-class permission, in `proposal_b.tf.json`). The scenario has its
own one-promise requirements corpus in the same directory — *"No role may
include the permission iam.serviceAccounts.actAs."*, quantified over the
proposal's own custom-role permission rows — compiled separately from step 1's
corpus (exit 0: nothing in it is booby-trapped; the compiled artifacts are not
committed):

```bash
# 8. Compile the scenario corpus, then judge both proposals.
.venv/bin/gcp-ground compile-requirements examples/terraform-roles \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json --out demo/compiled-roles

# 8a. Case A — EXPECTED TO EXIT 0: the accident is surfaced, not blocked.
.venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform-roles/proposal_a.tf.json \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json \
    --terraform-state examples/terraform-roles/terraform.tfstate \
    --requirements demo/compiled-roles \
    --explain

# 8b. Case B — EXPECTED TO EXIT 1: the same accident now breaks a promise.
.venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform-roles/proposal_b.tf.json \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json \
    --terraform-state examples/terraform-roles/terraform.tfstate \
    --requirements demo/compiled-roles \
    --explain
```

**Case A is APPROVED (exit 0) with the accident surfaced.** The scope-diff
check found the same binding in the terraform state, diffed the custom role's
permissions against the predefined role's snapshot enumeration, and the
`[iam_scope_diff]` warning leads the decision block's abstention taste: *swaps
`roles/bigquery.dataViewer` for `projects/acme-prod/roles/dataViewerScoped`
(`google_project_iam_custom_role.data_viewer_scoped`) … adds 1 permission(s)
roles/bigquery.dataViewer never granted: `bigquery.jobs.create` — the swap is
not only a scope reduction* — "reducing scope" verified as mostly-true, the
one extra named, the custom-role block to review named, and nothing blocked:
consequence is the promise layer's job, and no promise mentions
`bigquery.jobs.create`. (In this demo the warning rides through as an
abstention rather than a clean `grounded`, because the fixture snapshot's
roles are past the freshness limit and drift adjudication refuses to rest a
clean answer on a stale fact — the message is identical either way.)

**Case B is DENIED (exit 1).** The identical swap shape, but the extra is
`iam.serviceAccounts.actAs`, so the compiled promise is **VIOLATED** — the
stanza quotes *"No role may include the permission
iam.serviceAccounts.actAs."* and the refutation names the block to edit:
`refuted by proposed_role_permissions[3]
(google_project_iam_custom_role.data_viewer_scoped)
permission='iam.serviceAccounts.actAs'
role='projects/acme-prod/roles/dataViewerScoped'`. The same `[iam_scope_diff]` warning
appears with the extra annotated as `(impersonation)` — the escalation class
the accident would have handed to every member of the binding. What still
abstains, stated rather than papered over: the binding's role existence (the
custom role is being created by this very change, so the snapshot cannot know
it) and the `[subset]` widening note, both for the same partial-view reasons
as the terraform finale. A REST document, for the record, simply cannot
exercise this promise: no REST document kind carries a custom role's
permission list, and the rule abstains naming that fact instead of passing
vacuously.

### 9. Scenario three: the masked deny

The estate has carried a world-open RDP allow for years and nobody noticed,
because a higher-precedence deny masks it: `allow-rdp-broad` (allow tcp/3389
from 0.0.0.0/0, priority 1000) is dead — every packet it matches is decided
first by `deny-external-rdp` (deny tcp/3389 from 0.0.0.0/0, priority 900). A
refactor accidentally drops the deny block, and the dormant rule wakes up
world-open. `examples/terraform-masked/` holds the pieces: `base.tf.json`
declares the pair exactly as `terraform.tfstate` carries it,
`proposal.tf.json` is the accident (base minus the deny block) and
`cleanup.tf.json` is the intended fix (base minus the dead allow). The three
runs of the original arc use no promise corpus — every 9a–9c verdict comes
from the built-in estate checks, so they carry no compile step and no
`--requirements` flag (the conditional-approval arm at 9d–9f below adds the
scenario's own corpus for its two extra runs):

```bash
# 9a. The current state itself — EXPECTED TO EXIT 1: a masked pair is
#     hygiene debt, and the gate names it from both directions on arrival.
.venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform-masked/base.tf.json \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json \
    --terraform-state examples/terraform-masked/terraform.tfstate \
    --explain

# 9b. The accident (deny removed) — EXPECTED TO EXIT 1: the dormant allow
#     wakes up world-open, and the gate tells both halves of the story.
.venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform-masked/proposal.tf.json \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json \
    --terraform-state examples/terraform-masked/terraform.tfstate \
    --explain

# 9c. The cleanup (dead allow removed) — EXPECTED TO EXIT 1 TOO, honestly:
#     deletions are invisible without the pair tier, so the restated deny
#     still reads as killing the allow the state carries.
.venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform-masked/cleanup.tf.json \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json \
    --terraform-state examples/terraform-masked/terraform.tfstate \
    --explain
```

**9a — the base is DENIED (exit 1), three findings.** Run the *current*
configuration through the gate and the masked pair is named from both
directions. `[firewall_exposure]` reads one rule's own text — no snapshot, no
baseline, no other rule — and the allow's text is world-open on a sensitive
port: *"a public source (…) can reach tcp/3389 through this rule"* (the
witness address is a solver-minted example, not a constant of the rule —
nothing should pin it). `[firewall_shadow]`
folds the captured estate and answers the question a diff cannot — does this
rule do anything at all: the allow is *"unreachable — every packet this rule
matches is already decided by higher-precedence rule(s) deny-external-rdp;
the rule has no effect"*, and the restated deny draws the mirror finding,
*"this deny at priority 900 makes the existing allow 'allow-rdp-broad' at
priority 1000 unreachable"*. Had this gate been standing when the pair first
landed, the hygiene debt would never have arrived.

**9b — the accident is DENIED (exit 1), and the two findings tell the whole
story between them.** The exposure finding is the *after*: nothing in the
proposed document decides tcp/3389 ahead of the allow anymore, and its own
text admits every public source. The shadow finding is the *before*: the
estate fold still holds `deny-external-rdp` — the very rule this change
deletes — so the same allow is also *"unreachable … already decided by …
deny-external-rdp"* today. Dead today, world-open the moment this applies.
Note what the gate does NOT say: there is no *"you removed deny-external-rdp"*
line — that pair-tier articulation (old set versus new set) runs only where a
baseline target is derived for the document, which this scenario's shape does
not produce (the pair tier itself is verified end to end by the
`tf_block`/`tf_drift` suites). The deny's absence is never named; what is
named is what its absence leaves behind — the exposure check condemns the
allow from its own text (as 9a shows, it does so even while the deny still
stands beside it), and with the deny gone from the document nothing softens
that verdict's meaning: the allow is simply live.

**9c — the cleanup is DENIED (exit 1) too, and that is this scenario's honest
sharp edge.** Deleting the dead allow *narrows* the estate and was expected
to approve; empirically it does not, for the same reason 9b works at all:
deletions are invisible to a gate without the pair tier. The cleanup restates
the deny (a terraform configuration declares everything it keeps), the estate
fold still carries `allow-rdp-broad`, and the restated deny draws the same
kill-report the base drew: *"this deny at priority 900 makes the existing
allow 'allow-rdp-broad' at priority 1000 unreachable"* — its only blocking
finding. That sentence is true of today's estate — it is the mask itself,
re-discovered — but attributing it to the document that merely restates the
deny over-blocks the benign fix. Until the pair tier lands, a masked pair has
no clean one-sided exit: any document restating either rule draws a finding,
and the gate's conservative failure mode is a loud block, never a silent
pass. The abstention noise is the usual fixture-snapshot taste — staleness,
the two provenance notes, the network-existence abstention — plus one honest
*"no offline check is wired for claim kind 'firewall_rule'"* on the deny,
none of them deciding anything here.

**The conditional-approval arm (9d–9f): the deny is coming out anyway — on
what condition may the woken allow stay?** The incident review accepts the
accident as fact: `terraform-after-removal.tfstate` is the post-accident state
(serial 13, same lineage — the deny applied-gone, the woken allow world-open),
and the remediation question is what may replace the world-open text. The
review's condition: the allow may admit **only the two known domains**. A GCP
firewall has no DNS-domain concept, so the two domains are modeled as the two
audited partner networks' CIDR blocks — `10.198.51.0/24` and `10.203.113.0/26`,
private ranges reached over the partner interconnect (deliberately private:
tcp/3389 open to a genuinely public range would rightly draw the built-in
exposure finding no matter what any promise says). That condition is a subset
relation — the rule's `source_ranges` must sit inside the union of the two
blocks — and it compiles to a z3-checked promise in the scenario's own
one-promise corpus, `requirements.md` in the same directory, scenario-two
style (compiled separately from step 1's corpus; the artifacts are not
committed). The corpus states its own honesties: subset is spelled per range
row as "contains the partner block's base address AND carries a mask at least
as specific" — sound in the refuting direction (a range reaching beyond either
block always refutes; `0.0.0.0/0`'s zero mask fails the unsigned mask compare,
so the world-open shape itself is refuted wherever this corpus is in force)
and exact for base-anchored subranges, while a subset not anchored at a
partner base (say `10.198.51.128/25`) is conservatively refuted rather than
admitted. The 9a–9c commands above take no `--requirements` and their
documented outputs are unchanged.

```bash
# 9d. Compile the scenario corpus — EXPECTED TO EXIT 0: the one promise
#     grounds and admits (nothing here is booby-trapped).
.venv/bin/gcp-ground compile-requirements examples/terraform-masked \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json --out demo/compiled-masked

# 9e. The remediation — EXPECTED TO EXIT 0: the allow narrowed to exactly
#     the two audited partner ranges, judged with the promise in force.
.venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform-masked/narrowed.tf.json \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json \
    --terraform-state examples/terraform-masked/terraform-after-removal.tfstate \
    --requirements demo/compiled-masked \
    --explain

# 9f. The smuggle — EXPECTED TO EXIT 1: the two audited ranges PLUS one
#     unaudited /28 that reads like a typo of partner A's block.
.venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform-masked/narrowed_extra.tf.json \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json \
    --terraform-state examples/terraform-masked/terraform-after-removal.tfstate \
    --requirements demo/compiled-masked \
    --explain
```

**9e — the remediation is APPROVED (exit 0), and the approval is a judgment,
not an absence of findings.** The narrative carries `promises in force
(1 enforcing, 0 not — from demo/compiled-masked)` with a `holds` stanza
quoting the sentence and the compiled subset rule, and the check listing shows
all three deciders green:

```text
✓ [firewall_exposure] google_compute_firewall.allow_rdp_broad: no public
    source reaches a sensitive port
✓ [firewall_pair] examples/terraform-masked/narrowed.tf.json: the new rule
    set allows no packet the old set denied
✓ [sec:vpc_firewall] masked-allow-only-known-domains: the obligation holds
    over the document — grounded
```

Note the pair tier RUNNING here, unlike 9a–9c: with the post-accident state
holding exactly the one rule, the document's block resolves a baseline target
(`[tf-address] resolved`) and the old-set-versus-new-set comparison confirms
the narrowing from the other direction. The abstention taste is the usual
fixture-snapshot noise — staleness, the two provenance notes, the
network-existence abstention — none of it deciding anything. (The `holds`
stanza also reprints the promise's pinned compliant/violating witness pair;
those are compile-time solver models, masked `(…)` here as ever — nothing
should pin them.) The closing summary is the approval's other shape, and it
keeps the qualifier rather than printing the bare word:

```text
decision recap: APPROVED (exit 0) — grounded=4 unchecked=4 (narrative above)

summary — what just happened:
  terraform state on disk : examples/terraform-masked/terraform-after-removal.tfstate [cli]
  promises in force       : 1 enforcing, 0 not — from demo/compiled-masked [cli]
      (masked-allow-only-known-domains)
  provider                : no schema configured — resource shapes not checked
  proposed change         : examples/terraform-masked/narrowed.tf.json —
      a terraform configuration (1 resource): 1 google_compute_firewall
  result                  : APPROVED — 4 unchecked (exit 0)
```

**9f — the smuggle is DENIED (exit 1), and the promise is the only thing that
catches it.** The extra `10.198.52.0/28` is private, so the exposure check
grounds; the new set is still a strict narrowing of the world-open state the
accident left behind, so the pair check grounds too. Only the subset
obligation refuses, and the refutation witness names the offending range and
the block to edit:

```text
decision recap: DENIED (exit 1) — because:
  ⚠ [sec:vpc_firewall] masked-allow-only-known-domains: refuted by
      proposed_firewall_rules[1] (google_compute_firewall.allow_rdp_broad)
      action='allow' direction='INGRESS' … name='allow-rdp-broad' …
      source_range='10.198.52.0/28' source_range_mask='255.255.255.240' …
(the full narrative is above, before the report)

summary — what just happened:
  terraform state on disk : examples/terraform-masked/terraform-after-removal.tfstate [cli]
  promises in force       : 1 enforcing, 0 not — from demo/compiled-masked [cli]
      (masked-allow-only-known-domains)
  provider                : no schema configured — resource shapes not checked
  proposed change         : examples/terraform-masked/narrowed_extra.tf.json —
      a terraform configuration (1 resource): 1 google_compute_firewall
  result                  : DENIED (exit 1)
    it violated these promises: masked-allow-only-known-domains
```

(the elided fields are the row's remaining constants — unlike a solver-minted
witness address, everything in this refutation is quoted from the document
itself, which is why the offending range can be named verbatim)

### 10. Scenario four: the attribute the provider doesn't know

An agent renames a firewall's source filter to `src_ranges`; a colleague uses
an attribute their newer provider documents and this checkout's pinned
provider has never heard of. Both changes ground clean against the estate
snapshot — roles, members and permissions all real — and both would die at
`terraform plan`. `examples/terraform-schema/` holds the pieces:
`provider-schema.json` is a captured `terraform providers schema -json` for
the `google` provider (six resource types: the three this scenario uses plus
the three the scenario-1 variation touches — the extras are what let that
variation run with zero schema noise — hand-authored here faithfully to the
real shape; in your own repo, capture it from the init'd checkout with
`terraform providers schema -json > provider-schema.json` and refresh it when
`.terraform.lock.hcl` changes),
`proposal_ok.tf.json` is a clean change (a health-check firewall rule, a
binding, a custom role), `proposal_typo.tf.json` is the same change with
`src_ranges` for `source_ranges`, and `proposal_newer.tf.json` adds a `params`
block the captured schema does not define. It is a raw capture, so the
provider version is honestly unknown — the findings say "the captured
provider schema" and name no release:

```bash
# 10a. The typo — EXPECTED TO EXIT 1: the captured provider cannot accept it,
#      and the did-you-mean names the real attribute.
.venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform-schema/proposal_typo.tf.json \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json \
    --provider-schema examples/terraform-schema/provider-schema.json \
    --explain

# 10b. The version skew — EXPECTED TO EXIT 1 TOO, with the recapture guidance
#      instead of a suggestion: nothing in the captured schema is close.
.venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform-schema/proposal_newer.tf.json \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json \
    --provider-schema examples/terraform-schema/provider-schema.json \
    --explain

# 10c. The clean counterpart — EXPECTED TO EXIT 0.
.venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform-schema/proposal_ok.tf.json \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json \
    --provider-schema examples/terraform-schema/provider-schema.json \
    --explain
```

**10a is DENIED (exit 1) on the typo alone**, and the recap — the last lines
on your terminal — is the finding:

```text
decision recap: DENIED (exit 1) — because:
  ✗ [tf_attribute] google_compute_firewall.allow_health_checks: 'src_ranges'
      is not an attribute or nested block of google_compute_firewall in the
      captured provider schema — 'terraform plan' under the provider this
      schema was captured from would refuse it
(the full narrative is above, before the report)

summary — what just happened:
  terraform state on disk : none configured
  promises in force       : none loaded
  provider                : examples/terraform-schema/provider-schema.json
      [cli] — google, 6 resource types
  proposed change         : examples/terraform-schema/proposal_typo.tf.json —
      a terraform configuration (3 resources): 1 google_compute_firewall,
      1 google_project_iam_binding, 1 google_project_iam_custom_role
  result                  : DENIED (exit 1)
    blocked by 1 built-in finding: [tf_attribute]
```

— note what the summary does NOT say: no requirements are configured in this
scenario, so nothing is claimed about promises, and the denial is reported as
a built-in finding, which is what it is.

with the report line above it carrying the remediation: `(did you mean:
source_ranges?)`. Note the honest side-effect in the abstentions: with
`source_ranges` misspelled the rule *has* no source filter, so
`[firewall_exposure]` abstains on "an illegal GCP shape" rather than guessing
what the typo meant.

**10b is DENIED (exit 1) the same way**, but nothing in the schema is within
edit distance of `params`, so instead of a suggestion the finding carries the
version-skew guidance:

```text
  ✗ [tf_attribute] google_compute_firewall.allow_health_checks: 'params' is
      not an attribute or nested block of google_compute_firewall in the
      captured provider schema — 'terraform plan' under the provider this
      schema was captured from would refuse it; if 'params' arrived in a
      provider NEWER than the captured schema, recapture it where terraform
      init has run (terraform providers schema -json > provider-schema.json)
      and re-judge
```

— the gate cannot tell a hallucination from tomorrow's provider, and does not
pretend to: it says the *captured* provider refuses it, and names the one
command that re-decides the question against a newer capture.

**10c is APPROVED (exit 0)**: every attribute and nested block resolves in the
captured schema, so the family adds nothing — `decision recap: APPROVED (exit
0) — grounded=8 unchecked=6` — and the abstentions are the usual
fixture-snapshot taste (staleness, unqueried baselines, the network-existence
abstention).

The fourth run is the one WITHOUT a schema. Configure nothing at all and the
family is byte-silent (off-by-absence: the report only claims what it
checked); configure the *policy* while supplying no schema and the gate
abstains by name instead of passing in silence:

```bash
# 10d. No schema supplied — EXPECTED TO EXIT 0, with the honest abstention.
.venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform-schema/proposal_ok.tf.json \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json \
    --schema-policy block
```

```text
  ? [tf_schema] a schema policy is configured ('block') but NO provider schema
      is supplied — 3 google_* resource block(s) were NOT judged against any
      provider schema. Capture one, locally and credential-free, where
      terraform init has already run (terraform providers schema -json >
      provider-schema.json), then name it with --provider-schema,
      $GCP_GROUNDING_PROVIDER_SCHEMA or the 'provider_schema' key in
      .gcp-grounding.json
```

### 11. Scenario five: the org-policy rollback

This scenario's promise corpus stands in for **your own compiled promises**:
its eleven promise ids are an organisation's own control names respelled into
the artifact id grammar — promise ids admit `[a-z0-9-]` only, so each
catalogue underscore becomes a hyphen, a one-to-one mapping the corpus states
up front — and every refutation below reads back in the catalogue's vocabulary — swap `--requirements` at will, and note that three of
the eleven controls are deliberately **not** org policies (one VPC-firewall
egress control and two IAM controls), because "no egress to the world" and "no
admin grants" are facts about firewall rules and bindings, not about
`google_org_policy_policy` resources — the corpus models each control in the
domain the engine actually judges it in.

`examples/terraform-orgpolicy/` holds the pieces: `snapshot.json` is the
scenario's estate snapshot (the constraint vocabulary the eight org-policy
controls ground against, plus the roles and principals the IAM promises and
the estate's own names need), `cmm_demo.md` is the corpus,
`base.tf.json` (with `terraform.tfstate` as its applied state) is a compliant
estate — eight constraints correctly set at the org and project nodes, a
modest VPC whose only world-facing egress rule is a deny, bindings with no
admin grants — and each `proposal_*.tf.json` is that estate after one small,
realistic, bad edit. Two modelling honesties, stated in the corpus itself
rather than papered over: the conservative terraform extraction abstains by
name on `allow_all`/`deny_all` rules, so this estate spells "deny all external
IPs" as an **empty allowlist** (the most restrictive list there is); and the
flattened `org_policy_rules` rows do not record which *side* of a list a value
sat on, so the list-shaped promises judge values-on-the-policy — stricter than
their sentences, over-blocking rather than under-blocking.

```bash
# 11. Compile the scenario corpus — EXPECTED TO EXIT 0: all eleven promises
#     ground and admit (nothing in this corpus is booby-trapped).
.venv/bin/gcp-ground compile-requirements examples/terraform-orgpolicy \
    --snapshot examples/terraform-orgpolicy/snapshot.json --out demo/compiled-orgpolicy

# 11a. The compliant estate itself — EXPECTED TO EXIT 0, with every one of the
#      eleven promises reported as holding.
.venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform-orgpolicy/base.tf.json \
    --snapshot examples/terraform-orgpolicy/snapshot.json \
    --terraform-state examples/terraform-orgpolicy/terraform.tfstate \
    --requirements demo/compiled-orgpolicy \
    --explain
```

The base run's narrative shows the whole corpus in force — `promises in force
(11 enforcing, 0 not — from demo/compiled-orgpolicy)`, then eleven `holds`
stanzas — and ends `decision recap: APPROVED (exit 0)`. Each violating
proposal is the same command with the proposal swapped in; every one is
**EXPECTED TO EXIT 1**, and the recap names the violated controls by their
catalogue ids:

```bash
# 11b. Serial console re-enabled + a legacy VM allowed an external IP.
.venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform-orgpolicy/proposal_serial_and_publicip.tf.json \
    --snapshot examples/terraform-orgpolicy/snapshot.json \
    --terraform-state examples/terraform-orgpolicy/terraform.tfstate \
    --requirements demo/compiled-orgpolicy \
    --explain
```

```text
decision recap: DENIED (exit 1) — because:
  ⚠ [sec:org_policy] compute-disable-serialport-access: refuted by
      org_policy_rules[1] (google_org_policy_policy.serial_port_disabled)
      constraint='compute.disableSerialPortAccess' enforce=False …
  ⚠ [sec:org_policy] vm-public-ip-gcp: refuted by org_policy_rules[3]
      (google_org_policy_policy.vm_no_external_ip)
      constraint='compute.vmExternalIpAccess' … is_list=True
      value='projects/acme-prod/zones/us-central1-a/instances/legacy-bastion'
(the full narrative is above, before the report)

summary — what just happened:
  terraform state on disk : examples/terraform-orgpolicy/terraform.tfstate [cli]
  promises in force       : 11 enforcing, 0 not — from demo/compiled-orgpolicy
      [cli] (cloudrun-ingress-non-public, compute-disable-internet-neg,
      compute-disable-serialport-access, deny-admin-roles,
      egress-firewall-policy-high-strength-vpc-firewall, +6 more)
  provider                : no schema configured — resource shapes not checked
  proposed change         : examples/terraform-orgpolicy/proposal_serial_and_publicip.tf.json
      — a terraform configuration (13 resources): 7 google_org_policy_policy,
      3 google_compute_firewall, 2 google_project_iam_binding,
      1 google_compute_network
  result                  : DENIED (exit 1)
    it violated these promises: compute-disable-serialport-access,
      vm-public-ip-gcp
```

— the flipped `enforce` refutes the serial-port control, and under deny-all
the single enumerated instance *is* the violation of the external-IP control:
an exception being carved. The other five proposals follow the same shape
(swap the `--proposal` path; everything else is identical):

- `proposal_run_ingress_public.tf.json` — `run.allowedIngress` gains the value
  `all`. One added value, two named controls: the recap carries both
  `run-allowed-ingress-internal-loadbalancing` and
  `cloudrun-ingress-non-public` refutations, each quoting
  `(google_org_policy_policy.run_ingress_internal) … value='all'` — the
  catalogue keeps "stay internal" and "never public" as separate controls, and
  the gate reports in the catalogue's own granularity.
- `proposal_peering_and_neg.tf.json` — the peering allowlist gains
  `under:organizations/999999999999` (someone else's organization) and the
  internet-NEG policy drops to `enforce=FALSE`: refutes
  `vpc-externally-peered-vpc-gcp` and `compute-disable-internet-neg`.
- `proposal_storage_contacts.tf.json` — `storage.publicAccessPrevention` drops
  to `enforce=FALSE` and the essential-contacts allowlist gains
  `@contractor-mail.example`: refutes `public-access-prevention` and
  `security-contact-gcp`.
- `proposal_admin_impersonation.tf.json` — a binding grants `roles/owner` to
  `user:mallory@outsider.example` and another grants
  `roles/iam.serviceAccountTokenCreator`: refutes `deny-admin-roles` and
  `iam-deny-service-account-impersonation`, each refutation naming the binding
  block, the member and the role. (Over a fresh snapshot the outsider also
  draws the `✗ [principal] … does not exist in the snapshot` hallucination
  block beside the promise refutations.)
- `proposal_egress_world.tf.json` — a "temporary vendor sync" firewall rule
  allows egress to `0.0.0.0/0`. The compiled promise and a built-in estate
  check condemn it from two directions at once:

```text
decision recap: DENIED (exit 1) — because:
  ⚠ [firewall_reopen] google_compute_firewall.egress_vendor_sync: this allow
      at priority 900 re-opens traffic that the existing deny
      'deny-egress-world' at priority 65534 blocks — e.g. src (…); dst (…);
      protocol 6; port 443
  ⚠ [sec:vpc_firewall] egress-firewall-policy-high-strength-vpc-firewall:
      refuted by proposed_firewall_rules[1]
      (google_compute_firewall.egress_vendor_sync) action='allow'
      destination_range='0.0.0.0/0' … direction='EGRESS' …
(the full narrative is above, before the report)

summary — what just happened:
  terraform state on disk : examples/terraform-orgpolicy/terraform.tfstate [cli]
  promises in force       : 11 enforcing, 0 not — from demo/compiled-orgpolicy
      [cli] (cloudrun-ingress-non-public, compute-disable-internet-neg,
      compute-disable-serialport-access, deny-admin-roles,
      egress-firewall-policy-high-strength-vpc-firewall, +6 more)
  provider                : no schema configured — resource shapes not checked
  proposed change         : examples/terraform-orgpolicy/proposal_egress_world.tf.json
      — a terraform configuration (14 resources): 7 google_org_policy_policy,
      4 google_compute_firewall, 2 google_project_iam_binding,
      1 google_compute_network
  result                  : DENIED (exit 1)
    it violated these promises: egress-firewall-policy-high-strength-vpc-firewall
    blocked by 1 built-in finding: [firewall_reopen]
```

— the two-directions story restated in one place: the promise refutation under
"it violated these promises", the estate check under the built-in count, and
neither reported as the other.

(the `(…)` hold solver-minted witness addresses — an example packet through
the overlap, not constants of the rule, so nothing should pin them)

The contrast run is a *benign* org-policy edit — the Cloud Run ingress
allowlist tightened to `internal` alone, a strict narrowing:

```bash
# 11c. The benign counterpart — EXPECTED TO EXIT 0: tightening a list
#      constraint violates nothing, and all eleven promises still hold.
.venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform-orgpolicy/proposal_benign.tf.json \
    --snapshot examples/terraform-orgpolicy/snapshot.json \
    --terraform-state examples/terraform-orgpolicy/terraform.tfstate \
    --requirements demo/compiled-orgpolicy \
    --explain
```

One freshness note, because this scenario ships its own snapshot: its
`captured_at` is fixed (2026-07-25, the same fixture era as the demo estate),
so run at today's wall clock it sits past the 7-day ceiling and the run
carries the loud `? [staleness]` abstention demoting the snapshot's
categories. That is the ceiling working as designed — staleness abstains, it
never blocks, and the promise refutations judge the proposal's own content, so
every exit code above holds either way (the suite's own runs pin the clock
with `GCP_GROUNDING_NOW`, the package's documented CI answer). What a stale
snapshot costs is the hallucination findings: recapture — never `--max-age
off` — is the fix, exactly as the abstention says.

### 12. Scenario six: the deny that guarded the estate

The payments estate's only real protection for token minting is an IAM deny
policy: `guard-token-mint`, attached at `projects/acme-pay-prod`, denies the
two token-mint permissions (`iam.serviceAccounts.getAccessToken` /
`.getOpenIdToken`) to `principalSet://goog/public:all`. Under it sits a
DORMANT grant — `roles/iam.serviceAccountTokenCreator` to the payroll CI
service account — that the deny keeps fully inert, and above it an org-level
`iam.disableServiceAccountKeyCreation` policy whose constraint carries the
captured managed default `ALLOW`. `examples/terraform-denypolicy/` holds the
pieces: `snapshot.json` is the captured estate (the deny policy in the new
`iam_deny_policies` record table, the dormant grant in `iam_bindings`, the
org→`folders/665544332211`→two-projects hierarchy, the org policy and the
constraint's default), `requirements.md` is the scenario's three-promise
corpus, and each `plan_*.json` is a **rendered plan** — deliberately, twice
over: a deletion is visible only in a plan's `resource_changes`
(`change.before` is what the wake computation reads — the pair-tier gap that
over-blocks scenario three's cleanup has no purchase here), and the estate
judgments below read the snapshot's own captured categories, which the
snapshot-only route licenses as captured-complete. For the same reason the
commands pin `GCP_GROUNDING_NOW` to the fixture's capture era: the wake and
fold judgments are estate reads a stale snapshot may not license, so at
today's wall clock the staleness ceiling would honestly demote them to
abstentions (run 12c would *pass*, saying why) — the pin is the suite's own
documented CI mechanism, not a trick. One layout honesty, because
auto-detection is real: this directory ships no tfstate and no
`.origins.json` sidecar on purpose — a state artifact beside the proposal
would be discovered and re-route the run onto the merged-coverage path, whose
provenance rules deliberately withhold the existence licence a hand-captured
estate table cannot earn.

The corpus (compiled separately, scenario-two style; artifacts not
committed): `every-deny-covers-token-creation` is the strongest judgeable
spelling of "the guardrail stands" — an `assert_satisfiable` over the
`deny_rules` collection demanding the token permission denied to the public
set with `has_principal_exceptions=false` and `has_condition=false`. Because
`exceptionPermissions` are subtracted before rows exist, a policy that denies
the permission and excepts it back has no satisfying row; because principal
carve-outs are not subtractable, they surface as the flag instead.
`no-principal-threads-the-guardrail` is its refute-mode partner over
`deny_rule_exceptions`: any carve-out row refutes it, quoting the principal
verbatim, while an exception-free policy grounds *with* the observed-empty
attestation ("every deny rule was read and none carries a principal
exception") rather than passing over records nobody read.
`sa-key-creation-stays-effectively-enforced` is estate-tier, judged over
`effective_org_policy_bool` — the folded effective state at the proposal's
node and every captured descendant.

```bash
# 12. Compile the scenario corpus — EXPECTED TO EXIT 0: all three promises
#     ground and admit (nothing here is booby-trapped).
.venv/bin/gcp-ground compile-requirements examples/terraform-denypolicy \
    --snapshot examples/terraform-denypolicy/snapshot.json --out demo/compiled-denypolicy

# 12a. The compliant estate — EXPECTED TO EXIT 0: all three promises hold,
#      and the guardrail is visible from three directions at once.
GCP_GROUNDING_NOW=2026-07-18T12:00:00Z .venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform-denypolicy/plan_base.json \
    --snapshot examples/terraform-denypolicy/snapshot.json \
    --requirements demo/compiled-denypolicy \
    --explain
```

**12a — the base is APPROVED (exit 0), and the approval is three judgments,
not silence.** The narrative carries `promises in force (3 enforcing, 0 not —
from demo/compiled-denypolicy)` with all three `holds` stanzas, and the check
listing shows the guardrail working from every side — the masked-grant
warning (riding on `grounded`: a masked grant is not an exposure, and
blocking it would block a safe state) and the INERT org finding (loud on
purpose — a restatement that changes nothing is a signal reviewers need):

```text
✓ [iam_deny_shadow] google_project_iam_binding.payroll_ci_token_creator:
    warning — rule 0 of google_iam_deny_policy.guard_token_mint masks
    iam.serviceAccounts.getAccessToken (impersonation),
    iam.serviceAccounts.getOpenIdToken (impersonation) granted to
    serviceAccount:payroll-ci@acme-pay-prod.iam.gserviceaccount.com: the
    grant lands but is inert — the entire grant is inert; a masked grant is
    not an exposure, and removing the deny rule would wake it
✓ [org_effective] google_org_policy_policy.sa_key_guard: this change is
    INERT — it restates the effective state of
    constraints/iam.disableServiceAccountKeyCreation already in force at
    organizations/123456789012, and the effective state is unchanged at
    every node it governs (4 node(s))
✓ [sec:iam] no-principal-threads-the-guardrail: the obligation holds over
    the document — grounded; the deny document under review: every deny rule
    was read and none carries a principal exception
```

The abstention taste is two honest `no offline check is wired for claim kind
'denied_principal'/'unmodelled_principal'` lines on the deny rule's principal
entry — claim kinds whose per-claim checks live in the collections and the
interaction layer, not in a wired existence check — deciding nothing.

```bash
# 12b. The carve-out — EXPECTED TO EXIT 1: payroll CI added to the
#      guardrail's exceptionPrincipals, "so deploys stop failing".
GCP_GROUNDING_NOW=2026-07-18T12:00:00Z .venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform-denypolicy/plan_threading.json \
    --snapshot examples/terraform-denypolicy/snapshot.json \
    --requirements demo/compiled-denypolicy \
    --explain
```

**12b — the carve-out is DENIED (exit 1), and everything quoted is a constant
of the document.** Both deny promises refuse — the strong promise because the
rule now carries `has_principal_exceptions=True`, the refute promise on the
carve-out row itself — and the recap names the escaping (principal,
permission) pair verbatim:

```text
decision recap: DENIED (exit 1) — because:
  ⚠ [sec:iam] every-deny-covers-token-creation: refuted by deny_rules[0]
      (google_iam_deny_policy.guard_token_mint) condition=''
      denied_principal='principalSet://goog/public:all' has_condition=False
      has_principal_exceptions=True
      permission='iam.serviceAccounts.getAccessToken' policy='' rule_index=0
  ⚠ [sec:iam] no-principal-threads-the-guardrail: refuted by
      deny_rule_exceptions[0] (google_iam_deny_policy.guard_token_mint)
      exception_principal='principal://iam.googleapis.com/projects/-/serviceAccounts/payroll-ci@acme-pay-prod.iam.gserviceaccount.com'
      policy='' rule_index=0
(the full narrative is above, before the report)

summary — what just happened:
  terraform state on disk : none configured
  promises in force       : 3 enforcing, 0 not — from demo/compiled-denypolicy
      [cli] (every-deny-covers-token-creation,
      no-principal-threads-the-guardrail,
      sa-key-creation-stays-effectively-enforced)
  provider                : no schema configured — resource shapes not checked
  proposed change         : examples/terraform-denypolicy/plan_threading.json —
      a terraform plan: 2 google_project_iam_binding, 1 google_iam_deny_policy,
      1 google_org_policy_policy
  result                  : DENIED (exit 1)
    it violated these promises: every-deny-covers-token-creation,
      no-principal-threads-the-guardrail
```

The interaction check tells the same story from the grant's side, as a
warning in the listing: *"this grant to serviceAccount:payroll-ci@… threads
the exception 'principal://…/payroll-ci@…' of rule 0 of
google_iam_deny_policy.guard_token_mint, which names
iam.serviceAccounts.getAccessToken (impersonation), … — the guardrail does
not cover it; review the exception"*. A warning, not a block, because a
threaded grant exposes nothing *new* by itself — but had the threading member
been public, the same check contradicts outright (the guardrail nullified
from the allow side). With no promise corpus in force this run would have
PASSED with only that warning recorded; the promises are what turn the
carve-out into a refusal.

```bash
# 12c. The removal — EXPECTED TO EXIT 1: a rendered plan deleting the deny
#      policy, "it keeps breaking the deploy pipeline".
GCP_GROUNDING_NOW=2026-07-18T12:00:00Z .venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform-denypolicy/plan_remove_deny.json \
    --snapshot examples/terraform-denypolicy/snapshot.json \
    --requirements demo/compiled-denypolicy \
    --explain
```

**12c — the removal is DENIED (exit 1) on the interaction check alone, and
the promises' honesty is the point.** A delete-only plan carries no planned
deny values, so both deny promises abstain by name (*"IAM deny policy
'google_iam_deny_policy.guard_token_mint' has no planned values — the rule
was not evaluated"*) — an abstention never manufactures a block. What blocks
is the wake computation over `change.before` against the estate's captured
grants:

```text
decision recap: DENIED (exit 1) — because:
  ⚠ [iam_deny_shadow] google_iam_deny_policy.guard_token_mint: removing or
      narrowing rule 0 wakes the dormant grant of
      iam.serviceAccounts.getAccessToken (impersonation) to
      serviceAccount:payroll-ci@acme-pay-prod.iam.gserviceaccount.com
      (//cloudresourcemanager.googleapis.com/projects/acme-pay-prod) — the
      deny policy was the only thing keeping a known escalation path inert
  ⚠ [iam_deny_shadow] google_iam_deny_policy.guard_token_mint: removing or
      narrowing rule 0 wakes the dormant grant of
      iam.serviceAccounts.getOpenIdToken (impersonation) to
      serviceAccount:payroll-ci@acme-pay-prod.iam.gserviceaccount.com …
(the full narrative is above, before the report)

summary — what just happened:
  terraform state on disk : none configured
  promises in force       : 3 enforcing, 0 not — from demo/compiled-denypolicy
      [cli] (every-deny-covers-token-creation,
      no-principal-threads-the-guardrail,
      sa-key-creation-stays-effectively-enforced)
  provider                : no schema configured — resource shapes not checked
  proposed change         : examples/terraform-denypolicy/plan_remove_deny.json
      — a terraform plan: 1 google_iam_deny_policy
  result                  : DENIED (exit 1)
    blocked by 2 built-in findings: [iam_deny_shadow]
```

— and the summary is where the promises' abstention is visible as an absence:
three promises are in force, none of them refused, and the block is reported
as built-in findings alone.

No allow policy changed anywhere — effective permissions increased with no
grant edited, which is exactly the shape no per-document gate can see. The
block is polarity-scoped, not blanket: an ordinary woken pair (unclassed
permission, non-public member) draws a warning, and the escalation class or a
public member is what makes it `contradicted`. The clean opposite answer is
gated too: "this removal wakes nothing" is a universal negative over the
grant population, so it is only ever said over a complete `iam_bindings`
capture.

```bash
# 12d. The hygiene sweep — EXPECTED TO EXIT 1: a folder-level reset that
#      "just restores the default", judged over the EFFECTIVE collection.
GCP_GROUNDING_NOW=2026-07-18T12:00:00Z .venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform-denypolicy/plan_reset_payments.json \
    --snapshot examples/terraform-denypolicy/snapshot.json \
    --requirements demo/compiled-denypolicy \
    --explain
```

**12d — the reset is DENIED (exit 1), and no document anywhere spells
`enforce false`.** The proposal adds one block: a `reset` on
`iam.disableServiceAccountKeyCreation` at the payments folder. Its
document-local content is a no-op spelling — a reset states no value at all —
and every per-document view (the same-node comparison of scenario five
included) can at most shrug at it. The fold composes it: the org enforces,
the reset clears that inheritance at the folder, and the constraint's
captured managed default is `ALLOW` — so the *node-effective* value at the
folder and both projects below flips to unenforced, which is exactly what the
estate-tier promise quantifies over:

```text
decision recap: DENIED (exit 1) — because:
  ⚠ [sec:org_policy] sa-key-creation-stays-effectively-enforced: refuted by
      effective_org_policy_bool[0]
      (google_org_policy_policy.payments_default_sweep)
      constraint='iam.disableServiceAccountKeyCreation' enforce=False
      node='folders/665544332211'
(the full narrative is above, before the report)

summary — what just happened:
  terraform state on disk : none configured
  promises in force       : 3 enforcing, 0 not — from demo/compiled-denypolicy
      [cli] (every-deny-covers-token-creation,
      no-principal-threads-the-guardrail,
      sa-key-creation-stays-effectively-enforced)
  provider                : no schema configured — resource shapes not checked
  proposed change         : examples/terraform-denypolicy/plan_reset_payments.json
      — a terraform plan: 2 google_org_policy_policy,
      2 google_project_iam_binding, 1 google_iam_deny_policy
  result                  : DENIED (exit 1)
    it violated these promises: sa-key-creation-stays-effectively-enforced
```

— the refutation names the *effective* row (the folder node, the folded
`enforce=False`) and the terraform block to edit. The blast-radius finding in
the listing enumerates the full damage — *"this change alters the effective
state of constraints/iam.disableServiceAccountKeyCreation at 3 of the 3
node(s) it governs — folders/665544332211: enforce true -> false;
projects/acme-pay-dr: enforce true -> false; projects/acme-pay-prod: enforce
true -> false"* — while the org restatement in the same plan keeps its INERT
finding, and both deny promises still hold: the guardrail itself is
untouched, and each promise judges only its own question. Had the fold been
unlicensed — the constraint's default uncaptured, a condition on the chain,
an incomplete `org_policies` table — this run would have abstained naming the
gap rather than guessed either way.

In production the demo's flags collapse into a `.gcp-grounding.json` config file
discovered next to the proposal (see "Two overlapping ways to get the current
state" above) — the same inputs, written once, so the command line shrinks to
the proposal alone. The demo spells them out because the mapping *is* the
lesson.

Useful flags on `verify-policy`: `--explain` (the decision narrative, the z3
constraints built this run, the state block, and the closing `summary — what
just happened:` naming every input with the layer that supplied it),
`--format json` (the stable machine report), `--abstain-notes`
(surface what the gate could NOT decide on an otherwise-passing run). To
author real requirements, copy `sec_requirements/TEMPLATE.md`, write one
sentence plus one fenced `promise` block per requirement, compile with
`gcp-ground compile-requirements --snapshot <your-estate-snapshot>`, and
commit the artifacts it writes to `sec_requirements/compiled/` — the pinned
sentence in the artifact is exactly what the gate enforces.
