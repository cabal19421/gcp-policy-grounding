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
| **IAM deny policies** (v2) | deny-policy JSON | denied-permission existence; deny-rule semantics, exceptions honestly abstained |
| **Organization Policy** | v1 + v2 JSON, terraform | constraint existence; boolean/list value-type contradictions; enforce-flip detection; all three disablement spellings |
| **VPC firewall rules** | firewall JSON, terraform | world-open exposure via the packet algebra (CIDR/port/protocol bit-vectors); pair non-enlargement; estate-level shadowing and re-opening by priority |
| **Hierarchical firewall policies** | policy JSON, terraform | cross-level evaluation order and `goto_next`; a folder allow re-opening an org deny; placement and replacement |
| **Cloud Armor** | security-policy JSON, terraform | priority-order bypass; default-rule removal; match-expression grounding over the offline-decidable subset |
| **VPC Service Controls** | perimeter / access-level JSON, terraform | perimeter shrink; restricted-service removal; ingress/egress widening (`ANY_IDENTITY`, wildcards); dry-run flips; ghost access levels |
| **Custom roles** | role JSON, terraform | every included permission must exist in the estate's enumeration |
| **Shell commands** | `gcloud` `gsutil` `bq` `terraform` `kubectl` `curl` text | state-mutation classification (audit via `scan-command`, blocking via the hook's `--bash-policy`) |

Every surface gets the same four-bucket honesty contract, and every domain can
carry compiled promises from your requirements (`iam`, `vpc_firewall`,
`hier_firewall`, `cloud_armor`, `org_policy`, `vpc_sc`).

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
      source can reach tcp/22 through this rule
  ⚠ [sec:vpc_firewall] no-open-ssh-rdp-ingress: refuted by
      proposed_firewall_rules[1] (google_compute_firewall.allow_ssh_world) …
```

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
export GCP_GROUNDING_TF_STATE=infra/prod/terraform.tfstate
export GCP_GROUNDING_TF_PLAN=infra/prod/plan.json
export GCP_GROUNDING_TF_DIR=infra/prod
export GCP_GROUNDING_PRECEDENCE=highest-fidelity-wins
export GCP_GROUNDING_MAX_AGE=7d
export GCP_GROUNDING_DRIFT_POLICY=annotate
export GCP_GROUNDING_CONFIG=/checkout/.gcp-grounding.json
```

Flags beat the environment, the environment beats the config file, and the
config file beats what was auto-detected. `--state-explain` (below) prints which
layer supplied every one of them.

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
staleness can never silently bless a deleted role.

## Proposing a terraform change — agent or human

The proposal is always just the positional file argument; the gate neither
knows nor cares whether an agent or a human wrote it. For terraform changes it
accepts three forms, best first:

```bash
# 1. A rendered plan — resolved values, the form CI should use:
terraform plan -out change.plan && terraform show -json change.plan > proposal.json
gcp-ground verify-policy proposal.json --snapshot estate/api-snapshot.json

# 2. Terraform JSON configuration (.tf.json), as edited in the repo
gcp-ground verify-policy infra/prod/iam.tf.json --snapshot estate/api-snapshot.json

# 3. Raw HCL (.tf) — read by a deliberately small built-in parser; anything it
#    cannot resolve (module magic, interpolations) abstains loudly
gcp-ground verify-policy infra/prod/iam.tf --snapshot estate/api-snapshot.json
```

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
#    untranslated prose sentence stays NOT ENFORCED, and the corpus naming
#    the hallucinated roles/bigquery.reader is REJECTED with a did-you-mean.
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

In production the five flags collapse into a `.gcp-grounding.json` config file
discovered next to the proposal (see "Two overlapping ways to get the current
state" above) — the same inputs, written once, so the command line shrinks to
the proposal alone. The demo spells them out because the mapping *is* the
lesson.

Useful flags on `verify-policy`: `--explain` (dump the z3 constraints built
this run), `--format json` (the stable machine report), `--abstain-notes`
(surface what the gate could NOT decide on an otherwise-passing run). To
author real requirements, copy `sec_requirements/TEMPLATE.md`, write one
sentence plus one fenced `promise` block per requirement, compile with
`gcp-ground compile-requirements --snapshot <your-estate-snapshot>`, and
commit the artifacts it writes to `sec_requirements/compiled/` — the pinned
sentence in the artifact is exactly what the gate enforces.
