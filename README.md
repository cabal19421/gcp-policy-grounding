# gcp-policy-grounding

A **neuro-symbolic grounding gate** for Google Cloud IAM allow/deny policies,
Organization Policy, and the Terraform that generates them. It catches the
policy analog of code hallucination: an LLM (or a human) confidently writing
`roles/bigquery.reader` (doesn't exist) instead of `roles/bigquery.dataViewer`,
binding a service account nobody created, or putting list values on a boolean
org-policy constraint.

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

## The three inputs

### 1. What the engine compares

Three things go in. Every answer comes out of comparing them, and the report
says which of the three each answer came from.

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
