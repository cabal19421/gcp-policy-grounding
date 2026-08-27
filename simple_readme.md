# gcp-policy-grounding — the short version

A grounding gate for Google Cloud policy changes: it judges a proposed IAM,
Organization Policy, firewall, Cloud Armor or VPC Service Controls document —
or the Terraform that generates them — against a frozen JSON snapshot of your
estate, offline and without credentials. It catches names that do not exist
(`roles/bigquery.reader` for `roles/bigquery.dataViewer`) and the provably
dangerous change a linter can't see, such as a firewall allow inserted ahead of
the deny that covered it. Every answer lands in one of four buckets —
**grounded**, **ungrounded**, **contradicted**, **unverified**.

## Install

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'
```

## Run a demo

`./run_demo.sh <scenario>` runs one demo arc end to end — the
`compile-requirements` step it depends on included — echoing each step's story
and command before running it, comparing each step's exit to the one README.md
documents, and ending with a PASS/FAIL verdict. A DENIED step exits 1 *by
design*, so a nonzero step is not a failure by itself; a divergence from the
documented exit is. `./run_demo.sh --list` enumerates the scenarios, read from
README.md's at-a-glance table. Every arc runs against frozen fixtures.

| Command | What it shows |
| --- | --- |
| `./run_demo.sh 1` | A violating terraform diff — world-open SSH plus `roles/owner` to an outsider. DENIED: two promises violated, each refutation naming its block. |
| `./run_demo.sh 2a` | A custom-role swap meant to reduce scope, whose accidental extra permission is harmless. APPROVED, with an `[iam_scope_diff]` warning naming it. |
| `./run_demo.sh 2b` | The same swap, but the extra permission is `iam.serviceAccounts.actAs`. DENIED: the permission promise violated, the custom-role block named. |
| `./run_demo.sh 3` | The masked deny removed — the dormant allow wakes up world-open. DENIED: exposure and shadow verdicts. |
| `./run_demo.sh 3b` | The benign counterpart, deleting the dead allow instead. DENIED too: deletion-awareness needs the pair tier, and this shape derives no baseline target for it. |
| `./run_demo.sh 3c` | The remediation — the woken allow narrowed to exactly the two audited partner ranges. APPROVED: the promise holds, the built-ins green beside it. |
| `./run_demo.sh 3d` | The smuggle — those two ranges plus one unaudited /28. DENIED: both built-ins pass, only the promise catches it. |
| `./run_demo.sh 4` | The attribute the provider doesn't know: `src_ranges` for `source_ranges`. DENIED, with the did-you-mean naming the real attribute. |
| `./run_demo.sh 4b` | Version skew: an attribute absent from the captured provider schema. DENIED — the same finding, carrying recapture guidance instead of a suggestion. |
| `./run_demo.sh 4c` | The clean counterpart. APPROVED: every attribute is in the captured schema, so the family stays silent. |
| `./run_demo.sh 4d` | A schema policy configured, the schema omitted. APPROVED, with one `[tf_schema]` abstention naming what was not judged and the capture command. |
| `./run_demo.sh 5` | The org-policy rollback over a compliant estate. APPROVED: all eleven catalogue-named promises hold. |
| `./run_demo.sh 5a` | Serial console re-enabled and a VM allowed an external IP. DENIED: `compute-disable-serialport-access` + `vm-public-ip-gcp`. |
| `./run_demo.sh 5b` | Cloud Run ingress opened to `all`. DENIED: `run-allowed-ingress-internal-loadbalancing` + `cloudrun-ingress-non-public`. |
| `./run_demo.sh 5c` | External VPC peering allowed and internet-NEG enforcement dropped. DENIED: `vpc-externally-peered-vpc-gcp` + `compute-disable-internet-neg`. |
| `./run_demo.sh 5d` | Public-access prevention off and an outside contact domain. DENIED: `public-access-prevention` + `security-contact-gcp`. |
| `./run_demo.sh 5e` | `roles/owner` to an outsider plus a token-creator grant. DENIED: `deny-admin-roles` + `iam-deny-service-account-impersonation`. |
| `./run_demo.sh 5f` | An egress allow to `0.0.0.0/0`. DENIED: `egress-firewall-policy-high-strength-vpc-firewall`, beside the built-in `[firewall_reopen]`. |
| `./run_demo.sh 5g` | The benign counterpart, the ingress allowlist tightened. APPROVED: a narrowing violates nothing; all eleven still hold. |
| `./run_demo.sh 6` | The deny that guards the estate, the dormant grant it masks, and an org-policy restatement. APPROVED: three promises hold, the masked-grant warning and the INERT org finding recorded. |
| `./run_demo.sh 6a` | The carve-out: payroll CI added to the guardrail's `exceptionPrincipals`. DENIED: both deny promises violated, the escaping (principal, permission) quoted verbatim. |
| `./run_demo.sh 6b` | The removal: a rendered plan deleting the deny policy — the dormant grant wakes. DENIED by `[iam_deny_shadow]`; the promises abstain by name. |
| `./run_demo.sh 6c` | The hygiene sweep: a folder-level `reset` that reads as a no-op. DENIED: `sa-key-creation-stays-effectively-enforced` refuted over the effective collection. |
| `./run_demo.sh w` | The teaching walkthrough: one promise judged over a REST IAM policy and over the terraform that grants the same thing. DENIED twice — README.md's "How the gate thinks" quotes every artifact of this arc. |

## Verify a change yourself

Scenario 1's verify step is the command below; each of its five inputs is one
flag (`demo/compiled` is what the scenario's compile step wrote):

```bash
.venv/bin/gcp-ground verify-policy \
    --proposal examples/terraform/main.tf.json \
    --snapshot tests/fixtures/gcp/agentic_snapshot.json \
    --terraform-state examples/terraform/terraform.tfstate \
    --requirements demo/compiled \
    --explain
```

- `--proposal` — the proposed change, agent- or human-authored;
- `--snapshot` — the API snapshot: what is real and live in the estate;
- `--terraform-state` — the current state as captured in IaC;
- `--requirements` — the promises compiled from your requirements directory;
- `--explain` — the decision narrative.

It exits 1, and every `--explain` run closes with a summary whose input rows
name the settings layer that supplied them (`[cli]`, `[env]`, `[config
<path>]`, `[auto]`, `[default]`) and whose last rows are the decision. A list
row prints one item per line, and each promise carries the sentence its author
wrote, quoted from the compiled artifact:

```text
  result                  : DENIED (exit 1)
    it violated these promises:
      no-open-ssh-rdp-ingress
        “No ingress firewall rule may allow tcp/22 or tcp/3389 from 0.0.0.0/0.”
      no-primitive-roles-outside-domain
        “No binding may grant roles/owner or roles/editor to any principal outside domain acme.example.”
    blocked by 1 built-in finding: [firewall_exposure]
```

A change that breaks nothing exits 0 and reads APPROVED. A `.tf.json` or `.tf`
proposal REQUIRES a current-state or provider-schema option (`--terraform-state`,
`--terraform-plan`, `--terraform-dir`, `--provider-schema`, a config-file
equivalent, or an auto-detected sibling `terraform.tfstate`); rendered plan
JSON — the form CI should use — needs none.

## Promises: author, compile, enforce

1. **Author.** Copy `sec_requirements/TEMPLATE.md` into your requirements
   directory (`sec_requirements/` is the default one) and write, per
   requirement, one plain sentence — it is pinned verbatim into the compiled
   artifact and is exactly what the gate enforces — plus one fenced `promise`
   block making it machine-checkable. An untranslated sentence still compiles;
   it stays NOT ENFORCED rather than being dropped.
2. **Compile.** `.venv/bin/gcp-ground compile-requirements sec_requirements
   --snapshot estate/api-snapshot.json --out sec_requirements/compiled`, and
   commit the artifacts it writes. Per promise the compiler rejects bad grammar
   and types, grounds every role, permission, principal and constraint the
   sentence *names* against the snapshot (a hallucinated name fails to compile,
   with a did-you-mean), proves with z3 that the rule can fire and that it
   forbids something, and pins a compliant and a violating witness into the
   artifact — re-classified at every load, so a rule whose meaning drifts
   refuses to load instead of meaning something else.
3. **Review.** `python3 show_promises.py sec_requirements/compiled` renders
   sentence, enforcement status, compiled rule and witnesses side by side.
   Whether the formula means what your sentence says is yours to judge: read the
   violating witness and ask "is *this* what I meant to forbid?"
4. **Enforce.** Pass `--requirements sec_requirements/compiled` on a verify run.

## Everything else

[README.md](README.md) covers the rest, starting with "How the gate thinks" —
what a solver is, what your policies are flattened into, and one worked
encoding — then the three inputs and how the API snapshot and terraform are
merged and cross-checked (drift), the completeness boundary, reading provenance,
the provider schema, capturing a snapshot from a live estate, hook mode,
shell-command scanning, and a walked narrative per demo scenario.
