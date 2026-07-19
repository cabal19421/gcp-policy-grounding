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

## Layout

- `gcp_grounding/core/` — vendored grounding core (Datalog engine, solver
  detection, four-bucket report model), copied verbatim from the
  [harness](https://github.com/cabal19421/harness) grounding engine; see each
  file's header for provenance. **Do not edit** — domain logic only
  instantiates it.
- `gcp_grounding/` — the GCP domain: snapshot knowledge base, claim extractors
  (IAM / org-policy JSON, Terraform plan JSON), Datalog reasoner, z3 constraint
  layer, report renderer, end-to-end preflight, CLI, changed-file gate, live
  snapshot fetchers.
- `designs/gcp-policy-grounding.md` — the design document this repo is built
  from (implemented task-by-task by the harness design→PR pipeline).
- `tests/` — offline test suite; fixtures under `tests/fixtures/gcp/`. No
  network, no GCP credentials; z3-only assertions are skipped when z3 is not
  importable.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest -q tests/ -k gcp
```
