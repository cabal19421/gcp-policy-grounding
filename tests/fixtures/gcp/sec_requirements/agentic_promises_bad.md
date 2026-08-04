---
domain: iam
state: proposal
mode: refute
severity: high
---

# A requirement that names a role nobody has

One promise, deliberately hallucinated. `roles/bigquery.reader` is the canonical
LLM invention for `roles/bigquery.dataViewer`: it reads like a real GCP role and
is not one. The compiler grounds requirement vocabulary through the same
existence reasoner and the same near-miss suggester that catches that typo in a
policy document, so this file must FAIL to compile with a did-you-mean — a
requirement is not admitted just because it is well-formed.

## BigQuery reads are limited to the reader role

No binding may grant a BigQuery role other than roles/bigquery.reader.

```promise
id: bigquery-reader-only
vocab: role roles/bigquery.reader
smt:
  exists b in iam_bindings
    and
      prefix field b.role "roles/bigquery."
      cmp ne field b.role str "roles/bigquery.reader"
```
