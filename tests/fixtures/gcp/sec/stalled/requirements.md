---
domain: iam
state: proposal
severity: high
---

# One enforcing requirement and one that never compiled

The fixture behind the not-enforcing notice. Exactly two promises: one compiles
and enforces, the other is REJECTED at compile time because it names a role the
snapshot does not carry.

This is the shape that is otherwise invisible. The rejected promise re-emits an
`unverified` carry verdict, so `report.ok` stays True and the run exits 0; and
`--abstain-notes` is off by default, so its stderr is empty. Without a separate
operator signal, dropping this corpus into a hook is byte-identical to dropping
in a corpus where both rules work.

The enforcing promise must also HOLD over `iam_policy_good.json`, so that a run
against a clean policy produces the notice and nothing else.

## No primitive owner grants

No binding may grant the primitive owner role.

```promise
id: stalled-no-primitive-owner
mode: refute
smt:
  exists b in iam_bindings
    cmp eq field b.role str "roles/owner"
```

## No BigQuery reader grants

No binding may grant the BigQuery reader role.

```promise
id: stalled-hallucinated-role
mode: refute
vocab: role roles/bigquery.reader
note: roles/bigquery.reader does not exist — the planted typo for roles/bigquery.dataViewer
smt:
  exists b in iam_bindings
    cmp eq field b.role str "roles/bigquery.reader"
```
