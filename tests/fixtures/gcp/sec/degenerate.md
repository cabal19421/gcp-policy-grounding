---
domain: iam
state: proposal
---

# Degenerate requirements

Every failure mode of the requirement language, one per section, so the
compiler's honesty contract has a fixture for each abstain path.

## Unsatisfiable promise

A binding whose role both is and is not the viewer role.

```promise
id: unsatisfiable-promise
mode: refute
smt:
  exists b in iam_bindings
    and
      cmp eq field b.role str "roles/viewer"
      cmp ne field b.role str "roles/viewer"
```

## Tautological promise

Every binding's role either is or is not the viewer role.

```promise
id: tautological-promise
mode: assert_satisfiable
smt:
  forall b in iam_bindings
    or
      cmp eq field b.role str "roles/viewer"
      cmp ne field b.role str "roles/viewer"
```

## Hallucinated role

No binding may grant the BigQuery reader role.

```promise
id: hallucinated-role
mode: refute
vocab: role roles/bigquery.reader
note: near-miss for roles/bigquery.dataViewer; the planted hallucination
smt:
  exists b in iam_bindings
    cmp eq field b.role str "roles/bigquery.reader"
```

## Unregistered collection

No DNS policy may leave outbound query logging switched off.

```promise
id: unregistered-collection
mode: refute
domain: vpc_firewall
state: estate
smt:
  exists f in dns_policies
    cidr_contains field f.source_range ip4 "0.0.0.0"
```

## Cel bearing promise

No owner binding may be time-boxed with a CEL condition.

```promise
id: cel-bearing-promise
mode: refute
smt:
  exists b in iam_bindings
    and
      cmp eq field b.role str "roles/owner"
      cel "request.time < timestamp('2027-01-01T00:00:00Z')"
```

## Untranslated requirement

Access reviews must happen every quarter and be signed off by two independent approvers.
