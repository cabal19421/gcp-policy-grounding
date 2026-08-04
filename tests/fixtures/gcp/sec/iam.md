---
domain: iam
state: proposal
severity: high
---

# IAM allow-policy requirements

Invariants a proposed IAM allow policy must satisfy before it reaches the estate.

## No public principals

IAM bindings must not grant access to the entire internet.

```promise
id: no-public-principals
mode: refute
smt:
  exists b in iam_bindings
    in field b.member set["allAuthenticatedUsers", "allUsers"]
```

## No primitive owner grants

No binding may grant the primitive owner role.

```promise
id: no-primitive-owner
mode: refute
vocab: role roles/viewer
note: the primitive owner role is an escalation class, not a job function
smt:
  exists b in iam_bindings
    cmp eq field b.role str "roles/owner"
```

## Bindings are conditioned

Every IAM binding should carry an IAM Condition.

```promise
id: bindings-are-conditioned
mode: assert_satisfiable
smt:
  forall b in iam_bindings
    cmp eq field b.has_condition bool true
```
