---
domain: iam
state: proposal
severity: high
---

# Healthy IAM requirements

Every promise here compiles, and every one of them HOLDS over both
`iam_policy_good.json` and `iam_policy_bad.json`. That is the point: a hook run
against a clean policy with this corpus configured must be byte-silent, which is
what makes it the control for the not-enforcing notice.

Nothing here may reference a role the snapshot does not carry, and nothing may
constrain `has_condition` — `iam_policy_good.json` has unconditioned bindings, so
a conditioned-bindings promise would contradict it and turn a control run into a
blocking one.

## No public principals

IAM bindings must not grant access to the entire internet.

```promise
id: clean-no-public-principals
mode: refute
smt:
  exists b in iam_bindings
    in field b.member set["allAuthenticatedUsers", "allUsers"]
```

## No primitive owner grants

No binding may grant the primitive owner role.

```promise
id: clean-no-primitive-owner
mode: refute
smt:
  exists b in iam_bindings
    cmp eq field b.role str "roles/owner"
```
