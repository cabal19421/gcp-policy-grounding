---
domain: org_policy
state: proposal
---

# Organization Policy requirements

Invariants over the org-policy rules a proposal would set.

## Serial port stays disabled

The serial-port-access constraint must always enforce.

```promise
id: serial-port-stays-disabled
mode: assert_satisfiable
vocab: constraint constraints/compute.disableSerialPortAccess
smt:
  forall r in org_policy_rules
    implies
      cmp eq field r.constraint str "constraints/compute.disableSerialPortAccess"
      cmp eq field r.enforce bool true
```

## No new owner grants

A proposal must not introduce an owner binding that the old policy did not already carry.

```promise
id: no-new-owner-grants
mode: refute
domain: iam
state: pair
smt:
  and
    exists n in new_iam_bindings
      cmp eq field n.role str "roles/owner"
    not
      exists o in old_iam_bindings
        cmp eq field o.role str "roles/owner"
```
