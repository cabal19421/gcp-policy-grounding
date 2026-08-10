---
domain: iam
state: proposal
mode: refute
severity: high
---

# Promises for the custom-role swap scenario

One machine-checkable promise, quantified over the proposal's own custom-role
permission lists (`proposed_role_permissions`: one row per permission a
`google_project_iam_custom_role` block includes, each row carrying the role's
full name and the terraform block address). This corpus is scenario two's own —
it is compiled separately from `tests/fixtures/gcp/sec_requirements` (see
"Scenario two" in the repo README), so the demo corpus's promise counts stay
untouched. `iam.serviceAccounts.actAs` is grounded against the estate snapshot
before the promise is admitted, exactly like every other `vocab:` value.

## No role may act as a service account

No role may include the permission iam.serviceAccounts.actAs.

```promise
id: no-actas-in-custom-roles
vocab: permission iam.serviceAccounts.actAs
note: actAs is the impersonation permission — a role that carries it lets every member of every binding that grants the role run workloads as any service account it can name, which is an escalation path, not a data-access grant
note: the collection has rows only for a terraform proposal's custom-role blocks; no supported REST document kind carries a custom role's permission list, so over a REST document this promise abstains naming that fact rather than passing vacuously
smt:
  exists p in proposed_role_permissions
    cmp eq field p.permission str "iam.serviceAccounts.actAs"
```
