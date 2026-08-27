---
domain: iam
state: proposal
severity: high
---

# Scenario six's control corpus: the deny that guarded the estate

Three machine-checkable promises over the payments estate's guardrails,
written in the authoring format `sec_requirements/README.md` documents. Two
quantify over the IAM-deny collections (`deny_rules`,
`deny_rule_exceptions`) and judge each deny policy the moment it is proposed;
the third quantifies over the *effective* org-policy collection
(`effective_org_policy_bool`) — the folded answer to "what is actually
enforced at this node after the org, the folders and this change compose",
which no per-document view can give.

Honesty notes that apply corpus-wide, so no single promise has to restate
them:

- `deny_rules` mints one row per **effective** (rule, denied-principal,
  denied-permission) combination: `exceptionPermissions` are subtracted on the
  normalized short form *before* rows exist, so a policy that denies a
  permission and then excepts it back simply has no row for it — the strong
  promise below cannot be satisfied by a clawed-back denial. A rule naming a
  permission with no unambiguous normalized form (a wildcard, a malformed
  string) aborts the whole rule by name rather than guessing a row.
- Principal exceptions are never a string subtraction (an exception can carve
  one subject out of `public:all`), so they stay visible instead:
  `has_principal_exceptions` on every `deny_rules` row, and one
  `deny_rule_exceptions` row per carve-out. An exception-free policy grounds
  the refute-mode promise *with* the observed-empty attestation ("every deny
  rule was read and none carries a principal exception") — never a vacuous
  pass over records nobody read.
- The effective promise is **estate-tier**: it folds
  `snapshot.org_policies` + `snapshot.resource_hierarchy` with the proposal's
  own blocks over the proposal's node and every captured descendant. It
  abstains by name when the capture may not license the fold — an uncaptured
  or incomplete table, a condition anywhere on the folded chain, a fold that
  bottoms out at a managed default the snapshot did not capture
  (`constraint_default`) — and judges only what the estate actually recorded.

## Every deny policy keeps token minting denied to everyone

Every IAM deny policy under review must deny iam.serviceAccounts.getAccessToken to everyone, unconditionally, with no principal exceptions.

```promise
id: every-deny-covers-token-creation
mode: assert_satisfiable
vocab: permission iam.serviceAccounts.getAccessToken
note: the strongest judgeable spelling — the permission bound to the public set, no principal exceptions, no denialCondition; a maintenance-window denial or a carve-out refuses it
note: the permission field carries the normalized short form (the v2 spelling iam.googleapis.com/serviceAccounts.getAccessToken normalizes to it), which is why the vocab line grounds against snapshot.permissions
smt:
  exists r in deny_rules
    and
      cmp eq field r.permission str "iam.serviceAccounts.getAccessToken"
      cmp eq field r.denied_principal str "principalSet://goog/public:all"
      cmp eq field r.has_principal_exceptions bool false
      cmp eq field r.has_condition bool false
```

## No principal threads the guardrail

No deny rule may carve any principal out of its denial.

```promise
id: no-principal-threads-the-guardrail
mode: refute
note: refuted by ANY deny_rule_exceptions row, and the refutation quotes the carved-out principal verbatim — it is a constant of the document, not a solver model
smt:
  exists e in deny_rule_exceptions
    cmp ne field e.exception_principal str ""
```

## Service-account key creation stays effectively enforced

constraints/iam.disableServiceAccountKeyCreation must remain effectively enforced at every node the change determines.

```promise
id: sa-key-creation-stays-effectively-enforced
mode: refute
domain: org_policy
state: estate
vocab: constraint constraints/iam.disableServiceAccountKeyCreation
note: judged over the FOLDED effective state — a folder-level reset whose only effect materializes at the projects below refutes this promise even though no document anywhere spells enforce false
smt:
  exists e in effective_org_policy_bool
    and
      cmp eq field e.constraint str "iam.disableServiceAccountKeyCreation"
      cmp eq field e.enforce bool false
```
