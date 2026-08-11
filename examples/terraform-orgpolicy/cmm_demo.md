---
domain: org_policy
state: proposal
mode: refute
severity: high
---

# Scenario five's control corpus: the org-policy rollback

Eleven machine-checkable promises, written in the authoring format
`sec_requirements/README.md` documents. The promise ids are an organisation's
own control names, respelled into the artifact id grammar
(`^[a-z0-9][a-z0-9-]*$`, so each catalogue underscore becomes a hyphen —
`compute_disable_internet_neg` → `compute-disable-internet-neg`, a one-to-one,
mechanically reversible mapping) so each compiled rule maps back onto the
catalogue it came from — this corpus is a stand-in for your own compiled
promises, and the README's scenario five swaps it in through `--requirements`
exactly the way you would swap in yours. Eight promises are
Organization Policy controls; the last three are deliberately not (two IAM, one
VPC firewall), modelled in the domains the engine actually judges them in.
Every name a `vocab:` line carries exists in
`examples/terraform-orgpolicy/snapshot.json`, because the compiler grounds each
one through `reasoner.ground_existence` before the promise is admitted.

Two honesty notes that apply corpus-wide, so no single promise has to restate
them:

- The `org_policy_rules` collection flattens a list-typed rule to one row per
  value and does not record whether the value sat on the allow side or the deny
  side, so every list-shaped promise below judges *values on the policy*, not
  values-on-one-side — stricter than the sentence, over-blocking rather than
  under-blocking.
- The conservative terraform extraction abstains by name on `allow_all` /
  `deny_all` rules (they have no REST row shape), so this scenario's estate
  spells "deny all external IPs" as an *empty allowlist* — the most restrictive
  list there is — rather than `deny_all = "TRUE"`.

## Internet network endpoint groups stay disabled

Every Org Policy rule for constraints/compute.disableInternetNetworkEndpointGroups must set enforce to true.

```promise
id: compute-disable-internet-neg
vocab: constraint constraints/compute.disableInternetNetworkEndpointGroups
note: org_policy_rules spells the constraint as the tail after /policies/, so the literal here carries no constraints/ prefix
note: the formula checks what a rule STATES — the refutation of a rule that leaves enforce false — and abstains rather than grounding vacuously on a document that carries no rule for this constraint at all
smt:
  exists r in org_policy_rules
    and
      cmp eq field r.constraint str "compute.disableInternetNetworkEndpointGroups"
      cmp eq field r.enforce bool false
```

## VPC peering stays inside the organization

Every value on the constraints/compute.restrictVpcPeering list must be under:organizations/123456789012 — no externally peered VPC.

```promise
id: vpc-externally-peered-vpc-gcp
vocab: constraint constraints/compute.restrictVpcPeering
note: the collection's rows do not say which side of the list a value sat on, so ANY listed value other than the organization's own node refutes — a deny-side entry over-blocks rather than under-blocks
smt:
  exists r in org_policy_rules
    and
      cmp eq field r.constraint str "compute.restrictVpcPeering"
      cmp eq field r.is_list bool true
      cmp ne field r.value str "under:organizations/123456789012"
```

## No VM gets an external IP

constraints/compute.vmExternalIpAccess must deny all external IPs — no rule may put any VM on its value lists.

```promise
id: vm-public-ip-gcp
vocab: constraint constraints/compute.vmExternalIpAccess
note: deny-all is spelled as an empty allowlist in this estate (see the preamble); under deny-all, ANY enumerated value is an exception being carved, so a single list row for this constraint refutes
smt:
  exists r in org_policy_rules
    and
      cmp eq field r.constraint str "compute.vmExternalIpAccess"
      cmp eq field r.is_list bool true
```

## Cloud Run ingress stays internal or load-balanced

Every value on the constraints/run.allowedIngress list must be internal or internal-and-cloud-load-balancing.

```promise
id: run-allowed-ingress-internal-loadbalancing
vocab: constraint constraints/run.allowedIngress
smt:
  exists r in org_policy_rules
    and
      cmp eq field r.constraint str "run.allowedIngress"
      cmp eq field r.is_list bool true
      not
        in field r.value set["internal", "internal-and-cloud-load-balancing"]
```

## Cloud Run ingress is never public

No Org Policy rule for constraints/run.allowedIngress may carry the value all.

```promise
id: cloudrun-ingress-non-public
vocab: constraint constraints/run.allowedIngress
note: overlaps run-allowed-ingress-internal-loadbalancing by design — the catalogue keeps "never public" as its own control, so a reviewer sees BOTH names when ingress goes to "all", and this one alone when a hypothetical future vocabulary value is public-but-not-"all"
smt:
  exists r in org_policy_rules
    and
      cmp eq field r.constraint str "run.allowedIngress"
      cmp eq field r.value str "all"
```

## Serial-port access stays disabled

Every Org Policy rule for constraints/compute.disableSerialPortAccess must set enforce to true.

```promise
id: compute-disable-serialport-access
vocab: constraint constraints/compute.disableSerialPortAccess
smt:
  exists r in org_policy_rules
    and
      cmp eq field r.constraint str "compute.disableSerialPortAccess"
      cmp eq field r.enforce bool false
```

## Public access prevention stays enforced

Every Org Policy rule for constraints/storage.publicAccessPrevention must set enforce to true.

```promise
id: public-access-prevention
vocab: constraint constraints/storage.publicAccessPrevention
smt:
  exists r in org_policy_rules
    and
      cmp eq field r.constraint str "storage.publicAccessPrevention"
      cmp eq field r.enforce bool false
```

## Essential contacts stay on the corp domain

Every value on the constraints/essentialcontacts.allowedContactDomains list must be @acme.example.

```promise
id: security-contact-gcp
vocab: constraint constraints/essentialcontacts.allowedContactDomains
smt:
  exists r in org_policy_rules
    and
      cmp eq field r.constraint str "essentialcontacts.allowedContactDomains"
      cmp eq field r.is_list bool true
      cmp ne field r.value str "@acme.example"
```

## No egress to the whole internet

No egress firewall rule may allow traffic to 0.0.0.0/0.

```promise
id: egress-firewall-policy-high-strength-vpc-firewall
domain: vpc_firewall
note: NOT an org-policy control — it is judged in the vpc_firewall domain, over the proposal's own firewall rows, where direction and destination_range are first-class fields
note: reaching the whole internet is spelled as the destination range containing 0.0.0.0, which only 0.0.0.0/0 and its sub-blocks do
note: a firewall row omits destination_range when the rule states no destination ranges, and a promise that mentions the field then abstains loudly — so this scenario's estate states destination_ranges on every rule, which is what licenses the promise to judge all of them
smt:
  exists r in proposed_firewall_rules
    and
      cmp eq field r.direction str "EGRESS"
      cmp eq field r.action str "allow"
      cidr_contains field r.destination_range ip4 "0.0.0.0"
```

## No primitive admin roles

No binding may grant roles/owner or roles/editor to anyone.

```promise
id: deny-admin-roles
domain: iam
vocab: role roles/owner
vocab: role roles/editor
note: NOT an org-policy control — it is judged in the iam domain, over the proposal's own binding rows; stricter than the demo corpus's outside-the-domain variant, because this catalogue bans the primitive roles outright
smt:
  exists b in iam_bindings
    in field b.role set["roles/editor", "roles/owner"]
```

## No service-account impersonation grants

No binding may grant roles/iam.serviceAccountTokenCreator.

```promise
id: iam-deny-service-account-impersonation
domain: iam
vocab: role roles/iam.serviceAccountTokenCreator
note: NOT an org-policy control — it is judged in the iam domain, over the proposal's own binding rows
note: deliberately quantified over iam_bindings ALONE: an or over a second collection (proposed_role_permissions, the scenario-two actAs pattern) would abstain the whole promise on any proposal that defines no custom role, because an unevaluable branch abstains the formula it sits in — the actAs half of this control stays with the scenario-two corpus
smt:
  exists b in iam_bindings
    cmp eq field b.role str "roles/iam.serviceAccountTokenCreator"
```
