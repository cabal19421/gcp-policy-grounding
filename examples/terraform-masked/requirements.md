---
domain: vpc_firewall
state: proposal
mode: refute
severity: high
---

# Promises for the masked-deny scenario's conditional-approval arm

One machine-checkable promise, quantified over the proposal's own flattened
firewall rows (`proposed_firewall_rules`: one row per source range x port a
`google_compute_firewall` block admits, each row carrying the rule's name and
the terraform block address). This corpus is scenario three's own — it is
compiled separately from `tests/fixtures/gcp/sec_requirements`, so the demo
corpus's promise counts stay untouched.

## The woken allow admits only the two audited partner networks

The ingress allow rule allow-rdp-broad may admit sources only from within the two audited partner networks, 10.198.51.0/24 and 10.203.113.0/26.

```promise
id: masked-allow-only-known-domains
note: the "two known domains" are modeled as the two audited partner networks' CIDR blocks — GCP firewalls have no DNS-domain concept, so a named address block per partner is the strongest judgeable spelling
note: subset is spelled per range row as "the row's range contains the partner block's base address AND carries a mask at least as specific (unsigned compare)" — sound in the refuting direction (a range reaching beyond either block always refutes, 0.0.0.0/0's zero mask included) and exact for base-anchored subranges; a subset not anchored at a partner base (e.g. 10.198.51.128/25) is conservatively refuted rather than admitted
note: the union of the two disjoint partner blocks decides per row because CIDR blocks are nested-or-disjoint — a single range inside the union is inside one of the two blocks
smt:
  exists r in proposed_firewall_rules
    and
      cmp eq field r.name str "allow-rdp-broad"
      cmp eq field r.direction str "INGRESS"
      cmp eq field r.action str "allow"
      not
        or
          and
            cidr_contains field r.source_range ip4 "10.198.51.0"
            cmp ge field r.source_range_mask ip4 "255.255.255.0"
          and
            cidr_contains field r.source_range ip4 "10.203.113.0"
            cmp ge field r.source_range_mask ip4 "255.255.255.192"
```
