---
domain: vpc_firewall
state: estate
severity: high
---

# Estate firewall requirements

The one requirement in this suite that a human wrote by hand, compiled through
`gcp-ground compile-requirements` and judged by the real hook against a
terraform-derived current state. It quantifies over the ESTATE collection, not
over the document under review: that is what makes it a statement about the
whole estate, and therefore what a terraform-only view cannot discharge.

## No open SSH anywhere in the estate

No ingress firewall rule may allow tcp/22 from an open range.

```promise
id: no-open-ssh-ingress
mode: refute
smt:
  exists r in firewall_rules
    and
      cmp eq field r.direction str "INGRESS"
      cmp eq field r.action str "allow"
      cmp eq field r.port port 22
      cidr_contains field r.source_range ip4 "203.0.113.9"
```
