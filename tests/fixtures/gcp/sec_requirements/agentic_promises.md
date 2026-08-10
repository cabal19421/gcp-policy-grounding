---
domain: iam
state: proposal
mode: refute
severity: high
---

# Promises the agentic gate suite drives end to end

Six machine-checkable promises plus one that deliberately has no encoding, written
in the authoring format `sec_requirements/README.md` documents. Every name these
promises mention exists in `tests/fixtures/gcp/agentic_snapshot.json`, because the
compiler pushes each `vocab:` value through `reasoner.ground_existence` before it
admits the promise — a typo here must fail to compile, exactly as it does in a
policy document. Text before the first `##` heading yields no promises.

## No primitive roles outside the acme.example domain

No binding may grant roles/owner or roles/editor to any principal outside domain acme.example.

```promise
id: no-primitive-roles-outside-domain
vocab: role roles/owner
vocab: role roles/editor
vocab: principal domain:acme.example
note: membership in the domain is read off the member id's suffix, which is what the estate's own principal ids spell
smt:
  exists b in iam_bindings
    and
      in field b.role set["roles/editor", "roles/owner"]
      not
        suffix field b.member "acme.example"
```

## No public principals

No binding may include allUsers or allAuthenticatedUsers.

```promise
id: no-public-principals
note: allUsers and allAuthenticatedUsers are deliberately absent from vocab — they are not estate principals, and grounding them would reject this promise for naming a name the snapshot cannot have
smt:
  exists b in iam_bindings
    in field b.member set["allAuthenticatedUsers", "allUsers"]
```

## Impersonation stays with the platform SRE group

No binding may grant roles/iam.serviceAccountTokenCreator or roles/iam.serviceAccountUser to a principal that is not in group:platform-sre@acme.example.

```promise
id: impersonation-sre-only
vocab: role roles/iam.serviceAccountTokenCreator
vocab: role roles/iam.serviceAccountUser
vocab: principal group:platform-sre@acme.example
smt:
  exists b in iam_bindings
    and
      in field b.role set["roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser"]
      cmp ne field b.member str "group:platform-sre@acme.example"
```

## Service account key creation stays disabled

Every Org Policy rule for constraints/iam.disableServiceAccountKeyCreation must set enforce to true.

```promise
id: sa-key-creation-disabled
domain: org_policy
vocab: constraint constraints/iam.disableServiceAccountKeyCreation
note: org_policy_rules spells the constraint the way the document's name does, as the tail after /policies/, so the literal here carries no constraints/ prefix
note: the sentence says what the rule CHECKS — the refutation of a rule that leaves enforce false — and not "the constraint must be enforced", which this formula cannot decide from a proposal that carries no rule for it at all; the vocab line above is what scopes the promise, so a document about another constraint abstains instead of grounding vacuously
smt:
  exists r in org_policy_rules
    and
      cmp eq field r.constraint str "iam.disableServiceAccountKeyCreation"
      cmp eq field r.enforce bool false
```

## No open SSH or RDP ingress

No ingress firewall rule may allow tcp/22 or tcp/3389 from 0.0.0.0/0.

```promise
id: no-open-ssh-rdp-ingress
domain: vpc_firewall
note: the term language has no Proto literal, so this promise is protocol-agnostic and therefore STRICTER than the sentence — it also refutes udp/22 from the internet, which over-blocks rather than under-blocks
note: reachability from the whole internet is spelled as the source range containing 0.0.0.0, which only 0.0.0.0/0 and its sub-blocks do
smt:
  exists r in proposed_firewall_rules
    and
      cmp eq field r.direction str "INGRESS"
      cmp eq field r.action str "allow"
      cidr_contains field r.source_range ip4 "0.0.0.0"
      or
        port_in field r.port 22 22
        port_in field r.port 3389 3389
```

## Every perimeter restricts Cloud Storage

Every service perimeter must keep storage.googleapis.com in restricted_services.

```promise
id: perimeter-restricts-storage
domain: vpc_sc
note: the universal binds over perimeter_resources, NOT over perimeter_restricted_services — a perimeter whose restricted-services list is empty contributes no service row, so an existential over that collection has nothing to bind and refute mode grounds over a perimeter that restricts nothing
note: the section is bound too, because status is the enforced half and spec the dry-run one — without it a perimeter that restricts storage only in spec reads as keeping it
smt:
  exists p in perimeter_resources
    not
      exists q in perimeter_restricted_services
        and
          cmp eq field q.perimeter field p.perimeter
          cmp eq field q.section field p.section
          cmp eq field q.service str "storage.googleapis.com"
```

## Security review before merge

Changes must be reviewed by the security team before merge.

This section carries no `promise` block on purpose. There is no z3 formula for "a
human looked at it", and the compiler must say so: the requirement is never
silently dropped, it compiles to `status: unverified` with the sentence above
quoted verbatim, the same way an unsupported CEL condition degrades rather than
guessing.
