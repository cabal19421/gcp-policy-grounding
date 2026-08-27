---
domain: iam
state: proposal
mode: refute
severity: high
---

# The walkthrough corpus: one promise, start to finish

One machine-checkable promise, written in the authoring format
`sec_requirements/README.md` documents. It exists so the README section "How the
gate thinks" can show every artifact of one requirement's life — the sentence, the
compiled s-expression, the two pinned witnesses, the rows a document flattens
into, and the ground formula the solver actually decides — without any of it
being invented for the page.

Both `vocab:` values are grounded against the estate snapshot before the promise
is admitted: `roles/owner` is a real predefined role and `domain:acme.example` is
a real principal in `tests/fixtures/gcp/agentic_snapshot.json`. Spell either one
wrongly and the compile rejects the document rather than enforcing a rule about a
name that does not exist.

## Owner stays inside the company domain

No binding may grant roles/owner to a principal outside domain acme.example.

```promise
id: owner-stays-inside-acme
vocab: role roles/owner
vocab: principal domain:acme.example
note: domain membership is read off the member id's suffix, which is what the estate's own principal ids spell — the gate captures no group or domain membership graph, so a suffix test is the strongest sound reading of "outside the domain" available offline
note: the collection is iam_bindings, whose rows are one per (role, member) pair; a binding listing three members is three rows, so the quantifier below binds each member separately instead of matching a list
smt:
  exists b in iam_bindings
    and
      cmp eq field b.role str "roles/owner"
      not
        suffix field b.member "@acme.example"
```
