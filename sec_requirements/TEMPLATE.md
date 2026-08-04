---
domain: iam
state: proposal
severity: medium
---

# Title of this requirement document

One or two sentences of preamble. Text before the first `##` heading yields no
promises — it is here to orient a reviewer.

## Name of the requirement

State the invariant in one plain sentence. This first non-empty line becomes the
promise's `source.text`, pinned verbatim into the compiled artifact, so write it
the way you want it to read in a review.

<!--
Uncomment and edit this block to attach a machine-checkable promise. Delete it to
leave the requirement as prose — an untranslated section still compiles, to a
single `unverified` promise with the sentence above quoted, never a silent drop.

```promise
id: name-of-the-requirement
mode: refute
smt:
  exists b in iam_bindings
    cmp eq field b.role str "roles/owner"
```
-->
