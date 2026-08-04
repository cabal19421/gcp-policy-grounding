"""Terraform artifacts as a second source of CURRENT state.

Consumers import the submodules directly (``from gcp_grounding.tfsource import
state``); this file re-exports nothing, so adding a reader never changes what a
bare ``import gcp_grounding.tfsource`` costs or pulls in.

The pipeline, in order:

1. **discover** — find the artifacts in a tree (``.tfstate``, plan JSON,
   ``.tf`` / ``.tf.json``) and say which is which.
2. **read** — parse one artifact into :class:`gcp_grounding.facts.TfObject`
   values, spelling every value terraform did not hand over as a literal with
   an :class:`gcp_grounding.facts.Unresolved` marker.
3. **map** — turn objects into :class:`gcp_grounding.facts.Fact` values against
   the estate categories in :data:`gcp_grounding.facts.TF_CATEGORIES`.
4. **resolve** — reconcile facts that overlap, by provenance, into one winner
   per key, keeping the losers and the reason.
5. **assemble** — build the reconciled current-state estate the engine reads.

The layering rule: this package owns terraform artifact SYNTAX and nothing
else. It imports DOWN into the flat vocabulary modules (``facts``,
``provenance``, ``knowledge``) and is never imported by them, except lazily at
a boundary where a flat module needs a reader at call time. Anything that is
true of a fact regardless of which artifact produced it belongs in the flat
vocabulary, not here.
"""
