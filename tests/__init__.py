"""Marker making `tests` a regular, importable package.

Two consumers need the dotted path to resolve statically:

- The harness grounding gate: `tests.agentic.*` must be a resolvable dotted
  module path. The repo-root conftest.py puts the repo root on sys.path, so
  `from tests.agentic import env` resolves from any test module and from a
  child interpreter spawned with cwd=REPO_ROOT.
- `tests/test_gcp_evidence_lint.py` imports its allowlist as
  `tests.evidence_allowlist`: the allowlist is data the lint reads, not a
  test module. This marker makes it resolvable to anything that walks imports
  statically, which is what a review gate does.
"""
