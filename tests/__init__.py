"""Marker making ``tests`` an importable package.

``tests/test_gcp_evidence_lint.py`` imports its allowlist as
``tests.evidence_allowlist``: the allowlist is data the lint reads, not a test
module, and it is named as such in the design. A namespace package resolves that
at runtime by accident of the root ``conftest.py`` putting the repo root on
``sys.path``; this marker makes it resolvable to anything that walks imports
statically, which is what a review gate does.
"""
