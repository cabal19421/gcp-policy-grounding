"""Test package marker: makes `tests` a REGULAR package so `tests.agentic.*` is
a resolvable dotted module path for static analysers (the harness grounding
gate). The repo-root conftest.py puts the repo root on sys.path, so
`from tests.agentic import env` resolves from any test module and from a child
interpreter spawned with cwd=REPO_ROOT."""
