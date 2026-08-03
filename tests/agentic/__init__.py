"""Support code for the agentic gate suite — NOT test modules.

Nothing in this package is named ``test_*.py``, so pytest never *collects* it;
it holds the shared plumbing (capability probes, helpers, the subprocess
budget, the degraded-world import blocker) that the real ``tests/test_gcp_*``
modules and ``tests/conftest.py`` import.

The dotted path ``tests.agentic`` must stay RESOLVABLE. ``tests/`` is a regular
package (it carries a docstring-only ``__init__.py``), so a static analyser —
notably the harness grounding gate, which derives a module's dotted name by
walking up while each parent directory has an ``__init__.py`` — indexes this
file as ``tests.agentic``, exactly the spelling every importer uses. The repo
root is on ``sys.path`` via the repo-root ``conftest.py``, so
``from tests.agentic.env import ...`` also resolves at runtime from any test
module and from a child interpreter spawned with ``cwd=REPO_ROOT``, without an
editable install.

``_blockimports/`` deliberately has NO ``__init__.py``: it must stay a
non-package directory so ``site`` auto-imports its ``sitecustomize`` when it is
first on ``PYTHONPATH``.
"""
