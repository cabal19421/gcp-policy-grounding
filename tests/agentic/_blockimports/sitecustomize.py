"""Degraded-world import blocker for child processes.

This directory is placed FIRST on a child's ``PYTHONPATH`` (see the
``blocked_import_env`` fixture); ``site`` then auto-imports this module at
interpreter startup — which is why this directory must stay a NON-package (no
``__init__.py``). It reads ``GCP_TEST_BLOCK_IMPORTS``, a comma-separated list of
dotted module names, and when that list is non-empty inserts a meta-path finder
at position 0 that makes exactly those modules fail to *load*.

CRITICAL DESIGN POINT — the finder returns a SPEC WHOSE LOAD FAILS, and must
NEVER raise from ``find_spec``:

* ``core/solver.py:113`` calls ``importlib.util.find_spec("z3")`` *unguarded*.
  A finder raising from ``find_spec`` would crash ``get_solver`` instead of
  letting it degrade. Returning a normal
  :class:`importlib.machinery.ModuleSpec` whose loader raises only from
  ``exec_module`` means ``find_spec`` succeeds, the subsequent ``import z3``
  fails, and that failure is swallowed by the broad ``except`` at
  ``core/solver.py:116-120`` — yielding backend ``"builtin"``.
* The same spec shape makes ``preflight._tf_plan_extractor()``'s
  ``except ImportError`` return ``None``, giving the honest ``unverified``
  instead of an import crash.

Blocking is scoped to the names the env var lists, and to the child carrying
this directory on its ``PYTHONPATH`` — the parent test process is unaffected.
"""

import os
import sys
from importlib.abc import Loader, MetaPathFinder
from importlib.machinery import ModuleSpec


class _RaisingLoader(Loader):
    """A loader whose module never materializes: ``create_module`` declines to
    build one and ``exec_module`` raises ``ImportError`` when the import
    machinery tries to execute it."""

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        name = getattr(module.__spec__, "name", "?")
        raise ImportError(
            f"import of {name} is blocked by GCP_TEST_BLOCK_IMPORTS "
            f"(degraded-world test harness)"
        )


class _BlockFinder(MetaPathFinder):
    """Returns a load-failing spec for exactly the names it was given, and
    ``None`` — defer to the real finders — for everything else."""

    def __init__(self, names):
        self._names = frozenset(names)

    def find_spec(self, fullname, path=None, target=None):
        if fullname in self._names:
            return ModuleSpec(fullname, _RaisingLoader())
        return None


_blocked = [
    name.strip()
    for name in os.environ.get("GCP_TEST_BLOCK_IMPORTS", "").split(",")
    if name.strip()
]
if _blocked:
    sys.meta_path.insert(0, _BlockFinder(_blocked))
