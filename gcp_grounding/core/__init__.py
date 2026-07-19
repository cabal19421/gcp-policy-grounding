"""Vendored grounding core (Datalog engine, solver detection, report model).

Copied verbatim from the harness grounding engine (see each module's header
for the exact source revision). Reuse contract: these modules are NOT edited
here — new domain logic lives in ``gcp_grounding``, which only *instantiates*
this core. If a core file genuinely must change, that is an upstream change
in harness first, then a re-vendor.
"""

from .report import STATUSES, GroundingReport, Verdict  # noqa: F401
from .solver import get_solver  # noqa: F401
