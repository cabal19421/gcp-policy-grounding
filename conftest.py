"""Make `gcp_grounding` importable when pytest runs straight from a checkout
(plain `pytest`, no editable install): the repo root is this file's directory."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
