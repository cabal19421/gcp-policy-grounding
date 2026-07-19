"""Root conftest: pytest prepends this file's directory — the repo root — to
``sys.path``, so the in-repo ``gcp_grounding`` package is importable from a
plain checkout without ``pip install -e .``."""
