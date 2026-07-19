"""``python -m gcp_grounding`` — the same CLI the ``gcp-ground`` console
script exposes (:func:`gcp_grounding.cli.main`)."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
