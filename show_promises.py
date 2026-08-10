#!/usr/bin/env python3
"""Render compiled promise artifacts for humans: the verbatim English
sentence, its enforcement status, and the exact compiled SMT rule plus the
pinned witnesses that define what compliance and violation look like.

Usage:  python3 show_promises.py /tmp/compiled [promise-id ...]
"""
import json
import sys
from pathlib import Path


def render(doc: dict, only: set[str]) -> None:
    print(f"document: {doc['source_doc']}  (sha256 {doc['source_sha256'][:12]}…, "
          f"snapshot {doc['snapshot_captured_at']}, encoder {doc['encoder']})")
    for p in doc["promises"]:
        if only and p["id"] not in only:
            continue
        src = p.get("source") or {}
        status = p["status"].upper()
        badge = {"COMPILED": "✓ ENFORCED", "REJECTED": "✗ REJECTED",
                 "UNVERIFIED": "? NOT ENFORCED"}.get(status, status)
        print(f"\n{'=' * 72}")
        print(f"{badge}  [{p['domain']}/{p['state']}/{p['mode']}"
              f"{'/' + p['severity'] if p.get('severity') else ''}]  {p['id']}")
        print(f"  “{(src.get('text') or '').strip()}”")
        print(f"    — {src.get('file')}:{src.get('line')}")
        if p.get("reason"):
            print(f"  reason: {p['reason']}")
        smt = p.get("smt") or {}
        sexpr = smt.get("sexpr") if isinstance(smt, dict) else None
        if sexpr:
            print("  compiled rule (canonical s-expression):")
            for line in sexpr.splitlines():
                print(f"    {line}")
        w = p.get("witnesses") or {}
        for kind, label in (("positive", "compliant"), ("negative", "violating")):
            rec = w.get(kind)
            if rec:
                fields = ", ".join(f"{k.split('#', 1)[-1]}={v!r}"
                                   for k, v in sorted(rec["assignment"].items()))
                print(f"  {label} witness ({rec.get('origin', '?')}): {fields}")


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    where = Path(sys.argv[1])
    only = set(sys.argv[2:])
    paths = sorted(where.glob("*.promises.json")) if where.is_dir() else [where]
    for path in paths:
        render(json.loads(path.read_text()), only)
        print()


if __name__ == "__main__":
    main()
