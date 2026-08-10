"""README §'the three inputs' pinned to the code it documents: every long-form
flag it shows is a real CLI flag, its config block survives ``discovery``'s
strict loader, and its quoted abstentions are what ``baseline`` emits."""

import argparse
import json
import pathlib
import re

from gcp_grounding import baseline, cli, discovery, provenance

README = pathlib.Path(__file__).resolve().parents[1] / "README.md"
TEXT = README.read_text(encoding="utf-8")
FLAT = " ".join(TEXT.split())  # so a quoted message may be line-wrapped in prose
BASH = re.findall(r"```bash\n(.*?)```", TEXT, re.S)
CONFIG = re.findall(r"```json\n(.*?)```", TEXT, re.S)
HEADINGS = ("## The three inputs",) + tuple(f"### {i}. {t}" for i, t in enumerate((
    "What the engine compares", "Two overlapping ways to get the current state",
    "Pointing the tool at terraform", "The completeness boundary, in practice",
    "New resource versus never looked", "Reading provenance",
    "What this still does not mean"), 1))
QUOTES = {"baseline:new": "COMPLETELY and holds no such row, so this is a new "
                          "resource with no predecessor to compare it against",
          "baseline:unqueried": "was NOT looked up: every source covering"}


def _options(parser):
    """Every long-form option *parser* and its subparsers accept."""
    out = {s for a in parser._actions for s in a.option_strings}
    subs = [p for a in parser._actions if isinstance(a, argparse._SubParsersAction)
            for p in a.choices.values()]
    return out.union(*(_options(p) for p in subs)) if subs else out


def test_every_documented_flag_is_accepted_by_the_parser():
    # A single-quoted string is DATA handed to a flag, not a flag being
    # documented: the scan-command demo quotes a gcloud invocation whose own
    # --member/--role must not be read as gcp-ground flags.
    shown = {f for block in BASH
             for f in re.findall(r"--[A-Za-z0-9][A-Za-z0-9-]*",
                                 re.sub(r"'[^']*'", "", block))}
    unknown = sorted(shown - _options(cli.build_parser()))
    assert shown and not unknown, f"documented but not a CLI flag: {unknown}"


def test_the_config_block_is_accepted_by_the_strict_loader(tmp_path):
    assert len(CONFIG) == 1, "expected exactly one embedded config block"
    config, problems = discovery.parse_config(
        json.loads(CONFIG[0]), path=str(tmp_path / discovery.CONFIG_NAMES[0]))
    assert problems == () and config is not None


def test_the_quoted_abstentions_and_the_headings_are_current():
    for heading in HEADINGS:
        assert heading in TEXT, heading
    ref = baseline.TargetRef(category="firewall_rules", key="k", how="config-map")
    emitted = {"baseline:new": baseline._absent_entry(
                   ref, provenance.CategoryScope(scope="complete"), "api").reason,
               "baseline:unqueried": baseline._unqueried_entry(
                   ref, provenance.CategoryScope(scope="partial"), ("tf",), None).reason}
    for kind, quote in QUOTES.items():
        assert quote in FLAT, f"the README no longer quotes {kind}"
        assert quote in " ".join(emitted[kind].split()), kind
