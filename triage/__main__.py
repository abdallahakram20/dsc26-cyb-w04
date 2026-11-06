"""Command line:

python -m triage --sarif S --bandit B --project NAME [--equivalences E] [--baseline BASE]
                 [--suppressions SUP] [--today YYYY-MM-DD] [--fail-on high]

Print one JSON object with passed, new, existing, suppressed (lists of groups as objects with key, path,
line, severity, tools, fingerprints), fixed and invalid_suppressions (a count). Exit 0 if the gate
passes, 1 if it fails, 2 if an input file is missing, unreadable or not valid JSON. Suppressions apply
before the baseline comparison.
"""
import argparse
import json
import sys
from datetime import date

from triage.core import (apply_suppressions, dedupe, diff_baseline, gate,
                         load_bandit, load_semgrep_sarif, load_suppressions)


def _group_dict(g):
    return {"key": g.key, "path": g.path, "line": g.line, "severity": g.severity,
            "tools": g.tools, "fingerprints": g.fingerprints}


def _read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="triage")
    ap.add_argument("--sarif", required=True)
    ap.add_argument("--bandit", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--equivalences")
    ap.add_argument("--baseline")
    ap.add_argument("--suppressions")
    ap.add_argument("--today")
    ap.add_argument("--fail-on", default="high", choices=["info", "low", "medium", "high", "critical"])
    args = ap.parse_args(argv)

    try:
        today = date.fromisoformat(args.today) if args.today else date.today()
        findings = (load_semgrep_sarif(args.sarif, args.project)
                    + load_bandit(args.bandit, args.project))
        equivalences = _read_json(args.equivalences) if args.equivalences else {}
        baseline = set(_read_json(args.baseline)) if args.baseline else set()
        entries = _read_json(args.suppressions) if args.suppressions else []
        if not isinstance(equivalences, dict) or not isinstance(entries, list):
            raise ValueError("unexpected JSON shape")
    except (OSError, ValueError, TypeError, AttributeError, KeyError) as exc:
        print(f"triage: {exc}", file=sys.stderr)
        return 2

    groups = dedupe(findings, equivalences)
    valid, invalid = load_suppressions(entries)
    active, suppressed = apply_suppressions(groups, valid, today)
    new, existing, fixed = diff_baseline(active, baseline)
    passed = gate(new, args.fail_on)

    print(json.dumps({
        "passed": passed,
        "new": [_group_dict(g) for g in new],
        "existing": [_group_dict(g) for g in existing],
        "suppressed": [_group_dict(g) for g in suppressed],
        "fixed": fixed,
        "invalid_suppressions": len(invalid),
    }, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
