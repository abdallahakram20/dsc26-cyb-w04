import json
from datetime import date
from pathlib import Path

from triage.core import (Finding, apply_suppressions, dedupe, fingerprint, gate,
                         load_bandit, load_semgrep_sarif, load_suppressions)

FIX = Path(__file__).resolve().parent.parent / "fixtures"
PROJECT = "diwan_invoicing"


def all_findings():
    return (load_semgrep_sarif(FIX / "semgrep.sarif", PROJECT)
            + load_bandit(FIX / "bandit.json", PROJECT))


def test_semgrep_uses_security_severity_then_level():
    by_rule = {f.rule_id: f for f in load_semgrep_sarif(FIX / "semgrep.sarif", PROJECT)}
    assert by_rule["diwan.sql-string-format"].severity == "high"     # security-severity 8.8
    assert by_rule["diwan.weak-hash-md5"].severity == "low"          # level "note"
    assert by_rule["diwan.sql-string-format"].cwe == 89
    assert by_rule["diwan.sql-string-format"].path == "invoicing/db.py"


def test_bandit_low_confidence_is_downgraded():
    by_rule = {f.rule_id: f for f in load_bandit(FIX / "bandit.json", PROJECT)}
    assert by_rule["B113"].severity == "low"        # MEDIUM severity, LOW confidence
    assert by_rule["B602"].severity == "high"
    assert by_rule["B602"].code.strip().startswith("subprocess.call(")


def test_same_sql_injection_from_two_tools_is_one_group():
    eq = json.loads((FIX / "equivalences.json").read_text())
    groups = dedupe(all_findings(), eq)
    sql = [g for g in groups if g.path == "invoicing/db.py" and g.line == 13]
    assert len(sql) == 1 and sql[0].tools == ["bandit", "semgrep"]


def test_fingerprint_ignores_line_numbers_and_indentation():
    a = Finding("bandit", "B608", "invoicing/db.py", 13, "medium", 89, "", '    cur.execute("..." % x)')
    b = Finding("bandit", "B608", "invoicing/db.py", 40, "medium", 89, "", 'cur.execute("..."  %  x)')
    assert fingerprint(a) == fingerprint(b)


def test_gate_with_suppressions():
    eq = json.loads((FIX / "equivalences.json").read_text())
    sups, invalid = load_suppressions(json.loads((FIX / "suppressions.json").read_text()))
    assert len(invalid) == 1                       # reason "test" is too short
    active, suppressed = apply_suppressions(dedupe(all_findings(), eq), sups, date(2026, 11, 3))
    assert any(g.key == "weak-hash" for g in suppressed)
    assert gate(active, "high") is False           # SQL injection and shell=True are still there
