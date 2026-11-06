"""triage: read Semgrep SARIF and Bandit JSON, dedupe, suppress, diff a baseline, gate a build.

Fill in every function. Keep the names and signatures exactly as they are: the grader imports them.
The full rules are in README.md ("What to build").
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from datetime import date

SEVERITIES = ["info", "low", "medium", "high", "critical"]   # lowest to highest


@dataclass(frozen=True)
class Finding:
    tool: str            # "semgrep" or "bandit"
    rule_id: str
    path: str            # normalised, see normalize_path
    line: int
    severity: str        # one of SEVERITIES
    cwe: int | None
    message: str
    code: str            # the source text of the finding's line, as reported by the tool


@dataclass
class Group:
    key: str             # the issue key shared by its findings
    path: str
    line: int
    severity: str        # the highest severity among its findings
    findings: list[Finding] = field(default_factory=list)

    @property
    def tools(self) -> list[str]:
        """Sorted list of the tool names of the members."""
        return sorted(f.tool for f in self.findings)

    @property
    def fingerprints(self) -> list[str]:
        """Sorted list of the members' fingerprints."""
        return sorted(fingerprint(f) for f in self.findings)


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    reason: str
    expires: date
    by: str


_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


def normalize_path(raw: str, project: str) -> str:
    p = raw.replace("\\", "/")
    if p.startswith("file://"):
        p = p[len("file://"):]
    parts = [seg for seg in p.split("/") if seg not in ("", ".")]
    for i in range(len(parts) - 1, -1, -1):
        if parts[i] == project:
            return "/".join(parts[i + 1:])
    return "/".join(parts)


def fingerprint(f: Finding) -> str:
    code = " ".join(f.code.split())
    text = f"{f.tool}|{f.rule_id}|{f.path}|{code}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _security_score(value) -> float | None:
    """A usable security-severity is a number in (0, 10]; anything else is ignored."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        score = float(value)
    elif isinstance(value, str):
        try:
            score = float(value.strip())
        except ValueError:
            return None
    else:
        return None
    if math.isnan(score) or not (0 < score <= 10):
        return None
    return score


_LEVELS = {"error": "high", "warning": "medium", "note": "low", "none": "info"}


def _sarif_severity(result: dict, rule: dict) -> str:
    props = rule.get("properties") or {}
    score = _security_score(props.get("security-severity"))
    if score is not None:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"
    level = result.get("level")
    if level is None:
        level = (rule.get("defaultConfiguration") or {}).get("level")
    if level is None:
        level = "warning"
    return _LEVELS.get(level, "medium")


def _sarif_cwe(rule: dict) -> int | None:
    tags = (rule.get("properties") or {}).get("tags") or []
    for tag in tags:
        m = re.match(r"CWE-(\d+)", tag) if isinstance(tag, str) else None
        if m:
            return int(m.group(1))
    return None


def load_semgrep_sarif(path, project: str) -> list[Finding]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    findings: list[Finding] = []
    for run in data.get("runs") or []:
        rules = {}
        for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules") or []:
            rules[rule.get("id")] = rule
        for res in run.get("results") or []:
            rule_id = res.get("ruleId")
            rule = rules.get(rule_id, {})
            loc = (res.get("locations") or [{}])[0].get("physicalLocation") or {}
            region = loc.get("region") or {}
            uri = (loc.get("artifactLocation") or {}).get("uri", "")
            snippet = (region.get("snippet") or {}).get("text") or ""
            code = snippet.splitlines()[0] if snippet else ""
            findings.append(Finding(
                tool="semgrep",
                rule_id=rule_id,
                path=normalize_path(uri, project),
                line=int(region.get("startLine", 0)),
                severity=_sarif_severity(res, rule),
                cwe=_sarif_cwe(rule),
                message=(res.get("message") or {}).get("text", ""),
                code=code,
            ))
    return findings


_BANDIT_SEV = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def _bandit_code_line(block: str, line_number: int) -> str:
    for raw in (block or "").split("\n"):
        m = re.match(r"^(\d+) ?(.*)$", raw)
        if m and int(m.group(1)) == line_number:
            return m.group(2)
    return ""


def load_bandit(path, project: str) -> list[Finding]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    findings: list[Finding] = []
    for r in data.get("results") or []:
        sev = _BANDIT_SEV.get(r.get("issue_severity"), "info")
        if r.get("issue_confidence") == "LOW":
            sev = SEVERITIES[max(0, _SEV_RANK[sev] - 1)]
        cwe_obj = r.get("issue_cwe")
        cwe = cwe_obj.get("id") if isinstance(cwe_obj, dict) else None
        line = int(r.get("line_number", 0))
        findings.append(Finding(
            tool="bandit",
            rule_id=r.get("test_id"),
            path=normalize_path(r.get("filename", ""), project),
            line=line,
            severity=sev,
            cwe=int(cwe) if cwe is not None else None,
            message=r.get("issue_text", ""),
            code=_bandit_code_line(r.get("code", ""), line),
        ))
    return findings


def issue_key(f: Finding, equivalences: dict[str, str]) -> str:
    own = f"{f.tool}:{f.rule_id}"
    if own in equivalences:
        return equivalences[own]
    if f.cwe is not None:
        return f"CWE-{f.cwe}"
    return own


def dedupe(findings: list[Finding], equivalences: dict[str, str] | None = None) -> list[Group]:
    eq = equivalences or {}
    buckets: dict[tuple, list[Finding]] = {}
    for f in findings:
        buckets.setdefault((f.path, f.line, issue_key(f, eq)), []).append(f)
    groups = []
    for (path, line, key), members in buckets.items():
        top = max((m.severity for m in members), key=_SEV_RANK.__getitem__)
        groups.append(Group(key=key, path=path, line=line, severity=top, findings=members))
    groups.sort(key=lambda g: (-_SEV_RANK[g.severity], g.path, g.line, g.key))
    return groups


def load_suppressions(entries: list[dict]) -> tuple[list[Suppression], list[dict]]:
    valid: list[Suppression] = []
    invalid: list[dict] = []
    for e in entries:
        try:
            fp = e["fingerprint"]
            reason = e["reason"]
            by = e["by"]
            if not (isinstance(fp, str) and _HEX64.match(fp)):
                raise ValueError("fingerprint")
            if not (isinstance(reason, str) and len(reason.strip()) >= 10):
                raise ValueError("reason")
            if not (isinstance(by, str) and by.strip()):
                raise ValueError("by")
            expires = date.fromisoformat(e["expires"])
            valid.append(Suppression(fp, reason, expires, by))
        except Exception:
            invalid.append(e)
    return valid, invalid


def apply_suppressions(groups: list[Group], suppressions: list[Suppression],
                       today: date) -> tuple[list[Group], list[Group]]:
    live = {s.fingerprint for s in suppressions if s.expires >= today}
    active: list[Group] = []
    suppressed: list[Group] = []
    for g in groups:
        (suppressed if live.intersection(g.fingerprints) else active).append(g)
    return active, suppressed


def diff_baseline(groups: list[Group], baseline: set[str]) -> tuple[list[Group], list[Group], list[str]]:
    base = set(baseline)
    new: list[Group] = []
    existing: list[Group] = []
    seen: set[str] = set()
    for g in groups:
        fps = g.fingerprints
        seen.update(fps)
        (existing if base.intersection(fps) else new).append(g)
    fixed = sorted(base - seen)
    return new, existing, fixed


def gate(new_active: list[Group], fail_on: str) -> bool:
    """True means the build passes."""
    threshold = _SEV_RANK[fail_on]
    return not any(_SEV_RANK[g.severity] >= threshold for g in new_active)
