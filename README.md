# dsc26-cyb-w04 · Diwan SAST triage and gate

DSC Summer Internship 2026 · Cybersecurity track · Week 4 (SAST/DAST and finding triage)
**Python 3.12 · pytest 9.1.1 · standard library only** · expected time 3 to 4 hours · everything runs offline

## Scenario

Heba wants a gate in Diwan's CI that her delivery managers will not switch off. It reads Semgrep's
SARIF and Bandit's JSON, merges duplicates, ignores what is already in the baseline or properly
suppressed, and fails the build only for new findings at or above an agreed severity. DSC gives you
real output from both tools on a small fixture repository. You build `triage`. You do not need Semgrep
or Bandit installed: the task only reads their output.

## Set up

1. On GitHub create a **public** repository in your own account named exactly `dsc26-cyb-w04`, with no README.
2. Unzip this starter into a folder called `dsc26-cyb-w04`, then:

```bash
git init -b main
uv venv --python 3.12
source .venv/bin/activate            # Windows: .venv\Scripts\activate
uv pip install -r requirements.txt   # pinned versions; you cannot add packages
python -m pytest -q                  # the 5 public tests fail until you build the task
git add . && git commit -m "chore: starter from DSC"
git remote add origin https://github.com/<your-username>/dsc26-cyb-w04.git
git push -u origin main
```

Always run tests with `python -m pytest` from the repository root, the way the grader does.

## Files

```
triage/__init__.py
triage/core.py            # fill in every function; keep the names and signatures
triage/__main__.py        # python -m triage ...
fixtures/diwan_invoicing/ # three small Python files with deliberate problems (never imported or run)
fixtures/rules.yaml       # the five Semgrep rules used to produce the SARIF
fixtures/semgrep.sarif    # real output of Semgrep 1.178.0 (5 results)
fixtures/bandit.json      # real output of Bandit 1.9.4 (11 results)
fixtures/equivalences.json, fixtures/baseline.json, fixtures/suppressions.json
tests/test_public.py
AI_USAGE.md
requirements.txt
```

**Do not edit `fixtures/`.** The grader replaces the whole folder with DSC's copy before it runs.

## What to build

### 1. `triage/core.py`

```python
SEVERITIES = ["info", "low", "medium", "high", "critical"]   # lowest to highest

@dataclass(frozen=True)
class Finding:
    tool: str            # "semgrep" or "bandit"
    rule_id: str
    path: str            # normalised, see below
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
    # properties: .tools -> sorted list of tool names; .fingerprints -> sorted list of member fingerprints

@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    reason: str
    expires: date
    by: str

def normalize_path(raw: str, project: str) -> str: ...
def fingerprint(f: Finding) -> str: ...
def load_semgrep_sarif(path, project: str) -> list[Finding]: ...
def load_bandit(path, project: str) -> list[Finding]: ...
def issue_key(f: Finding, equivalences: dict[str, str]) -> str: ...
def dedupe(findings: list[Finding], equivalences: dict[str, str] | None = None) -> list[Group]: ...
def load_suppressions(entries: list[dict]) -> tuple[list[Suppression], list[dict]]: ...
def apply_suppressions(groups, suppressions, today: date) -> tuple[list[Group], list[Group]]: ...
def diff_baseline(groups, baseline: set[str]) -> tuple[list[Group], list[Group], list[str]]: ...
def gate(new_active: list[Group], fail_on: str) -> bool: ...
```

- **`normalize_path(raw, project)`**: turn backslashes into `/`, drop a leading `file://`, drop empty
  and `.` segments, and if a segment equals `project`, keep only what comes after its **last**
  occurrence. `./invoicing/web.py`, `diwan_invoicing\invoicing\web.py` and
  `/home/runner/work/diwan_invoicing/diwan_invoicing/invoicing/web.py` all become `invoicing/web.py`.
  Both loaders store normalised paths.
- **`load_semgrep_sarif`**: one `Finding` per result in every run (`tool` is `"semgrep"`, `line` is
  `region.startLine`, `message` is `message.text`). Join each result to its rule by id within its run.
  Severity: if the rule's `properties["security-severity"]` parses as a number greater than 0 and at
  most 10, map it (9.0 and above critical, 7.0 and above high, 4.0 and above medium, otherwise low).
  Otherwise use the result's `level`, else the rule's `defaultConfiguration.level`, else `warning`,
  mapped error→high, warning→medium, note→low, none→info. CWE: the first rule tag that starts
  `CWE-<digits>`, else `None`. `code`: the first line of `region.snippet.text`, or `""`.
- **`load_bandit`**: one `Finding` per entry in `results` (`tool` is `"bandit"`, `rule_id` is
  `test_id`, `line` is `line_number`, `message` is `issue_text`). Severity HIGH→high, MEDIUM→medium,
  LOW→low (anything else info), then one step lower if `issue_confidence` is LOW (low becomes info;
  info stays info). CWE from `issue_cwe.id`, else `None`. `code`: Bandit's `code` field holds several
  lines, each starting with its line number and a space; take the text of the line whose number
  **equals** `line_number`, else `""`.
- **`fingerprint(f)`**: SHA-256 hex of `f"{tool}|{rule_id}|{path}|{code}"` where `code` has its
  whitespace collapsed to single spaces and stripped (`" ".join(code.split())`). Line numbers are not
  part of it. The hidden tests compute this formula themselves to build baselines and suppressions, so
  follow it exactly.
- **`issue_key(f, equivalences)`**: `equivalences.get(f"{tool}:{rule_id}")` if present; else
  `f"CWE-{cwe}"`; else `f"{tool}:{rule_id}"`.
- **`dedupe`**: findings with the same path, line and issue key form one group. Group severity is the
  highest of its members. Sort groups by severity (highest first), then path, line, key. The output must
  not depend on the order of the input (including the members' fingerprints and tools, which the
  properties return sorted). Every input finding ends up in exactly one group.
- **`load_suppressions(entries)`**: an entry is valid if it has a 64-character lowercase hex
  `fingerprint`, a `reason` of at least 10 characters after stripping, a non-blank `by`, and an `expires`
  that parses with `date.fromisoformat`. Return `(valid, invalid_entries)`, never raise for a bad entry.
- **`apply_suppressions(groups, suppressions, today)`**: a group is suppressed if any member's
  fingerprint matches a suppression that has not expired (`expires >= today`; a suppression expiring
  today still applies). Return `(active, suppressed)`, both in input order.
- **`diff_baseline(groups, baseline)`**: a group is existing if any member fingerprint is in the
  baseline, otherwise new. `fixed` is the sorted list of baseline fingerprints that no group contains.
  Return `(new, existing, fixed)`, `new` and `existing` in input order.
- **`gate(new_active, fail_on)`**: `True` (pass) unless any group has severity at or above `fail_on`.

### 2. `triage/__main__.py`

```
python -m triage --sarif S --bandit B --project NAME [--equivalences E] [--baseline BASE]
                 [--suppressions SUP] [--today YYYY-MM-DD] [--fail-on high]
```

Prints one JSON object with `passed`, `new`, `existing`, `suppressed` (lists of groups as objects with
`key`, `path`, `line`, `severity`, `tools`, `fingerprints`), `fixed` and `invalid_suppressions` (a
count). Exit 0 if the gate passes, 1 if it fails, 2 if an input file is missing, unreadable or not valid
JSON. Suppressions apply before the baseline comparison: dedupe, then `apply_suppressions`, then
`diff_baseline` on the active groups, then `gate` on the new ones. `--today` defaults to today's date,
`--fail-on` to `high`. `equivalences.json` is a JSON object, `baseline.json` a JSON list of
fingerprints, `suppressions.json` a JSON list of entries.

## Public tests

`tests/test_public.py`: SARIF severity from the score and the level, Bandit's low-confidence downgrade,
one group for the SQL injection both tools found, fingerprints that ignore line numbers and indentation,
and the gate with the fixture's suppressions. They are a smoke test, not the grade.

## How grading works

1. Push, then press **Submit for grading** on DSC Hex. The grader pins your latest commit, clones it,
   **replaces `fixtures/` with DSC's copy**, copies in DSC's hidden tests and runs
   `python -m pytest -q -p no:cacheprovider --timeout=30 tests_hidden/` from the repository root with
   Python 3.12, the pinned packages and the network off: 30 seconds per test, 3 minutes in total.
2. Before the run the grader deletes any root `conftest.py`, ignores pytest settings in config files,
   and removes top-level files that would shadow a standard-library or test-tool module. Keep your code
   inside `triage/`.
3. If `AI_USAGE.md` is missing or lacks any of the headings `## Tools`, `## What AI got wrong`,
   `## In my own words`, the grader stops and scores 0 with that reason.
4. Score 0 to 100; per hidden test you see its public name, pass or fail and a short hint. Each ID passes
   only if every case under it passes. A hidden test that cannot import a name fails on its own; the
   others still run. The property test uses fixed seeds.
5. 5 grader runs per task per day. Late policy: ×1.0 within 72 hours of the W4 session starting, ×0.6
   for the following 7 days, ×0.5 after that until Thu 3 Dec 23:59. W5 reopens W4 at ×1.0.

### Hidden tests

| ID | Public name | What it checks | Weight |
|---|---|---|---|
| H01 | SARIF severity: score first, then levels | `security-severity` of exactly 9.0, 7.0 and 4.0 (and 3.9, and a number rather than a string); `0.0`, `"abc"` and `11` ignored; the score beats the result level; a result `level` overriding the rule default; a rule with no default configuration | 10 |
| H02 | SARIF: CWE from tags, several runs | Tags without a CWE give `None`; the first CWE tag wins; a file with two runs yields findings from both | 6 |
| H03 | Bandit: severity, confidence, missing CWE | Every severity × confidence combination, including LOW/LOW → info and an unknown severity; a result with no `issue_cwe` | 8 |
| H04 | Bandit: the right line from the code block | Line 9 vs 10 vs 100 in the same block; line 10 in a block of lines 99–101; a finding on the last line of a file | 6 |
| H05 | paths: one spelling per file | Leading `./`, backslashes, `file://` URIs, an absolute CI path with the project name twice, a Windows path, empty and `.` segments; both loaders normalise | 8 |
| H06 | fingerprints survive reformatting | Stable under line shifts and re-indentation (spaces and tabs); different for a different tool, rule, path or code; 64 hex characters; equal to the documented formula | 8 |
| H07 | dedupe: same line and same issue only | Merges across tools by CWE and by the equivalence table; keeps B501 and B113 apart; group severity is the maximum; the public fixture's 11 groups | 10 |
| H08 | dedupe: deterministic order | Severity, path, line, key; same result for shuffled input | 4 |
| H09 | suppressions: reason, owner, expiry | Valid entry applies; expired yesterday does not; expiring today does; short reason, missing or blank `by`, bad fingerprint (uppercase, 63 characters), bad or missing date are invalid | 10 |
| H10 | one suppressed member hides the group | A suppression on the Bandit fingerprint hides the merged Semgrep + Bandit group | 4 |
| H11 | baseline: new, existing, fixed | Including a finding whose line moved since the baseline, and `fixed` sorted | 8 |
| H12 | gate thresholds | `fail_on` low, medium, high and critical against mixed groups; an empty list passes | 6 |
| H13 | CLI: end to end on a second fixture set | DSC's own SARIF, Bandit, baseline and suppression files from a different repository: exit codes 0, 1 and 2 (a missing file and a file that is not JSON) and the JSON keys | 8 |
| H14 | no finding is ever lost | Property test: the group sizes add up to the input count, members match their group's path and line, severity is the maximum | 4 |
| | | **Total** | **100** |

**Anti-cheating notes.** H13 uses a second, private fixture repository scanned by the same tool
versions, so code that special-cases the public fixture's paths or rule ids fails. H14 is a property
test. The suppression and baseline files in the hidden tests are generated from the documented
fingerprint formula, so a fingerprint that does not follow the spec loses H09–H11 together; check yours
against the public test first.

## AI tools

AI tools are allowed. `AI_USAGE.md` must keep its three headings (`## Tools`, `## What AI got wrong`,
`## In my own words`). Under `## In my own words`, without AI:

1. Bandit rates the MD5 in `etag()` HIGH and `DB_PASSWORD` LOW. Which would you fix first in Diwan's code, and why?
2. Why does a suppression need an expiry date?

The grader does not score the content, but it scores 0 if the file or a heading is missing.

## Rules

- Defensive and offline. Standard library only; you cannot add packages. Never point a scanner at
  anything you do not own or have written permission to test.
