# AGENTS.md — dsc26-cyb-w04
# Rules for AI assistants working in this repo. P0 = must never break, P1 = important, P2 = preferred.

[P0] Never read, print, commit, or paste the contents of .env files, API keys, tokens, or real production logs; if a secret appears in a diff, stop and say so.
[P0] Never modify anything under fixtures/ — the grader replaces that folder with its own copy.
[P0] Keep all production code inside triage/ and use only the Python standard library; never add a package to requirements.txt.
[P0] Before finishing any change (the security check before any PR), run `python -m pytest -q` from the repository root with the project's virtualenv activated and report the result; never claim tests pass without running them.
[P0] When reading security-severity from SARIF, accept it as a number or a numeric string (e.g. "8.8"); ignore values outside (0, 10]; if absent, fall back to the result level, then the rule default level, then warning.
[P1] Compute fingerprints exactly as SHA-256 of tool|rule_id|path|code with the code's whitespace collapsed to single spaces; never include line numbers.
[P1] A suppression is valid only with a 64-character lowercase hex fingerprint, a reason of at least 10 characters, a non-blank owner, and a parseable expiry date; never raise on a bad entry — return it as invalid.
[P1] A suppression applies only while it has not expired (expires >= today); an expired suppression must not hide a group.
[P1] Every finding from the input must end up in exactly one group — never drop a finding silently.
[P1] When a tool's severity conflicts with the code context (e.g. MD5 in etag() vs DB_PASSWORD), report both the tool rating and the context, and let context decide — never silently downgrade a HIGH.
[P1] When a change modifies a trust boundary, a data flow, or authentication/authorization code, check it against the threat model in dsc26-cyb-w02 (models/rawaj_scoring.yaml): name the affected threat ID in the PR description, or write "no threat affected" with one line saying why.
[P2] Keep the function names and signatures, dedupe ordering, gate thresholds, CLI exit codes, and offline/fixed-seed tests exactly as the README specifies; do not restate the spec here.
