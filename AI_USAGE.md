## Tools

Claude (Anthropic) wrote the first version of `triage/core.py` and `triage/__main__.py` from the task spec. I ran and reviewed the code myself.

## What AI got wrong

At first, the AI couldn't correctly analyze `security-severity` in SARIF, if it was given as a string, e.g., “8.8”, and not as a float. It also did not fall back to result or rule levels, if `security-severity` was missing. I noticed this while testing the `test_semgrep_uses_security_severity_then_level` function, which also failed as well, and fixed this by converting the string score to a float and also adding fall back logic in `_sarif_severity()` function.

## In my own words


1. Bandit rates the MD5 in `etag()` HIGH and `DB_PASSWORD` LOW. Which would you fix first in Diwan's code, and why?

I'd fix DB_PASSWORD first.

Why: DB_PASSWORD is a hard-coded production secret and a direct security risk (CWE-259). It provides access to the database if revealed. On the other hand, the use of MD5 in etag() is used for HTTP request validation (ETags). Therefore, Bandit's HIGH rating is a context-blind false positive. Static analysis tools blindly assess patterns HIGH, regardless of the actual usage context of the patterns. Thus, a pattern like MD5 is always rated as HIGH by these tools.

2. Why does a suppression need an expiry date?

Suppressions should be time-boxed to ensure temporary risk acceptances do not turn into technical debt or unaddressed security flaws. It requires that development and security teams review previously documented findings and validate if the rationale for accepting the risk is still valid.
