## What this pull request changes

<!-- One or two sentences. What is different after this merges? -->

## Why

<!-- The problem this solves, or the gap this fills. Link the issue if there is one. -->

## How it was tested

<!-- The exact commands you ran, and what you checked. -->

```
python -m pytest -q
python -m ruff check src tests tools --exclude tests/fixtures
```

## Checklist

- [ ] The change is one logical thing, not a reformat in disguise.
- [ ] New behaviour has a test, including a negative test where it makes sense.
- [ ] Any new rule carries evidence: a file, a line, and a reason.
- [ ] Documentation is updated if the rule table, the report format or the SARIF output changed.
- [ ] `python -m pytest -q` and `python -m ruff check src tests tools --exclude tests/fixtures` both pass.
- [ ] The commit message explains what changed and why, not just which files changed.
