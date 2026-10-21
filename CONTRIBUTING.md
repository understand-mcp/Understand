# Contributing to UNDERSTAND

Thanks for looking at this. UNDERSTAND is a static analysis engine, a CLI and an
MCP server, all over one analysis core. Contributions are welcome: rules, parsers,
languages, report formats, documentation and bug reports all count.

Before you start: read [SECURITY.md](SECURITY.md) if you want to report a
vulnerability rather than a bug, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for
the ground rules of participation.

## The one rule that matters

**A finding is a claim, and a claim needs evidence.**

Every finding this tool emits carries the file, the line, the rule that fired and
the reasoning that produced it. If you add a rule, it must be able to show why it
fired, on which line, and what the reader should do about it. A rule that can only
say "this looks wrong" does not belong here. The engine's whole value is that a
reader can check its work and disagree with it.

The second rule follows from the first: **false positives cost more than misses.**
A scanner that cries wolf gets switched off. If your rule is noisy, ship it
disabled, or narrow it until the noise is gone. Read
[docs/extending.md](docs/extending.md) for how the rule tables are structured.

## Setting up

```bash
git clone https://github.com/understand-mcp/Understand.git
cd Understand
python -m venv .venv && . .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

The optional `ts` extra adds the tree-sitter grammars for TypeScript and
JavaScript:

```bash
pip install -e ".[dev,ts]"
```

Without those wheels the engine falls back to its lexical parser for TS/JS. Both
paths are tested.

## Running the checks

```bash
python -m pytest -q
python -m ruff check src tests tools --exclude tests/fixtures
python -m mypy src
```

All three must pass. The tests and the linter run in CI on Linux and Windows across
Python 3.11, 3.12 and 3.13, and the type check runs once on Linux, so a change
that only works on your machine will be caught. macOS runs in its own workflow,
because a lack of macOS runners must not be able to block a merge.

If your change touches the map renderer or the report HTML, also check the output
visually:

```bash
understand scan . --deep --cross-module -o map.html --open
```

## Adding a rule

1. Find the analyzer that owns the rule family in
   `src/understand/engine/analyzers/`. Security rules live in
   `security_analysis.py`, correctness rules in the bug analyzers.
2. Add the rule id, title, category and severity to the table at the top of that
   file. Rule ids are stable and appear in SARIF output and in user
   configuration, so never renumber an existing one.
3. Implement the detection and attach `Evidence` with a file, a start line and
   an end line. A finding with no evidence is a bug.
4. Add a fixture under `tests/fixtures/` and a test that asserts the rule fires
   on it, plus a test that asserts it does **not** fire on a near-miss. The
   negative test is the one that keeps the rule honest.
5. Document the rule in the rule table in `docs/`.

## Adding a language

Parsing is behind a small interface: `parse_module()` in
`src/understand/engine/parsing.py` dispatches on the detected language, and
`src/understand/engine/symbol_index.py` provides the symbols. A new language
needs a parser, a language spec in `src/understand/engine/language_detection.py`
and fixtures. Python uses the stdlib `ast` module; TypeScript and JavaScript use
tree-sitter grammars from the `ts` extra.

Call target resolution is currently by name only, so a new language gives you an
exact parse and an approximate graph. That is the honest limit and it is stated
in the README rather than hidden.

## Pull requests

- One logical change per pull request. A rule plus its fixtures and tests is one
  change; a reformat of the whole tree is a different one.
- Write the commit message for a reader six months from now: what changed and
  why, not a list of files.
- Say what you tested and what you did not.
- If you change the report format, the SARIF output or the rule table, update
  the docs in the same pull request.
- CI must be green before a pull request is merged.

## Reporting a bug

Use the bug report template. The three things that make a report useful are the
repository or code you ran it on, the exact command, and the output you got
versus the output you expected. A finding that is wrong is a bug: paste the
finding and say which part of it does not hold.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Be direct,
be kind, and argue about the tool rather than about the person using it.
