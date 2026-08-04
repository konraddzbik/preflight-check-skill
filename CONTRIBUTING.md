# Contributing

Thanks for helping improve `preflight-check-skill`. Pull requests are welcome —
new detectors, fewer false positives, better docs.

## Golden rule: never commit a real secret

All test fixtures must use **synthetic, checksum-valid-but-fake** values — never a
real key or a real person's data. CI runs `gitleaks` against every push and PR to
enforce this. If `gitleaks` flags your change, fix the fixture; do not add a
blanket allowlist.

## Development setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

Optional but recommended: install `gitleaks` locally so the cloud-key detectors
run (the suite passes without it — it falls back to regex-only mode).

## Running the checks

```bash
pytest -q                       # full suite (109+ tests)
pytest --cov=core --cov-report=term-missing
ruff check .                    # lint
gitleaks detect --source . --config .gitleaks.toml --no-banner
```

All four must pass before a PR is mergeable — they mirror CI exactly.

## Adding or changing a detector

Most changes need **no Python code** — the pattern catalog lives in
`core/catalog.yaml`:

```yaml
polish_pii:
  - id: PESEL
    pattern: '\b\d{11}\b'
    validator: validate_pesel   # optional; a name from core/detectors/validators.py
    severity: critical           # critical | high | medium | low
    enabled: true
```

- If your pattern needs a checksum/format check to avoid false positives, add a
  `validate_*` function in `core/detectors/validators.py` and register it in the
  `VALIDATORS` dict, then reference it by name in the catalog.
- Always add a test with a **valid** example (should redact) and an **invalid**
  look-alike (should NOT redact) — checksum validation is the whole point.
- **Patterns must be linear-time.** The hook runs regexes over untrusted pasted
  text; avoid nested/ambiguous unbounded quantifiers (`(a+)+`, a char class that
  also contains the following literal). Bound quantifiers with `{m,n}` where a
  real maximum exists (see `EMAIL`). A pattern that can backtrack catastrophically
  will hang the hook.

## Commit / PR conventions

- Keep PRs focused; one logical change per PR.
- Include tests for any behavior change.
- Update `README.md` and `CHANGELOG.md` when user-facing behavior changes.

## Reporting security issues

Do **not** open a public issue for anything that could expose a live secret — see
[SECURITY.md](SECURITY.md).
