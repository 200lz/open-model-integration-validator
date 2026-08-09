# Contributing to OMIV

OMIV welcomes focused changes that preserve its evidence semantics and offline-first
verification boundary.

1. Open an issue for material schema or compatibility changes.
2. Keep provider-specific collection behind provider-neutral evidence contracts.
3. Add deterministic tests for every semantic change.
4. Never commit credentials, customer data, signed URLs, private payloads, raw model
   or tokenizer payloads, or complete copied webpages.
5. Run `python -m pip install -e '.[dev]'`, `pytest`, `ruff check .`, `mypy`, and
   `python -m compileall -q src tests tools`.
6. Run `ruff format --check` on every Python file changed by the contribution. The
   repository has known historical format debt; do not mix mass formatting with a
   functional change.

Generated evidence must be reproducible, reviewable, and accompanied by source,
scope, digest, and limitations. Public-document evidence must be bounded to the
minimum reviewed claim region. New dependencies require a purpose and license review.

By submitting a contribution, you represent that you have the right to submit it
under Apache-2.0. This project currently uses no separate contributor license
agreement. See [GOVERNANCE.md](GOVERNANCE.md), [SECURITY.md](SECURITY.md), and
[SUPPORT.md](SUPPORT.md).
