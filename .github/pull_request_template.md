## Summary

Describe the evidence or behavior changed and why.

## Validation

- [ ] Focused tests pass.
- [ ] Full offline tests pass, or omitted coverage is explained.
- [ ] `ruff check .` and `mypy` pass.
- [ ] Every changed Python file passes scoped `ruff format --check`.
- [ ] Generated evidence is deterministic and its source, digest, and limitations are recorded.

## Public-safety review

- [ ] No credential, customer data, signed URL, raw private header, private payload,
      machine-specific path, or complete copied webpage is included.
- [ ] No model or tokenizer payload is downloaded by default tests or CI.
- [ ] Provider names are descriptive; no endorsement, certification, or production-readiness claim is made.
- [ ] New dependencies and third-party material include an ownership/license review.
