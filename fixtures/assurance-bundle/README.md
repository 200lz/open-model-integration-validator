# Assurance Bundle v1 conformance fixtures

These requests exercise the portable Phase 6F contract without network, conversion,
or GPU execution.

- `valid-request.json` resolves to `READY`, builds a `COMPLETE` bundle, and verifies
  offline as `COMPLETE` against the tracked Phase 6A exact-comparison evidence.
- `incomplete-request.json` resolves to `BLOCKED`, retains the proposed GPU action in
  the plan, builds an `INCOMPLETE` bundle, and verifies offline as `INCOMPLETE`.

Implementations must not execute the declared costly operation during preflight,
assembly, packing, or verification.
