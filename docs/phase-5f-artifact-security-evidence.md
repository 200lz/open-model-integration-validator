# Phase 5F artifact security evidence architecture

Phase 5F is a normalization and policy layer over bounded security inspection.
It preserves five independent dimensions: artifact identity, inspection
integrity, scanner trust, coverage, and finding policy. Its output is not a
universal safety statement.

The implementation is split as follows:

- `models.py` contains immutable strict records and versioned schema IDs.
- `building.py` owns digest-derived identities and the built-in scanner record.
- `scanning.py` owns local path safety, bounds, static indicators, ZIP metadata,
  execution records, coverage reconstruction, and evidence bundles.
- `policy.py` owns static policy profiles and precedence.
- `evaluation.py` reconstructs layered outcomes and the final verdict.
- `reporting.py` owns bounded loading and deterministic JSON/Markdown.
- `adapters.py` owns external normalized result import and separate governance,
  Passport, and custody records.
- `signing.py` links Phase 5D envelopes without changing their underlying claims.
- `examples.py` regenerates compact synthetic artifacts and canonical outputs.

The scanner never follows symlinks, extracts an archive, deserializes an object,
executes code, loads a plugin, starts a subprocess, or uses the network. ZIP
inspection reads the bounded central directory only. File reads stop at both the
per-file and total plan limits. Exhausted bounds are represented as partial or
failed coverage and cannot satisfy a strict policy.

The built-in inspector detects only declared indicators. File extensions and
magic bytes can indicate unsafe serialization, scripts, or native binaries;
bounded textual patterns can indicate private material, signed URLs, dynamic
imports, shell/process calls, or remote references. These are normalized
findings, not semantic malware conclusions. Absence of an indicator is not proof
of absence of a vulnerability.

Phase 5D adds three active signed-object types and purposes:

- `SECURITY_SCAN_EXECUTION_RECORD` / `SECURITY_SCAN_ISSUANCE`
- `SECURITY_EVIDENCE_BUNDLE` / `SECURITY_EVIDENCE_ISSUANCE`
- `SECURITY_EVALUATION` / `SECURITY_EVALUATION_ISSUANCE`

Signature integrity, key trust, revocation, and expiration remain layered trust
results. A trusted signature does not repair a partial scan or change a FAIL.

The Phase 5E adapter accepts only a subject-matched, policy-matched, digest-valid
evaluation reconstructed from the supplied bundle and selected security policy.
`PASS_WITH_LIMITATIONS` maps to `SATISFIED_WITH_LIMITATIONS` only when that
canonical security policy explicitly permits governance limitations; callers
cannot override this mapping.
FAIL, incomplete coverage, broken evidence, errors, and untrusted required
scanners never become satisfied requirements. Existing Phase 5E decisions are not
rewritten; new governance decisions must be derived as separate objects.

Phase 5F intentionally stops before deployment and runtime verification. A later
phase may consume these records alongside deployment admission, payload integrity,
and runtime observations, but it must not reinterpret a Phase 5F PASS as proof of
runtime safety.
