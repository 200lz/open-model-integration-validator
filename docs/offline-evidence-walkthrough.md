# OMIV offline evidence walkthrough

This beginner-oriented walkthrough follows tracked synthetic Open Model Integration
Validator (OMIV) evidence from strict parsing through canonical identity, scoped
interpretation, missing evidence, trust policy, and runtime-resolution boundaries.
After OMIV is installed, every verification command is offline. No step contacts a
model provider, downloads a model or tokenizer, executes inference, loads a runtime,
or needs a private key.

The walkthrough manifest is explicitly
`NON_CANONICAL_DEMONSTRATION_MANIFEST`. It and the walkthrough are labeled
`SYNTHETIC`, `DEMONSTRATION_ONLY`, `NOT_PROVIDER_EVIDENCE`,
`NOT_AN_ASSURANCE_BUNDLE`, and `NOT_A_SAFETY_OR_AUTHENTICITY_RESULT`. They do not
add a canonical schema or copy canonical evidence. Every input remains in its
released Phase 5 or Phase 6A–6E location.

## Before you start

Use Python 3.11–3.14 and install OMIV from the source checkout as described in the
[quickstart](quickstart.md). Installation may contact a configured package index;
the commands below do not use the network. Run them from the repository root.

The shortest complete route uses the fixed-command runner. Its default mode is
read-only:

```bash
python tools/run_offline_evidence_walkthrough.py
```

To include the isolated malformed-input demonstration, supply a temporary directory
outside the checkout. The runner creates and removes only its own child directory;
the final `rmdir` removes the empty directory created by `mktemp`:

```bash
walkthrough_tmp="$(mktemp -d)"
python tools/run_offline_evidence_walkthrough.py \
  --temporary-directory "$walkthrough_tmp"
rmdir "$walkthrough_tmp"
```

The complete run returns `0`, including when an individual evidence command returns
the expected semantic exit `1` or the isolated malformed input returns the expected
exit `2`. An unexpected command result makes the runner fail closed with exit `2`.

## Step 1: confirm the installed version

**Input:** None.

**Command:**

```bash
omiv --version
```

**Expected exit code:** `0`.

**Expected bounded output:**

```text
0.10.0
```

**What it establishes:** the invoked CLI reports the source candidate's package
version.

**What it does not establish:** a `v0.10.0` tag, GitHub release, or PyPI publication.

**Next evidence link:** the tracked
[`immutable-pinned.json`](../runtime-resolution-parity/scenarios/immutable-pinned.json)
scenario.

## Step 2: strictly verify a canonical tracked object

**Input:**
[`runtime-resolution-parity/scenarios/immutable-pinned.json`](../runtime-resolution-parity/scenarios/immutable-pinned.json).

**Command:**

```bash
omiv runtime-resolution verify \
  runtime-resolution-parity/scenarios/immutable-pinned.json
```

**Expected exit code:** `0`.

**Expected bounded output:**

```text
VALID_CANONICAL_RUNTIME_RESOLUTION_OBJECT schema=omiv.runtime-resolution-scenario-result.v1
```

**What it establishes:** strict parsing recognized the supported schema and
reconstructed the synthetic scenario's canonical ID/digest relationships. The runner
also displays its schema, subject ID, scope, result ID, digest, and recorded outcome.

**What it does not establish:** a provider request, alias resolution, deployment,
runtime-loaded identity, inference, authority, authenticity, or safety.

**Next evidence link:** the Phase 6A
[`local.manifest.json`](../payload-integrity/observations/local.manifest.json).

## Step 3: read Phase 6A local payload identity correctly

**Input:**
[`payload-integrity/observations/local.manifest.json`](../payload-integrity/observations/local.manifest.json).

**Command:**

```bash
omiv payload verify-manifest \
  payload-integrity/observations/local.manifest.json
```

**Expected exit code:** `0`.

**Expected bounded output invariant:**

```text
VALID_LOCAL_OBSERVATION
```

The full single-line result includes the reconstructed manifest ID and
`semantic_correctness=NOT_EVALUATED`.

**What it establishes:** the supplied manifest is a valid canonical observation of
59 bytes across four regular files for its declared stable local scope.

**What it does not establish:** remote completeness, semantic correctness,
authenticity, safety, or runtime-loaded identity. Metadata identity is not payload
identity, and artifact identity is not runtime identity.

**Next evidence link:** the Phase 6B
[`metadata-only.snapshot.json`](../reconciliation/snapshots/metadata-only.snapshot.json).

## Step 4: separate Phase 6B remote metadata from payload identity

**Input:**
[`reconciliation/snapshots/metadata-only.snapshot.json`](../reconciliation/snapshots/metadata-only.snapshot.json).

**Command:**

```bash
omiv reconcile verify \
  reconciliation/snapshots/metadata-only.snapshot.json
```

**Expected exit code:** `0`.

**Expected bounded output:**

```text
VALID_CANONICAL_RECONCILIATION_OBJECT schema=omiv.remote-snapshot-manifest.v1 model_safety=NOT_VERIFIED
```

**What it establishes:** the imported snapshot's schema, subject, manifest identity,
requested revision, resolved immutable identifier, and declared metadata scope are
internally valid.

**What it does not establish:** that the opaque remote digest is payload-comparable,
that the listing is complete beyond its imported response scope, current provider
state, publisher authority, authenticity, or model safety. No provider is contacted.

**Next evidence link:** the deliberately incomplete Phase 6B
[`incomplete.json`](../reconciliation/comparisons/incomplete.json) comparison.

## Step 5: preserve unavailable or incomplete evidence

**Input:**
[`reconciliation/comparisons/incomplete.json`](../reconciliation/comparisons/incomplete.json).

**Command:**

```bash
omiv reconcile verify reconciliation/comparisons/incomplete.json
```

**Expected exit code:** `1`—this is an expected semantic result, not malformed input
or a shell failure.

**Expected bounded output:**

```text
VALID_CANONICAL_RECONCILIATION_OBJECT schema=omiv.remote-local-reconciliation-comparison.v1 model_safety=NOT_VERIFIED
```

**What it establishes:** the canonical comparison is valid and explicitly records
`INCOMPLETE_LOCAL_OBSERVATION`; one declared member is missing locally.

**What it does not establish:** exact local reconciliation. Unavailable evidence is
not invalid evidence, and absent evidence is not `PASS`.

**Next evidence link:** the Phase 6C
[`sampled.json`](../quantization-fidelity/evidence/sampled.json) evidence.

## Step 6: interpret bounded Phase 6C fidelity evidence

**Input:**
[`quantization-fidelity/evidence/sampled.json`](../quantization-fidelity/evidence/sampled.json).

**Command:**

```bash
omiv quantization verify quantization-fidelity/evidence/sampled.json
```

**Expected exit code:** `0`.

**Expected bounded output:**

```text
CONFORMS_FOR_DECLARED_SCOPE evidence=quantization_evidence_e6d2b534a1398275c86f0b51a3373e69 numerical=SAMPLED_WITHIN_POLICY
```

**What it establishes:** deterministic sampled numerical evidence satisfied its
declared sampling policy and canonical identity checks.

**What it does not establish:** full-population fidelity, behavioral equivalence,
authority, security, safety, runtime identity, or production readiness. Finite
samples are finite evidence.

**Next evidence link:** the Phase 6D
[`synthetic.json`](../tokenizer-configuration-parity/evidence/synthetic.json) evidence.

## Step 7: interpret Phase 6D tokenizer/configuration scope

**Input:**
[`tokenizer-configuration-parity/evidence/synthetic.json`](../tokenizer-configuration-parity/evidence/synthetic.json).

**Command:**

```bash
omiv tokenizer-config verify \
  tokenizer-configuration-parity/evidence/synthetic.json
```

**Expected exit code:** `0`.

**Expected bounded output:**

```text
PARITY_ESTABLISHED_FOR_DECLARED_SCOPE evidence=tokenizer_evidence_f290ada7bb4a2cc746a6bd807b0a39da scope=COMPLETE_DECLARED_TOKENIZER_ASSET_SET
```

**What it establishes:** the supplied tokenizer/configuration objects satisfy the
complete declared asset-set comparison scope.

**What it does not establish:** behavioral equivalence, runtime compatibility,
authenticity, publisher authority, or security. Any finite probe remains evidence
only for the inputs and transformations it actually covers.

**Next evidence link:** the tracked Phase 5
[`trusted-transformation.signed-envelope.json`](../trust/examples/trusted-transformation.signed-envelope.json).

## Step 8: separate signature and trust policy from publisher authority

**Input:** a tracked signed envelope, trust bundle, trust policy, and evaluation
context, including
[`project-trust-bundle.json`](../trust/examples/project-trust-bundle.json).

**Command:**

```bash
omiv trust verify \
  --input trust/examples/trusted-transformation.signed-envelope.json \
  --trust-bundle trust/examples/project-trust-bundle.json \
  --policy trust/examples/project-trust-policy.json \
  --evaluation-context trust/examples/evaluation-context.json
```

**Expected exit code:** `0`.

**Expected bounded output invariant:**

```text
TRUSTED_SIGNATURE_WITH_LIMITATIONS
```

The following lines explicitly retain `identity_verification=UNVERIFIED`,
`claim_independently_proven=NO`, `runtime=NOT_CHECKED`, and
`approval=NOT_AVAILABLE`.

**What it establishes:** signature integrity and acceptance under the supplied
static trust bundle, policy, and evaluation context.

**What it does not establish:** rightful publisher authority, real-world identity,
provider authenticity, approval, runtime identity, or safety. Signature validity is
not publisher authority; policy satisfaction is not safety or deployment approval.

**Next evidence link:** the Phase 6E
[`t0.json`](../runtime-resolution-parity/receipts/t0.json) receipt.

## Step 9: distinguish the requested identifier from resolved identity

**Input:**
[`runtime-resolution-parity/receipts/t0.json`](../runtime-resolution-parity/receipts/t0.json).

**Command:**

```bash
omiv runtime-resolution verify runtime-resolution-parity/receipts/t0.json
```

**Expected exit code:** `0`.

**Expected bounded output:**

```text
VALID_CANONICAL_RUNTIME_RESOLUTION_OBJECT schema=omiv.registry-resolution-receipt.v1
```

**What it establishes:** canonical receipt identity and the supplied distinction
between a requested identifier object and resolved identifier
`synthetic-model-A`. The receipt says its observation level is `CALLER_DECLARED` and
authority is `NOT_ESTABLISHED`.

**What it does not establish:** live alias resolution, current routing, deployment
observation, provider authority, payload identity, or runtime-loaded weights. A
resolved slug is not a payload digest.

**Next evidence link:** the composite Phase 6E
[`evidence.json`](../runtime-resolution-parity/evidence.json).

## Step 10: stop at the runtime-resolution boundary

**Input:**
[`runtime-resolution-parity/evidence.json`](../runtime-resolution-parity/evidence.json).

**Command:**

```bash
omiv runtime-resolution verify runtime-resolution-parity/evidence.json
```

**Expected exit code:** `1`—again, this is the expected semantic result for a valid
partial evidence object.

**Expected bounded output:**

```text
PARTIAL_FOR_DECLARED_SCOPE evidence=runtime_resolution_evidence_1b47f3d0a4c705bf80b6e79bcce019ea scope=declared.phase6e.scope
```

**What it establishes:** the canonical Phase 6E object is internally valid and
truthfully reports partial declared-scope coverage.

**What it does not establish:** output-to-weight attribution. Its output-provenance
coverage is `0/1` because weight attribution is unavailable. An output digest is not
proof of which weights produced it; no inference is performed.

**Next evidence link:** the [evidence-boundary summary](#evidence-boundary-summary).

## Step 11: see malformed input return exit 2

Use the runner's `--temporary-directory` command shown under
[Before you start](#before-you-start). It creates a bounded temporary copy of the
Step 2 scenario, changes only its recorded digest, invokes the same real verifier,
observes exit `2`, and removes the temporary copy. It hashes the tracked source
before and after and fails if that source changes.

**Expected runner line:**

```text
MALFORMED_INPUT_DETECTED exit=2 source_unchanged=YES temporary_files_removed=YES
```

Exit `2` means the temporary input is integrity-invalid. It does not change or cast
doubt on the tracked source object.

## External artifact: clean-checkout NOT_AVAILABLE

The ignored `reports/raw/kimi_k3_tensors.json` inventory is not distributed and is
never opened, copied, generated, downloaded, or required by this walkthrough. A
clean checkout therefore retains the recorded expected identity while reporting:

```text
clean_checkout=NOT_AVAILABLE required=NO expected_identity=RECORDED_NOT_OBSERVED
```

The expected identity is size `115542096` and SHA-256
`15a6757becb69c56492fdb630d6853696082a9ec6109bcea05f387a5052ea469`.
This record does not make the absent bytes verified. `NOT_AVAILABLE` is a scoped
availability fact, not `INVALID`, and never becomes `PASS` by omission.

## Exit-code interpretation

| Exit | Meaning in this walkthrough |
| --- | --- |
| `0` | Valid or satisfactory for the exact command scope; read the limitations before making a broader claim. |
| `1` | Valid but incomplete, unavailable, not evaluated, or policy non-pass; expected for Steps 5 and 10. |
| `2` | Malformed, unsafe, integrity-invalid, or unsupported input; unexpected during normal tracked-input steps. |

The runner returns `0` when all per-step exits and exact bounded outputs match this
contract. It returns `2` for an unexpected exit, stdout or stderr, source digest,
schema, manifest, path, timeout, or size condition. Raw output is rejected if it
contains a traceback, warning, unsafe control, or absolute machine path; these values
are never made to look valid by presentation sanitization.

## Evidence-boundary summary

The complete journey preserves these distinctions:

```text
declaration != observation
metadata identity != payload identity
artifact identity != runtime-loaded identity
signature validity != publisher authority
policy satisfaction != safety or deployment approval
finite probes != behavioral equivalence
output digest != weight attribution
unavailable evidence != invalid evidence
absent evidence != PASS
```

No step claims provider authenticity, publisher authority, current provider state,
runtime-loaded weights, inference-used weights, inference execution, behavioral
equivalence, safety or security certification, production readiness, complete model
assurance, or Phase 6F Assurance Bundle support.

Continue with the [architecture](architecture.md), the
[technical reference](reference/technical-reference.md), or the
[roadmap](roadmap.md). Return to the [documentation index](README.md) or the
[main README](../README.md).
