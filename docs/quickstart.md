# OMIV quickstart

This guide installs OMIV from a source clone and verifies one small tracked object.
It requires Python 3.11–3.14. The example needs no model weights, tokenizer files,
credentials, private keys, environment variables, provider access, or ignored local
artifacts.

## Install from source

On Linux or macOS:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

On Windows PowerShell, replace the activation command with:

```powershell
.venv\Scripts\Activate.ps1
```

Editable source installation is not a PyPI release. Creating the environment and
installing dependencies may contact a configured package index. The verification
below performs no network request.

## Run the offline verification

```bash
omiv --version
omiv runtime-resolution verify runtime-resolution-parity/scenarios/immutable-pinned.json
```

Expected output:

```text
0.10.0
VALID_CANONICAL_RUNTIME_RESOLUTION_OBJECT schema=omiv.runtime-resolution-scenario-result.v1
```

Both commands return exit code `0`. For `runtime-resolution verify`, exit code `0`
means only that strict parsing succeeded, the supported schema was recognized,
canonical identity/digest relationships validated, and the supplied tracked
synthetic object is internally valid for that scope. Exit code `2` means malformed
or integrity-invalid input. This example has no policy outcome that uses exit code
`1`; other OMIV commands can use `1` for a valid but scope-limited, unavailable, or
policy-nonpassing result.

## Inspect the evidence

The verified object is
[`runtime-resolution-parity/scenarios/immutable-pinned.json`](../runtime-resolution-parity/scenarios/immutable-pinned.json).
Inspect its typed fields without changing it:

```bash
omiv runtime-resolution inspect runtime-resolution-parity/scenarios/immutable-pinned.json
```

Inspection prints the supplied object as deterministic JSON. The verification flow
is:

```text
supplied object
  -> strict parsing
  -> canonical identity and digest reconstruction
  -> scope-qualified result
  -> explicit limitations
```

## What this proves

- the tracked synthetic object conforms to its registered OMIV schema;
- its identity-bearing content reconstructs the recorded canonical identity;
- the verifier returns a deterministic, bounded result without network access;
- the example works without `reports/raw/kimi_k3_tensors.json`.

## What this does not prove

The object and demonstration are explicitly:

- `SYNTHETIC`
- `DEMONSTRATION_ONLY`
- `NOT_PROVIDER_EVIDENCE`
- `NOT_A_SAFETY_OR_AUTHENTICITY_RESULT`

In particular, this result does **not** imply that:

- a provider request occurred;
- a live alias was resolved;
- a deployment was observed;
- runtime-loaded weights were observed;
- the selected model produced an inference;
- provider authenticity was established;
- publisher authority was established; or
- safety or production readiness was established.

It also does not prove output attribution or complete behavioral equivalence.

## Clean up

Deactivate the virtual environment with `deactivate`. If it was created only for
this checkout, remove `.venv` using the normal safe file-management tools for your
platform after leaving the environment.

Return to the [documentation index](README.md) or the [main README](../README.md).
