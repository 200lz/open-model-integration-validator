# Offline quickstart demonstration

This demonstration uses OMIV's installed public CLI and the existing tracked
[`immutable-pinned.json`](../../runtime-resolution-parity/scenarios/immutable-pinned.json)
scenario. There is no wrapper, generated evidence, output path, clock, randomness,
private key, provider credential, or network request.

The supplied input is `SYNTHETIC`, `DEMONSTRATION_ONLY`,
`NOT_PROVIDER_EVIDENCE`, and `NOT_A_SAFETY_OR_AUTHENTICITY_RESULT`.

From the repository root, run:

```bash
omiv runtime-resolution verify runtime-resolution-parity/scenarios/immutable-pinned.json
```

Expected output:

```text
VALID_CANONICAL_RUNTIME_RESOLUTION_OBJECT schema=omiv.runtime-resolution-scenario-result.v1
```

Expected exit code: `0`.

The command performs the real transition from supplied object through strict
parsing and canonical identity/digest verification to a scoped result whose input
retains explicit limitations. It does not establish current provider state,
artifact bytes, runtime identity, output attribution, safety, or authenticity.

Return to the [documentation index](../../docs/README.md) or the
[main README](../../README.md).
