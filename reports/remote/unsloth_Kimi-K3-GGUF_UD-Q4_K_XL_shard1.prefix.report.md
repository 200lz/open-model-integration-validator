# Remote GGUF Prefix Probe

## Result

PASS

## Repository

- Provider: huggingface
- Repository: unsloth/Kimi\-K3\-GGUF
- Requested revision: main
- Resolved revision: 3d4b61ab4b6789d401191c476cbb4567246db8f5
- File: UD\-Q4\_K\_XL/Kimi\-K3\-UD\-Q4\_K\_XL\-00001\-of\-00032\.gguf
- Requested range: 0\-7
- Response bytes: 8
- Response SHA\-256: 527ee9a8eac07fc69af277c264ea5bf5c0f037c442b5c3336c18aa10d2096bd6
- GGUF magic valid: true
- GGUF version: 3
- Claim: bounded GGUF prefix identity only; no payload claim

## Findings

### RANGE\-001

- Status: PASS
- Message: HTTPS and provider host policy validated\.
- Evidence:

    {}

### RANGE\-002

- Status: PASS
- Message: Exactly eight response bytes were accepted\.
- Evidence:

    {}

### RANGE\-003

- Status: PASS
- Message: Content\-Range matched bytes 0 through 7\.
- Evidence:

    {}

### RANGE\-004

- Status: PASS
- Message: Response body length was eight bytes\.
- Evidence:

    {}

### RANGE\-005

- Status: PASS
- Message: Artifact size matched snapshot metadata\.
- Evidence:

    {}

### RANGE\-006

- Status: PASS
- Message: GGUF magic and little\-endian version prefix are present\.
- Evidence:

    {}

## Limitations

- Only bytes 0 through 7 were requested\.
- Complete metadata, tensors, split headers, and payloads were not inspected\.

## Integrity

- Report schema: omiv\.remote\-gguf\-prefix\-report\.v1
- Canonicalization: omiv\-json\-v1
- Report SHA\-256: 8b1294201d1c24074778949e9a334b16df7d9f0a06ed2a797532b128cd9dbbe0
