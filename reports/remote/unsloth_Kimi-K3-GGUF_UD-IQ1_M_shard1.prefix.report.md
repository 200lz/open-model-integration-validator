# Remote GGUF Prefix Probe

## Result

PASS

## Repository

- Provider: huggingface
- Repository: unsloth/Kimi\-K3\-GGUF
- Requested revision: main
- Resolved revision: 3d4b61ab4b6789d401191c476cbb4567246db8f5
- File: UD\-IQ1\_M/Kimi\-K3\-UD\-IQ1\_M\-00001\-of\-00015\.gguf
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
- Report SHA\-256: c5ca33b43e208fc37c5ac2016f530aabc05642c24dcc915df61f96aff161a1b4
