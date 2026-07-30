# Remote Split GGUF Report

## Result

PASS

## Pinned Collection

- Repository: unsloth/Kimi\-K3\-GGUF
- Resolved revision: 3d4b61ab4b6789d401191c476cbb4567246db8f5
- Snapshot SHA-256: a450f338b1582101b375e815682ee01215145bd5d6782014d954f130b4295520
- Shards: 15
- Declared split count: 15
- Repository bytes: 648872012448
- Accepted header bytes: 7098363
- Range requests: 218

## Split Identity

| File ordinal | Header index | Header ordinal | Declared count | Agreement |
| ---: | ---: | ---: | ---: | --- |
| 1 | 0 | 1 | 15 | yes |
| 2 | 1 | 2 | 15 | yes |
| 3 | 2 | 3 | 15 | yes |
| 4 | 3 | 4 | 15 | yes |
| 5 | 4 | 5 | 15 | yes |
| 6 | 5 | 6 | 15 | yes |
| 7 | 6 | 7 | 15 | yes |
| 8 | 7 | 8 | 15 | yes |
| 9 | 8 | 9 | 15 | yes |
| 10 | 9 | 10 | 15 | yes |
| 11 | 10 | 11 | 15 | yes |
| 12 | 11 | 12 | 15 | yes |
| 13 | 12 | 13 | 15 | yes |
| 14 | 13 | 14 | 15 | yes |
| 15 | 14 | 15 | 15 | yes |

## Tensor and Payload Summary

- Declared global tensor count: 2573
- Aggregated descriptors: 2573
- Exact duplicate names: 0
- Conflicting names: 0
- Bounded spans: 2573
- Unsupported spans: 0
- Invalid spans: 0
- Overlaps: 0

## Per-Shard Summary

| Ordinal | Path | Metadata | Tensors | Header bytes | Requests | Span result |
| ---: | --- | ---: | ---: | ---: | ---: | --- |
| 1 | UD\-IQ1\_M/Kimi\-K3\-UD\-IQ1\_M\-00001\-of\-00015\.gguf | 64 | 0 | 6934118 | 71 | no\_tensors |
| 2 | UD\-IQ1\_M/Kimi\-K3\-UD\-IQ1\_M\-00002\-of\-00015\.gguf | 3 | 208 | 12972 | 11 | bounded |
| 3 | UD\-IQ1\_M/Kimi\-K3\-UD\-IQ1\_M\-00003\-of\-00015\.gguf | 3 | 188 | 11948 | 11 | bounded |
| 4 | UD\-IQ1\_M/Kimi\-K3\-UD\-IQ1\_M\-00004\-of\-00015\.gguf | 3 | 220 | 14035 | 10 | bounded |
| 5 | UD\-IQ1\_M/Kimi\-K3\-UD\-IQ1\_M\-00005\-of\-00015\.gguf | 3 | 166 | 10663 | 10 | bounded |
| 6 | UD\-IQ1\_M/Kimi\-K3\-UD\-IQ1\_M\-00006\-of\-00015\.gguf | 3 | 220 | 14035 | 10 | bounded |
| 7 | UD\-IQ1\_M/Kimi\-K3\-UD\-IQ1\_M\-00007\-of\-00015\.gguf | 3 | 176 | 11265 | 10 | bounded |
| 8 | UD\-IQ1\_M/Kimi\-K3\-UD\-IQ1\_M\-00008\-of\-00015\.gguf | 3 | 196 | 12546 | 11 | bounded |
| 9 | UD\-IQ1\_M/Kimi\-K3\-UD\-IQ1\_M\-00009\-of\-00015\.gguf | 3 | 185 | 11830 | 11 | bounded |
| 10 | UD\-IQ1\_M/Kimi\-K3\-UD\-IQ1\_M\-00010\-of\-00015\.gguf | 3 | 203 | 12962 | 11 | bounded |
| 11 | UD\-IQ1\_M/Kimi\-K3\-UD\-IQ1\_M\-00011\-of\-00015\.gguf | 3 | 220 | 14035 | 10 | bounded |
| 12 | UD\-IQ1\_M/Kimi\-K3\-UD\-IQ1\_M\-00012\-of\-00015\.gguf | 3 | 169 | 10849 | 11 | bounded |
| 13 | UD\-IQ1\_M/Kimi\-K3\-UD\-IQ1\_M\-00013\-of\-00015\.gguf | 3 | 193 | 12349 | 11 | bounded |
| 14 | UD\-IQ1\_M/Kimi\-K3\-UD\-IQ1\_M\-00014\-of\-00015\.gguf | 3 | 195 | 12443 | 11 | bounded |
| 15 | UD\-IQ1\_M/Kimi\-K3\-UD\-IQ1\_M\-00015\-of\-00015\.gguf | 3 | 34 | 2313 | 9 | bounded |

## Findings

### SPLIT\-001

- Status: PASS
- Message: Filename split set is complete\.
- Evidence:

    {"shard_count":15}

### SPLIT\-002

- Status: PASS
- Message: Zero\-based header split indices are complete and unique\.
- Evidence:

    {"header_indices_complete":true}

### SPLIT\-003

- Status: PASS
- Message: Filename and normalized header shard identities agree\.
- Evidence:

    {"identity_agreement":true}

### SPLIT\-004

- Status: PASS
- Message: Filename, header, and selected split counts agree\.
- Evidence:

    {"declared_split_count":15}

### SPLIT\-005

- Status: PASS
- Message: Policy\-selected metadata consistency rules were evaluated\.
- Evidence:

    {"failure_count":0}

### SPLIT\-006

- Status: PASS
- Message: Primary\-only and subset metadata follow the recorded policy\.
- Evidence:

    {"primary_only_key_count":61}

### SPLIT\-007

- Status: PASS
- Message: Aggregated descriptor count agrees with split tensor\-count metadata\.
- Evidence:

    {"aggregated_tensor_count":2573,"declared_global_tensor_count":2573}

### SPLIT\-008

- Status: PASS
- Message: Tensor names are globally unique across shards\.
- Evidence:

    {"conflict_count":0,"exact_duplicate_count":0}

### SPLIT\-009

- Status: PASS
- Message: Computable tensor payload spans remain within declared shard bounds\.
- Evidence:

    {"bounded_count":2573,"invalid_count":0,"unsupported_count":0}

### SPLIT\-010

- Status: PASS
- Message: No unexpected overlap was found among computable spans\.
- Evidence:

    {"overlap_count":0}

### SPLIT\-011

- Status: PASS
- Message: Every selected filename shard is represented exactly once\.
- Evidence:

    {"selected_shard_count":15}

### SPLIT\-012

- Status: PASS
- Message: Aggregate policies and inventory use deterministic canonical hashing\.
- Evidence:

    {"aggregation_policy_sha256":"bde5adafbeee1c9426a8a8c15eb50b3ecabde389bce46cf5395841e48edf7e95"}

## Limitations

- Metadata consistency applies only the recorded structural policy\.
- Tensor names and shapes are not interpreted as Kimi K3 semantics\.
- Payload spans use recorded GGML block layouts without reading payload bytes\.
- Bounded spans do not prove payload presence, integrity, or quantization fidelity\.
- No HF\-to\-GGUF mapping or runtime parity claim is made\.

## Integrity

- Inventory SHA-256: 1aa8e70e92cda916aa552e468c49410389bc3cf71f1f56163716f68078bb04c7
- Aggregation policy SHA-256: bde5adafbeee1c9426a8a8c15eb50b3ecabde389bce46cf5395841e48edf7e95
- Metadata policy SHA-256: 708003ae726ba55dc740fef3b68219db5c860c7855e3412efe0afa489a78ed40
- GGML type policy SHA-256: 7375ba88935de55244fc7085f1ac469b64ddea0bab19236bd8154f5ea2a9f473
- Report SHA-256: 42d8d90ea9872527deceb1620fda8bdd73baf8fd4bfc5cde2d886cb78a771b29
