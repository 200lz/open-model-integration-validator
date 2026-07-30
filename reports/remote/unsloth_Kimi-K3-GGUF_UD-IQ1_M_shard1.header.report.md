# Remote GGUF Header Report

## Result

PASS

## Pinned Artifact

- Provider: huggingface
- Repository: unsloth/Kimi\-K3\-GGUF
- Resolved revision: 3d4b61ab4b6789d401191c476cbb4567246db8f5
- File: UD\-IQ1\_M/Kimi\-K3\-UD\-IQ1\_M\-00001\-of\-00015\.gguf
- Repository declared size: 6934144
- Snapshot SHA-256: a450f338b1582101b375e815682ee01215145bd5d6782014d954f130b4295520

## Header Boundary

- GGUF version: 3
- Metadata entries: 64
- Tensor descriptors: 0
- Alignment: 32
- Metadata and descriptor end (exclusive): 6934118
- Padding length: 26
- Header end / payload start (exclusive): 6934144
- Highest accepted offset (inclusive): 6934117
- Accepted remote bytes: 6934118
- HTTP Range requests: 71
- Payload relation: payload\_at\_eof

## Largest Metadata Entries

| Key | Type | Encoded bytes |
| --- | --- | ---: |
| tokenizer\.ggml\.merges | ARRAY | 3201710 |
| tokenizer\.ggml\.tokens | ARRAY | 3049063 |
| tokenizer\.ggml\.token\_type | ARRAY | 655409 |
| tokenizer\.chat\_template | STRING | 24739 |
| kimi\-k3\.attention\.head\_count\_kv | ARRAY | 427 |
| general\.tags | ARRAY | 125 |
| general\.base\_model\.0\.repo\_url | STRING | 90 |
| quantize\.imatrix\.dataset | STRING | 75 |
| quantize\.imatrix\.file | STRING | 74 |
| general\.repo\_url | STRING | 66 |

## Representative Tensor Descriptors

| Name | Dimensions (GGUF order) | Type | Relative offset |
| --- | --- | --- | ---: |

## Findings

### HEADER\-001

- Status: PASS
- Message: GGUF v3 fixed prefix and little\-endian fields are valid\.
- Evidence:

    {"gguf_version":3}

### HEADER\-002

- Status: PASS
- Message: Metadata and tensor counts are within the recorded parser policy\.
- Evidence:

    {"metadata_count":64,"tensor_count":0}

### HEADER\-003

- Status: PASS
- Message: All metadata binary encodings were fully parsed within configured bounds\.
- Evidence:

    {"metadata_entry_count":64}

### HEADER\-004

- Status: PASS
- Message: All per\-file tensor descriptors were syntactically parsed and uniquely named\.
- Evidence:

    {"tensor_descriptor_count":0}

### HEADER\-005

- Status: PASS
- Message: Tensor relative offsets fit within the repository\-declared file boundary\.
- Evidence:

    {"repository_declared_file_size":6934144}

### HEADER\-006

- Status: PASS
- Message: GGUF alignment is valid and bounded by policy\.
- Evidence:

    {"alignment":32}

### HEADER\-007

- Status: PASS
- Message: The exact half\-open header boundary was derived from parsed descriptors\.
- Evidence:

    {"metadata_and_descriptor_end":6934118,"payload_start_offset":6934144}

### HEADER\-008

- Status: PASS
- Message: No accepted or requested byte reached the tensor payload boundary\.
- Evidence:

    {"highest_accepted_offset":6934117,"payload_start_offset":6934144}

### HEADER\-009

- Status: PASS
- Message: Every HTTP Content\-Range total agreed with repository file size\.
- Evidence:

    {"repository_declared_file_size":6934144}

### HEADER\-010

- Status: PASS
- Message: The header inventory and parser policy use deterministic canonical hashing\.
- Evidence:

    {"parser_policy_sha256":"f77b269ec6f7b3ca18d52201528473ad15f752c8fd58e10b7162033e670131a3"}

## Limitations

- Metadata PASS validates binary encoding, not semantic correctness\.
- Tensor descriptor PASS is per\-file syntax, not Kimi K3 architecture evidence\.
- No tensor payload byte, payload digest, or payload value was accessed\.
- No cross\-shard consistency or split\-model claim is made\.

## Integrity

- Inventory SHA-256: ad657eab768dc46fb07054eb1fdfaa5e1fac48f389c78523b38bef63c2bd7a8d
- Parser policy SHA-256: f77b269ec6f7b3ca18d52201528473ad15f752c8fd58e10b7162033e670131a3
- Report SHA-256: 5934de5d8ecb9ed921e7766651929eec1d7173912633bb9c8cfd442eb2b49e6c
- Canonicalization: omiv\-json\-v1
