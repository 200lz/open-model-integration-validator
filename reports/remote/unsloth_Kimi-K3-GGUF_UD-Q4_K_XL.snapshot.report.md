# Remote Repository Snapshot

## Result

PASS

## Repository

- Provider: huggingface
- Repository: unsloth/Kimi\-K3\-GGUF
- Requested revision: main
- Resolved revision: 3d4b61ab4b6789d401191c476cbb4567246db8f5
- Selected files: 32
- Total declared bytes: 1508668683104
- Candidate split sets: 1

## Findings

### REMOTE\-001

- Status: PASS
- Message: Repository revision resolved to an immutable commit\.
- Evidence:

    {"requested_revision":"main","resolved_revision":"3d4b61ab4b6789d401191c476cbb4567246db8f5"}

### REMOTE\-002

- Status: PASS
- Message: All selected paths passed canonical POSIX path validation\.
- Evidence:

    {"selected_path_count":32,"strict_subtree":true}

### REMOTE\-003

- Status: PASS
- Message: Selected file sizes are present and valid\.
- Evidence:

    {"file_count":32}

### REMOTE\-004

- Status: PASS
- Message: Candidate split filenames are complete\.
- Evidence:

    {"candidate_count":1,"complete_candidate_count":1,"extra_gguf_file_count":0}

### REMOTE\-005

- Status: PASS
- Message: No duplicate selected file identities were observed\.
- Evidence:

    {"unique_file_count":32}

### REMOTE\-006

- Status: PASS
- Message: Snapshot uses canonical ordering and deterministic payload hashing\.
- Evidence:

    {"snapshot_sha256":"845df5f9ddfd88c6abe4778ac9924fb68bc0c247380dfa580a0683b07d9547c0"}

## Limitations

- Filename completeness is repository\-layout evidence, not GGUF\-header validation\.
- No tensor payload bytes were requested by repository enumeration\.

## Integrity

- Report schema: omiv\.remote\-snapshot\-report\.v1
- Canonicalization: omiv\-json\-v1
- Report SHA\-256: 165075db4049c0377e2acd5ae6ecf054fa9e65f354475d527cec226ecb24748b
