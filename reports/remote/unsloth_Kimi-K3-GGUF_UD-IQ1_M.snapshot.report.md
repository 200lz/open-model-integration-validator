# Remote Repository Snapshot

## Result

PASS

## Repository

- Provider: huggingface
- Repository: unsloth/Kimi\-K3\-GGUF
- Requested revision: main
- Resolved revision: 3d4b61ab4b6789d401191c476cbb4567246db8f5
- Selected files: 15
- Total declared bytes: 648872012448
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

    {"selected_path_count":15,"strict_subtree":true}

### REMOTE\-003

- Status: PASS
- Message: Selected file sizes are present and valid\.
- Evidence:

    {"file_count":15}

### REMOTE\-004

- Status: PASS
- Message: Candidate split filenames are complete\.
- Evidence:

    {"candidate_count":1,"complete_candidate_count":1,"extra_gguf_file_count":0}

### REMOTE\-005

- Status: PASS
- Message: No duplicate selected file identities were observed\.
- Evidence:

    {"unique_file_count":15}

### REMOTE\-006

- Status: PASS
- Message: Snapshot uses canonical ordering and deterministic payload hashing\.
- Evidence:

    {"snapshot_sha256":"a450f338b1582101b375e815682ee01215145bd5d6782014d954f130b4295520"}

## Limitations

- Filename completeness is repository\-layout evidence, not GGUF\-header validation\.
- No tensor payload bytes were requested by repository enumeration\.

## Integrity

- Report schema: omiv\.remote\-snapshot\-report\.v1
- Canonicalization: omiv\-json\-v1
- Report SHA\-256: ea7be6d02ddbf17ab0eb04ff9775bfcd6f21f0f9456947d158a973b8bb7f5cc4
