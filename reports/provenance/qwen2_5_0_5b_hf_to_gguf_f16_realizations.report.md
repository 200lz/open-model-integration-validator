# Open Model Integration Validator Conversion Provenance Report

## Result

- Result: PASS_WITH_WARNINGS
- PASS: 11
- WARN: 1
- FAIL: 0

## Source

- Format: huggingface\-safetensors
- Model family: qwen2
- Repository: Qwen/Qwen2\.5\-0\.5B\-Instruct
- Revision: 7ae557604adf67be50417f59c2c2f167def9a775
- Inventory digest: 85fa02ce8134d58db8af70189b5b3ee9f839a8933e142133442536226e96a302
- Artifact digest coverage: 1/1
- Model pack: qwen2 v1

## Semantic Interpretation

- Model pack: qwen2
- Pack metadata digest: 807eb5de8f71aff1e75c17af41ba5118ef926ded8e2b81c3adfbba29fe95bd87
- Mapping ID: qwen2\.5\-0\.5b\-hf\-to\-gguf\-realizations
- Mapping digest: c5800e9316b5a2841b91f928a1ec7754241192e7e202f68c5b5b21492110e014
- Policy references: 0

## Process

- Operation: convert
- Tool: llama\.cpp
- Revision: e3546c7948e3af463d0b401e6421d5a4c2faf565
- Revision kind: git\_commit
- Entrypoint: convert\_hf\_to\_gguf\.py
- Invocation: \[&\#x27;python&\#x27;, &\#x27;\{source\_model\_dir\}&\#x27;, &\#x27;\-\-outfile&\#x27;, &\#x27;\{target\_output\}&\#x27;, &\#x27;\-\-outtype&\#x27;, &\#x27;f16&\#x27;\]
- Exit code: 0
- Success: true

## Target

- Format: gguf
- Architecture: qwen2
- Inventory digest: b0850a54414ffe2504ef511ecb915b2706579bbac699a75d13ce1e50a1a104cb
- Artifact role: model
  - Artifact ID: qwen2\.5\-0\.5b\-instruct\-f16\.generated\.gguf
  - Artifact digest: 6f71ffde75bde493ca5cefe995306e2c2522e6e84a3dd5b4215453dda37bea32
  - Artifact bytes: 994156960

## Lineage Findings

### PROV\-001

- Status: PASS
- Message: Source identity is sufficiently pinned
- Evidence:
    {"complete_required_artifact_digests":true,"conflicts":[],"repository_revision_pin":true,"required_artifact_count":1}

### PROV\-002

- Status: WARN
- Message: Some source artifact digests were not independently checked
- Evidence:
    {"checked":[],"mismatches":[],"unchecked_roles":["model"]}

### PROV\-003

- Status: PASS
- Message: Source inventory identity matches
- Evidence:
    {"declared_sha256":"85fa02ce8134d58db8af70189b5b3ee9f839a8933e142133442536226e96a302","mismatches":[],"observed_sha256":"85fa02ce8134d58db8af70189b5b3ee9f839a8933e142133442536226e96a302"}

### PROV\-004

- Status: PASS
- Message: Model pack identity matches
- Evidence:
    {"installed_pack_id":"qwen2","mismatches":[]}

### PROV\-005

- Status: PASS
- Message: Mapping manifest identity matches
- Evidence:
    {"declared_sha256":"c5800e9316b5a2841b91f928a1ec7754241192e7e202f68c5b5b21492110e014","mismatches":[],"observed_sha256":"c5800e9316b5a2841b91f928a1ec7754241192e7e202f68c5b5b21492110e014"}

### PROV\-006

- Status: PASS
- Message: Conversion tool identity is pinned
- Evidence:
    {"declared_revision":"e3546c7948e3af463d0b401e6421d5a4c2faf565","immutable":true,"observed_repository_head":null,"revision_kind":"git_commit"}

### PROV\-007

- Status: PASS
- Message: Invocation is reproducibly recorded
- Evidence:
    {"argument_count":5,"output_argument_identifiable":true,"problems":[],"redacted_arguments":[],"shell_command_string":false}

### PROV\-008

- Status: PASS
- Message: Process result is internally consistent
- Evidence:
    {"declared_roles":["model"],"problems":[],"target_roles":["model"]}

### PROV\-009

- Status: PASS
- Message: Target artifact digest matches
- Evidence:
    {"checked":[{"evidence":"inventory","role":"model"}],"mismatches":[],"unchecked_roles":[]}

### PROV\-010

- Status: PASS
- Message: Target inventory identity matches
- Evidence:
    {"declared_sha256":"b0850a54414ffe2504ef511ecb915b2706579bbac699a75d13ce1e50a1a104cb","mismatches":[],"observed_sha256":"b0850a54414ffe2504ef511ecb915b2706579bbac699a75d13ce1e50a1a104cb"}

### PROV\-011

- Status: PASS
- Message: Provenance chain is internally consistent
- Evidence:
    {"problems":[]}

### PROV\-012

- Status: PASS
- Message: Exact lineage is sufficiently pinned
- Evidence:
    {"failed_rules":[],"inventories_exact":true,"mapping_exact":true,"source_exact":true,"target_exact":true,"tool_exact":true}

## Limitations

- PROV\-002: Some source artifact digests were not independently checked
- Lineage does not prove converter correctness, target payload numerical correctness, or inference parity\.

## Integrity

- Report schema: omiv\.conversion\-provenance\-report\.v1
- Provenance SHA-256: 801ba112864540c87e0f7daceb1a8f1f1071b784239156780539a26e7929f977
- Canonicalization: omiv\-json\-v1
- Report SHA-256: a1d08c5f2c0dac75682d6cce059929d4cd7d27f2cd7d7319c20b3aebb958270a
