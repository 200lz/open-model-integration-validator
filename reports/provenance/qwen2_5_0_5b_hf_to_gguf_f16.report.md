# Open Model Integration Validator Conversion Provenance Report

## Result

- Result: PASS
- PASS: 12
- WARN: 0
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
- Mapping ID: qwen2\.5\-0\.5b\-hf\-to\-gguf
- Mapping digest: d56abf11141f8ae379b9bd6fe629f30168c27e9cb55c0a7a7efe70888916fb06
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

- Status: PASS
- Message: Source artifact digests match supplied evidence
- Evidence:
    {"checked":[{"evidence":"current_file","role":"model"}],"mismatches":[],"unchecked_roles":[]}

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
    {"declared_sha256":"d56abf11141f8ae379b9bd6fe629f30168c27e9cb55c0a7a7efe70888916fb06","mismatches":[],"observed_sha256":"d56abf11141f8ae379b9bd6fe629f30168c27e9cb55c0a7a7efe70888916fb06"}

### PROV\-006

- Status: PASS
- Message: Conversion tool identity is pinned
- Evidence:
    {"declared_revision":"e3546c7948e3af463d0b401e6421d5a4c2faf565","immutable":true,"observed_repository_head":"e3546c7948e3af463d0b401e6421d5a4c2faf565","revision_kind":"git_commit"}

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
    {"checked":[{"evidence":"current_file","role":"model"}],"mismatches":[],"unchecked_roles":[]}

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

- Lineage does not prove converter correctness, target payload numerical correctness, or inference parity\.

## Integrity

- Report schema: omiv\.conversion\-provenance\-report\.v1
- Provenance SHA-256: f20df189f1f2483ccdd577abf46a3661957e7f4478d7786f6719867c1f56e79a
- Canonicalization: omiv\-json\-v1
- Report SHA-256: 781ada94bb28766b16664ff94496d2683e13352bb6d0c8c9ff0b31d754aa741b
