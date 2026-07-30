# Open Model Integration Validator Mapping Report

## Result

FAIL

## Source

- Repository: Qwen/Qwen2\.5\-0\.5B\-Instruct
- Revision: 7ae557604adf67be50417f59c2c2f167def9a775
- Physical tensors: 290
- Logical tensors: 1
- Source inventory digest: 85fa02ce8134d58db8af70189b5b3ee9f839a8933e142133442536226e96a302

## Target

- Architecture: qwen2
- Model: Qwen2\.5 0\.5B Instruct
- Physical tensors: 290
- Target artifact digest: 6f71ffde75bde493ca5cefe995306e2c2522e6e84a3dd5b4215453dda37bea32
- Target inventory digest: b0850a54414ffe2504ef511ecb915b2706579bbac699a75d13ce1e50a1a104cb

## Mapping Manifest

- Mapping ID: qwen2\.5\-0\.5b\-hf\-to\-gguf
- Mapping digest: d56abf11141f8ae379b9bd6fe629f30168c27e9cb55c0a7a7efe70888916fb06
- Schema version: omiv\.semantic\-mapping\.v1
- Model pack: qwen2
- Model pack version: 1
- Model pack metadata digest: 807eb5de8f71aff1e75c17af41ba5118ef926ded8e2b81c3adfbba29fe95bd87

## Coverage

- Physical source mapped: 290/290
- Logical source mapped: 0/1
- Target explained: 290/290
- Resolved mappings: 290
- Duplicate source mappings: 0
- Duplicate target mappings: 0
- Unmapped source entities: 1
- Unmapped target entities: 0

## Findings

### MAP\-001

- Status: FAIL
- Message: Source semantic coverage is incomplete
- Evidence:
    {"example_cap":10,"ignored_source_count":0,"ignored_sources":[],"logical_mapped":0,"logical_total":1,"physical_mapped":290,"physical_total":290,"unclassified_source_count":0,"unclassified_source_examples":[],"unmapped_logical_count":1,"unmapped_logical_examples":["qwen2.output_projection.weight"],"unmapped_physical_count":0,"unmapped_physical_examples":[],"zero_source_binding_count":0,"zero_source_binding_examples":[]}

### MAP\-002

- Status: FAIL
- Message: Target semantic coverage is incomplete
- Evidence:
    {"example_cap":10,"target_explained":290,"target_total":290,"unclassified_target_count":0,"unclassified_target_examples":[],"unexpected_target_count":0,"unexpected_target_examples":[],"zero_target_binding_count":1,"zero_target_binding_examples":["logical-output-projection"]}

### MAP\-003

- Status: PASS
- Message: Every mapped source semantic entity is unique
- Evidence:
    {"duplicate_source_count":0,"duplicate_source_examples":[],"example_cap":10,"multi_match_binding_count":0,"multi_match_binding_examples":[],"source_kind_mismatch_count":0,"source_kind_mismatch_examples":[]}

### MAP\-004

- Status: PASS
- Message: Every target tensor and semantic identity is produced once
- Evidence:
    {"duplicate_target_identity_count":0,"duplicate_target_identity_examples":[],"duplicate_target_name_count":0,"duplicate_target_name_examples":[],"example_cap":10,"multi_match_binding_count":0,"multi_match_binding_examples":[]}

### MAP\-005

- Status: FAIL
- Message: Layer identity or binding preservation failed
- Evidence:
    {"example_cap":10,"layer_mismatch_count":0,"layer_mismatch_examples":[],"missing_binding_count":1,"missing_binding_examples":["logical-output-projection"],"resolved_count":290}

### MAP\-006

- Status: PASS
- Message: Every resolved descriptor shape satisfies its declared relation
- Shape relation counts: \{&\#x27;identical&\#x27;: 121, &\#x27;reverse\_dimensions&\#x27;: 169\}
- Resolved count: 290
- Mismatch groups: 0
- Payload transpose claimed: no
- Evidence:
    {"descriptor_relation_only":true,"example_cap":10,"mismatch_group_count":0,"mismatch_groups":[],"payload_transpose_claimed":false,"relation_counts":{"identical":121,"reverse_dimensions":169},"resolved_count":290}

### MAP\-007

- Status: PASS
- Message: Semantic parameters, modules, and projections are compatible
- Evidence:
    {"checked_count":290,"example_cap":10,"mismatch_count":0,"mismatch_examples":[]}

### MAP\-008

- Status: FAIL
- Message: Logical tie materialization is invalid
- Logical tied source: qwen2\.output\_projection\.weight
- Physical source identity: qwen2\.token\_embedding\.weight
- Materialized target: None
- Payload equality status: not checked
- Evidence:
    {"failure_count":1,"failure_examples":["logical tie does not resolve exactly once"],"logical_tied_source":"qwen2.output_projection.weight","materialized_target":null,"payload_equality_status":"not checked","payload_origin":"unverified","physical_lm_head_required":false,"physical_source_identity":"qwen2.token_embedding.weight","source_materialized":false}

### MAP\-009

- Status: PASS
- Message: Validated conversion provenance establishes exact lineage
- Known source repository: None
- Known source revision: None
- Missing provenance fields: None
- Limitation: Lineage does not prove converter correctness or numerical parity
- Evidence:
    {"exact_lineage_status":"pass","limitation":"Lineage does not prove converter correctness or numerical parity","linked_failure_rules":[],"linked_warning_rules":["PROV-002"],"provenance_supplied":true}

## Integrity

- Report schema: omiv\.semantic\-mapping\-report\.v1
- Canonicalization: omiv\-json\-v1
- Report SHA-256: cc4ba86f063f650458469cead34a6b658df2518b5e0dcd4bab7261c0c1cf3546
- Tool version: 0\.1\.0
