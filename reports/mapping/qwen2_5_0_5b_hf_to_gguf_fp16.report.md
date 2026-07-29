# Open Model Integration Validator Mapping Report

## Result

PASS WITH WARNINGS

## Source

- Repository: Qwen/Qwen2\.5\-0\.5B\-Instruct
- Revision: 7ae557604adf67be50417f59c2c2f167def9a775
- Physical tensors: 290
- Logical tensors: 1
- Source inventory digest: 85fa02ce8134d58db8af70189b5b3ee9f839a8933e142133442536226e96a302

## Target

- Architecture: qwen2
- Model: qwen2\.5\-0\.5b\-instruct
- Physical tensors: 291
- Target artifact digest: 8e0ae26000627ed62de0e78e41860af70094558b9d2913385c842a6aa06cf3fc
- Target inventory digest: c4aab57a9016bc928d5151a1e47c2980e63a591acd19ab40b1812998535f5592

## Mapping Manifest

- Mapping ID: qwen2\.5\-0\.5b\-hf\-to\-gguf
- Mapping digest: 4c30d57752da1ed516a32e9a11f023bb6cbbb5e74e950006fa96d0869cd94068
- Schema version: omiv\.semantic\-mapping\.v1

## Coverage

- Physical source mapped: 290/290
- Logical source mapped: 1/1
- Target explained: 291/291
- Resolved mappings: 291
- Duplicate source mappings: 0
- Duplicate target mappings: 0
- Unmapped source entities: 0
- Unmapped target entities: 0

## Findings

### MAP\-001

- Status: PASS
- Message: Source semantic coverage is complete
- Evidence:
    {"example_cap":10,"ignored_source_count":0,"ignored_sources":[],"logical_mapped":1,"logical_total":1,"physical_mapped":290,"physical_total":290,"unclassified_source_count":0,"unclassified_source_examples":[],"unmapped_logical_count":0,"unmapped_logical_examples":[],"unmapped_physical_count":0,"unmapped_physical_examples":[],"zero_source_binding_count":0,"zero_source_binding_examples":[]}

### MAP\-002

- Status: PASS
- Message: Target semantic coverage is complete
- Evidence:
    {"example_cap":10,"target_explained":291,"target_total":291,"unclassified_target_count":0,"unclassified_target_examples":[],"unexpected_target_count":0,"unexpected_target_examples":[],"zero_target_binding_count":0,"zero_target_binding_examples":[]}

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

- Status: PASS
- Message: Model scope and layer identities are preserved
- Evidence:
    {"example_cap":10,"layer_mismatch_count":0,"layer_mismatch_examples":[],"missing_binding_count":0,"missing_binding_examples":[],"resolved_count":291}

### MAP\-006

- Status: PASS
- Message: Every resolved descriptor shape satisfies its declared relation
- Shape relation counts: \{&\#x27;identical&\#x27;: 121, &\#x27;reverse\_dimensions&\#x27;: 170\}
- Resolved count: 291
- Mismatch groups: 0
- Payload transpose claimed: no
- Evidence:
    {"descriptor_relation_only":true,"example_cap":10,"mismatch_group_count":0,"mismatch_groups":[],"payload_transpose_claimed":false,"relation_counts":{"identical":121,"reverse_dimensions":170},"resolved_count":291}

### MAP\-007

- Status: PASS
- Message: Semantic parameters, modules, and projections are compatible
- Evidence:
    {"checked_count":291,"example_cap":10,"mismatch_count":0,"mismatch_examples":[]}

### MAP\-008

- Status: PASS
- Message: Logical tied output projection is structurally materialized
- Logical tied source: qwen2\.output\_projection\.weight
- Physical source identity: qwen2\.token\_embedding\.weight
- Materialized target: output\.weight
- Payload equality status: not checked
- Evidence:
    {"failure_count":0,"failure_examples":[],"logical_tied_source":"qwen2.output_projection.weight","materialized_target":"output.weight","payload_equality_status":"not checked","payload_origin":"unverified","physical_lm_head_required":false,"physical_source_identity":"qwen2.token_embedding.weight","source_materialized":false}

### MAP\-009

- Status: WARN
- Message: Exact source\-to\-target provenance is unavailable
- Known source repository: Qwen/Qwen2\.5\-0\.5B\-Instruct
- Known source revision: 7ae557604adf67be50417f59c2c2f167def9a775
- Missing provenance fields: \[&\#x27;conversion\_command&\#x27;, &\#x27;converter\_commit&\#x27;, &\#x27;source\_artifact\_hash&\#x27;, &\#x27;source\_repository&\#x27;, &\#x27;source\_revision&\#x27;\]
- Limitation: Semantic and structural compatibility does not prove that the target was generated from this exact source artifact
- Evidence:
    {"exact_lineage_established":false,"limitation":"Semantic and structural compatibility does not prove that the target was generated from this exact source artifact","mismatched_provenance_fields":[],"missing_provenance_fields":["conversion_command","converter_commit","source_artifact_hash","source_repository","source_revision"],"names_and_shapes_are_not_lineage_evidence":true,"source_repository":"Qwen/Qwen2.5-0.5B-Instruct","source_revision":"7ae557604adf67be50417f59c2c2f167def9a775","target_lineage_metadata":{"conversion_command":null,"converter_commit":null,"source_artifact_hash":null,"source_repository":null,"source_revision":null}}

## Integrity

- Report schema: omiv\.semantic\-mapping\-report\.v1
- Canonicalization: omiv\-json\-v1
- Report SHA-256: 52de5d4663bb7403c82b868c7af230588cccdafe01b4b49f4d7b8e89bfdbab20
- Tool version: 0\.1\.0
