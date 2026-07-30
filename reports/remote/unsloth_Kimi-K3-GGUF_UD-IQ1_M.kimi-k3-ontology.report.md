# Kimi K3 Target GGUF Ontology Report

## Result

PASS

## Pinned Target

- Repository: unsloth/Kimi\-K3\-GGUF
- Resolved revision: 3d4b61ab4b6789d401191c476cbb4567246db8f5
- Split inventory SHA-256: 1aa8e70e92cda916aa552e468c49410389bc3cf71f1f56163716f68078bb04c7
- Snapshot SHA-256: a450f338b1582101b375e815682ee01215145bd5d6782014d954f130b4295520
- Shards: 15
- Tensor descriptors: 2573

## Architecture Metadata

- Architecture: kimi\-k3
- Model name: Kimi\-K3
- Direct metadata items: 30
- Derived items: 3
- Required failures: 0

## Tensor-Name Census

- Unique names: 2573
- Layer-indexed names: 2569
- Non-layer names: 4
- Suffix vocabulary size: 44
- Observed layer range: 0–92
- GGML types: \{&\#x27;F32&\#x27;: 1181, &\#x27;IQ1\_S&\#x27;: 209, &\#x27;IQ2\_XXS&\#x27;: 56, &\#x27;IQ3\_XXS&\#x27;: 11, &\#x27;Q8\_0&\#x27;: 1116\}

## Schedules

- KDA layers (69): \[0, 1, 2, 4, 5, 6, 8, 9, 10, 12, 13, 14, 16, 17, 18, 20, 21, 22, 24, 25, 26, 28, 29, 30, 32, 33, 34, 36, 37, 38, 40, 41, 42, 44, 45, 46, 48, 49, 50, 52, 53, 54, 56, 57, 58, 60, 61, 62, 64, 65, 66, 68, 69, 70, 72, 73, 74, 76, 77, 78, 80, 81, 82, 84, 85, 86, 88, 89, 90\]
- MLA layers (24): \[3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63, 67, 71, 75, 79, 83, 87, 91, 92\]
- Dense layers: \[0\]
- MoE layers: 92

## Structural Families

- Packed routed-expert families: \[&\#x27;moe\.packed\_down&\#x27;, &\#x27;moe\.packed\_gate&\#x27;, &\#x27;moe\.packed\_up&\#x27;\]
- Structurally encoded expert count: \[896\]
- Shared-expert families: \[&\#x27;moe\.shared\_down&\#x27;, &\#x27;moe\.shared\_gate&\#x27;, &\#x27;moe\.shared\_up&\#x27;\]
- g_proj physical families: \[&\#x27;g\_proj\.kda&\#x27;, &\#x27;g\_proj\.mla&\#x27;\]
- Attention Residual block size: 12

## Classification Accounting

- Classified: 2573
- Intentionally unclassified: 0
- Invalid: 0
- Duplicate classification: 0

## Family Census

| Family | Count | Scope | Physical shapes | GGML types | Coverage |
| --- | ---: | --- | --- | --- | --- |
| attention\.input\_norm | 93 | all\_layers | \[\[7168\]\] | \{&\#x27;F32&\#x27;: 93\} | PASS |
| attention\.output | 93 | all\_layers | \[\[12288, 7168\]\] | \{&\#x27;Q8\_0&\#x27;: 93\} | PASS |
| attn\_res\.attention\_score | 93 | all\_layers | \[\[7168\]\] | \{&\#x27;F32&\#x27;: 93\} | PASS |
| attn\_res\.ffn\_score | 93 | all\_layers | \[\[7168\]\] | \{&\#x27;F32&\#x27;: 93\} | PASS |
| attn\_res\.output\_score | 1 | model | \[\[7168\]\] | \{&\#x27;F32&\#x27;: 1\} | PASS |
| dense\.down | 1 | dense\_layers | \[\[33792, 7168\]\] | \{&\#x27;Q8\_0&\#x27;: 1\} | PASS |
| dense\.gate | 1 | dense\_layers | \[\[7168, 33792\]\] | \{&\#x27;Q8\_0&\#x27;: 1\} | PASS |
| dense\.up | 1 | dense\_layers | \[\[7168, 33792\]\] | \{&\#x27;Q8\_0&\#x27;: 1\} | PASS |
| ffn\.input\_norm | 93 | all\_layers | \[\[7168\]\] | \{&\#x27;F32&\#x27;: 93\} | PASS |
| g\_proj\.kda | 69 | kda\_layers | \[\[7168, 12288\]\] | \{&\#x27;Q8\_0&\#x27;: 69\} | PASS |
| g\_proj\.mla | 24 | mla\_layers | \[\[7168, 12288\]\] | \{&\#x27;Q8\_0&\#x27;: 24\} | PASS |
| kda\.a | 69 | kda\_layers | \[\[96\]\] | \{&\#x27;F32&\#x27;: 69\} | PASS |
| kda\.beta | 69 | kda\_layers | \[\[7168, 96\]\] | \{&\#x27;F32&\#x27;: 69\} | PASS |
| kda\.dt\_bias | 69 | kda\_layers | \[\[12288\]\] | \{&\#x27;F32&\#x27;: 69\} | PASS |
| kda\.forget\_a | 69 | kda\_layers | \[\[7168, 128\]\] | \{&\#x27;Q8\_0&\#x27;: 69\} | PASS |
| kda\.forget\_b | 69 | kda\_layers | \[\[128, 12288\]\] | \{&\#x27;Q8\_0&\#x27;: 69\} | PASS |
| kda\.key | 69 | kda\_layers | \[\[7168, 12288\]\] | \{&\#x27;Q8\_0&\#x27;: 69\} | PASS |
| kda\.key\_conv | 69 | kda\_layers | \[\[4, 1, 12288\]\] | \{&\#x27;F32&\#x27;: 69\} | PASS |
| kda\.output\_norm | 69 | kda\_layers | \[\[128\]\] | \{&\#x27;F32&\#x27;: 69\} | PASS |
| kda\.query | 69 | kda\_layers | \[\[7168, 12288\]\] | \{&\#x27;Q8\_0&\#x27;: 69\} | PASS |
| kda\.query\_conv | 69 | kda\_layers | \[\[4, 1, 12288\]\] | \{&\#x27;F32&\#x27;: 69\} | PASS |
| kda\.value | 69 | kda\_layers | \[\[7168, 12288\]\] | \{&\#x27;Q8\_0&\#x27;: 69\} | PASS |
| kda\.value\_conv | 69 | kda\_layers | \[\[4, 1, 12288\]\] | \{&\#x27;F32&\#x27;: 69\} | PASS |
| mla\.key\_b | 24 | mla\_layers | \[\[128, 512, 96\]\] | \{&\#x27;Q8\_0&\#x27;: 24\} | PASS |
| mla\.kv\_a\_mqa | 24 | mla\_layers | \[\[7168, 576\]\] | \{&\#x27;Q8\_0&\#x27;: 24\} | PASS |
| mla\.kv\_a\_norm | 24 | mla\_layers | \[\[512\]\] | \{&\#x27;F32&\#x27;: 24\} | PASS |
| mla\.query\_a | 24 | mla\_layers | \[\[7168, 1536\]\] | \{&\#x27;Q8\_0&\#x27;: 24\} | PASS |
| mla\.query\_a\_norm | 24 | mla\_layers | \[\[1536\]\] | \{&\#x27;F32&\#x27;: 24\} | PASS |
| mla\.query\_b | 24 | mla\_layers | \[\[1536, 18432\]\] | \{&\#x27;Q8\_0&\#x27;: 24\} | PASS |
| mla\.value\_b | 24 | mla\_layers | \[\[512, 128, 96\]\] | \{&\#x27;Q8\_0&\#x27;: 24\} | PASS |
| model\.output\_norm | 1 | model | \[\[7168\]\] | \{&\#x27;F32&\#x27;: 1\} | PASS |
| model\.output\_projection | 1 | model | \[\[7168, 163840\]\] | \{&\#x27;Q8\_0&\#x27;: 1\} | PASS |
| model\.token\_embedding | 1 | model | \[\[7168, 163840\]\] | \{&\#x27;Q8\_0&\#x27;: 1\} | PASS |
| moe\.latent\_down | 92 | moe\_layers | \[\[7168, 3584\]\] | \{&\#x27;Q8\_0&\#x27;: 92\} | PASS |
| moe\.latent\_norm | 92 | moe\_layers | \[\[3584\]\] | \{&\#x27;F32&\#x27;: 92\} | PASS |
| moe\.latent\_up | 92 | moe\_layers | \[\[3584, 7168\]\] | \{&\#x27;Q8\_0&\#x27;: 92\} | PASS |
| moe\.packed\_down | 92 | moe\_layers | \[\[3072, 3584, 896\]\] | \{&\#x27;IQ1\_S&\#x27;: 81, &\#x27;IQ3\_XXS&\#x27;: 11\} | PASS |
| moe\.packed\_gate | 92 | moe\_layers | \[\[3584, 3072, 896\]\] | \{&\#x27;IQ1\_S&\#x27;: 64, &\#x27;IQ2\_XXS&\#x27;: 28\} | PASS |
| moe\.packed\_up | 92 | moe\_layers | \[\[3584, 3072, 896\]\] | \{&\#x27;IQ1\_S&\#x27;: 64, &\#x27;IQ2\_XXS&\#x27;: 28\} | PASS |
| moe\.router | 92 | moe\_layers | \[\[7168, 896\]\] | \{&\#x27;F32&\#x27;: 92\} | PASS |
| moe\.router\_bias | 92 | moe\_layers | \[\[896\]\] | \{&\#x27;F32&\#x27;: 92\} | PASS |
| moe\.shared\_down | 92 | moe\_layers | \[\[6144, 7168\]\] | \{&\#x27;Q8\_0&\#x27;: 92\} | PASS |
| moe\.shared\_gate | 92 | moe\_layers | \[\[7168, 6144\]\] | \{&\#x27;Q8\_0&\#x27;: 92\} | PASS |
| moe\.shared\_up | 92 | moe\_layers | \[\[7168, 6144\]\] | \{&\#x27;Q8\_0&\#x27;: 92\} | PASS |

## Findings

### KIMIGGUF\-001

- Status: PASS
- Message: Architecture identifier and required metadata are valid\.
- Evidence:

    {"architecture":"kimi-k3","required_failures":[]}

### KIMIGGUF\-002

- Status: PASS
- Message: The target layer set is complete\.
- Evidence:

    {"missing":[],"observed":[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92],"unexpected":[]}

### KIMIGGUF\-003

- Status: PASS
- Message: The KDA and MLA schedules are exact\.
- Evidence:

    {"kda_count":69,"missing_kda":[],"missing_mla":[],"mla_count":24}

### KIMIGGUF\-004

- Status: PASS
- Message: The dense and MoE schedules are structurally complete\.
- Evidence:

    {"dense_layers":[0],"moe_layer_count":92}

### KIMIGGUF\-005

- Status: PASS
- Message: Required target attention families are complete\.
- Evidence:

    {"family_count":23}

### KIMIGGUF\-006

- Status: PASS
- Message: Packed routed\-expert families are complete and consistent\.
- Evidence:

    {"families":["moe.packed_down","moe.packed_gate","moe.packed_up"],"missing_layers":[]}

### KIMIGGUF\-007

- Status: PASS
- Message: Packed shapes and metadata encode the expected expert count\.
- Evidence:

    {"metadata_count":896,"shape_counts":[896]}

### KIMIGGUF\-008

- Status: PASS
- Message: Shared\-expert families are complete and consistent\.
- Evidence:

    {"families":["moe.shared_down","moe.shared_gate","moe.shared_up"],"missing_layers":[]}

### KIMIGGUF\-009

- Status: PASS
- Message: The physical KDA/MLA g\_proj representations cover all layers\.
- Evidence:

    {"missing_layers":[],"physical_families":["g_proj.kda","g_proj.mla"]}

### KIMIGGUF\-010

- Status: PASS
- Message: Fused Attention Residual score tensors are complete\.
- Evidence:

    {"block_size":12,"missing_components":[]}

### KIMIGGUF\-011

- Status: PASS
- Message: Descriptor shapes satisfy target\-side family rules\.
- Evidence:

    {"invalid_families":[]}

### KIMIGGUF\-012

- Status: PASS
- Message: GGML type placement satisfies the recorded family policy\.
- Evidence:

    {"invalid_families":[]}

### KIMIGGUF\-013

- Status: PASS
- Message: Every target descriptor has exactly one accounting category\.
- Evidence:

    {"classified":2573,"duplicate_classification":0,"invalid":0,"unclassified":0}

### KIMIGGUF\-014

- Status: PASS
- Message: The verified split inventory linkage is internally consistent\.
- Evidence:

    {"resolved_revision":"3d4b61ab4b6789d401191c476cbb4567246db8f5","snapshot_sha256":"a450f338b1582101b375e815682ee01215145bd5d6782014d954f130b4295520","source_split_inventory_sha256":"1aa8e70e92cda916aa552e468c49410389bc3cf71f1f56163716f68078bb04c7"}

### KIMIGGUF\-015

- Status: PASS
- Message: The ontology inventory uses canonical ordering and policies\.
- Evidence:

    {"classification_digest":"9a7716d40b89a14105fd1cb597fa73437361d7fe93f22517d50efc3cef84b510","ontology_policy_digest":"dcd1ab32ba30153b2aa0c614136a35b090688e60fb2c7beb339421132badbbca"}

## Limitations

- The ontology classifies target\-side physical GGUF descriptors only\.
- Packed expert PASS does not prove source expert ordering or source\-to\-target mapping\.
- Shape PASS does not prove tensor values or conversion transforms\.
- GGML type placement PASS does not prove quantization fidelity\.
- No tensor payload byte, tokenizer parity, logit parity, or runtime output was checked\.

## Integrity

- Inventory SHA-256: 0447410a5c6138b2c4a06a98fd9ff52f4db44637b099af82032d3b230013d0d9
- Model-pack SHA-256: 2939affbf3ce86f0be1b7ebc48ef61291e1268ea06d4cf38f5ce6bc60bdd35ff
- Ontology policy SHA-256: dcd1ab32ba30153b2aa0c614136a35b090688e60fb2c7beb339421132badbbca
- Classification SHA-256: 9a7716d40b89a14105fd1cb597fa73437361d7fe93f22517d50efc3cef84b510
- Report SHA-256: 27ec104444ed84fa048973d1a280a3922c529929480f2c7320c7deb84edc2b42
