# Open Model Integration Validator Report

## Result

PASS WITH WARNINGS

## Artifacts

| Role | Architecture | Model | Artifact SHA-256 | Inventory SHA-256 | Byte size | Tensors | Metadata entries |
| --- | --- | --- | --- | --- | ---: | ---: | ---: |
| Source | qwen2 | qwen2\.5\-0\.5b\-instruct | 8e0ae26000627ed62de0e78e41860af70094558b9d2913385c842a6aa06cf3fc | c4aab57a9016bc928d5151a1e47c2980e63a591acd19ab40b1812998535f5592 | 1266425696 | 291 | 26 |
| Target | qwen2 | qwen2\.5\-0\.5b\-instruct | 74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db | dccc7aae1d559ce619263ec97ba57104f584daf4662fa53da495bd1170a4a985 | 491400032 | 291 | 26 |

## Policy

- Policy ID: qwen2\.5\-0\.5b\-fp16\-to\-q4\_k\_m
- Policy digest: c77e8a7e38a9e3f64741029c556f2cf0b2f9bf136b43905e217650d7236cf8ed
- Schema version: 1

## Summary

- Pass: 4
- Warn: 1
- Fail: 0

## Findings

### GGUF\-DIFF\-001

- Status: PASS
- Rule ID: GGUF\-DIFF\-001
- Message: Architecture identity is preserved
- Evidence:

    {"required":true,"source_architecture":"qwen2","target_architecture":"qwen2"}

### GGUF\-DIFF\-002

- Status: PASS
- Rule ID: GGUF\-DIFF\-002
- Message: Tensor\-name coverage is identical
- Evidence:

    {"example_cap":10,"missing_count":0,"missing_examples":[],"required":true,"source_tensor_count":291,"target_tensor_count":291,"unexpected_count":0,"unexpected_examples":[]}

### GGUF\-DIFF\-003

- Status: PASS
- Rule ID: GGUF\-DIFF\-003
- Message: Tensor shapes are preserved
- Evidence:

    {"required":true,"shape_change_group_count":0,"shape_change_groups":[],"shape_order":"gguf_on_disk_reader_tensor_shape"}

### GGUF\-DIFF\-004

- Status: PASS
- Rule ID: GGUF\-DIFF\-004
- Message: All GGML type transitions satisfy policy
- Evidence:
- Accepted transition groups: 6

    {"matched_selectors":["*.ffn_down.weight"],"source_type":"F16","target_type":"Q4_K","tensor_count":12,"tensor_examples":["blk.11.ffn_down.weight","blk.12.ffn_down.weight","blk.14.ffn_down.weight","blk.15.ffn_down.weight","blk.17.ffn_down.weight","blk.18.ffn_down.weight","blk.2.ffn_down.weight","blk.20.ffn_down.weight","blk.22.ffn_down.weight","blk.23.ffn_down.weight"]}

    {"matched_selectors":["*"],"source_type":"F16","target_type":"Q5_0","tensor_count":133,"tensor_examples":["blk.0.attn_k.weight","blk.0.attn_output.weight","blk.0.attn_q.weight","blk.0.ffn_gate.weight","blk.0.ffn_up.weight","blk.1.attn_k.weight","blk.1.attn_output.weight","blk.1.attn_q.weight","blk.1.ffn_gate.weight","blk.1.ffn_up.weight"]}

    {"matched_selectors":["*.ffn_down.weight"],"source_type":"F16","target_type":"Q6_K","tensor_count":12,"tensor_examples":["blk.0.ffn_down.weight","blk.1.ffn_down.weight","blk.10.ffn_down.weight","blk.13.ffn_down.weight","blk.16.ffn_down.weight","blk.19.ffn_down.weight","blk.21.ffn_down.weight","blk.3.ffn_down.weight","blk.6.ffn_down.weight","blk.7.ffn_down.weight"]}

    {"matched_selectors":["*.attn_v.weight"],"source_type":"F16","target_type":"Q8_0","tensor_count":12,"tensor_examples":["blk.0.attn_v.weight","blk.1.attn_v.weight","blk.10.attn_v.weight","blk.13.attn_v.weight","blk.16.attn_v.weight","blk.19.attn_v.weight","blk.21.attn_v.weight","blk.3.attn_v.weight","blk.6.attn_v.weight","blk.7.attn_v.weight"]}

    {"matched_selectors":["output.weight"],"source_type":"F16","target_type":"Q8_0","tensor_count":1,"tensor_examples":["output.weight"]}

    {"matched_selectors":["*"],"source_type":"F32","target_type":"F32","tensor_count":121,"tensor_examples":["blk.0.attn_k.bias","blk.0.attn_norm.weight","blk.0.attn_q.bias","blk.0.attn_v.bias","blk.0.ffn_norm.weight","blk.1.attn_k.bias","blk.1.attn_norm.weight","blk.1.attn_q.bias","blk.1.attn_v.bias","blk.1.ffn_norm.weight"]}
- Rejected transition groups: 0
- Checked tensors: 291

### GGUF\-DIFF\-005

- Status: WARN
- Rule ID: GGUF\-DIFF\-005
- Message: Metadata drift requires review
- Evidence:
- Allowed differences: 1

    {"key":"general.file_type","source":{"array_element_type":null,"array_length":null,"key":"general.file_type","value":1,"value_sha256":null,"value_type":"UINT32"},"target":{"array_element_type":null,"array_length":null,"key":"general.file_type","value":15,"value_sha256":null,"value_type":"UINT32"}}
- Warning differences: 1

    {"key":"qwen2.context_length","source":{"array_element_type":null,"array_length":null,"key":"qwen2.context_length","value":8192,"value_sha256":null,"value_type":"UINT32"},"target":{"array_element_type":null,"array_length":null,"key":"qwen2.context_length","value":32768,"value_sha256":null,"value_type":"UINT32"}}
- Required equality failures: 0
- Ignored differences: 0

## Integrity

- Report schema: omiv\.gguf\-comparison\-report\.v1
- Canonicalization: omiv\-json\-v1
- Report SHA-256: 92be82b165eb2e683a324f2224f148e0d0595e8fd7e93297e39ccf0a38ca4e47
- Tool version: 0\.1\.0
