# Open Model Integration Validator Report

## Result

PASS WITH WARNINGS

## Artifacts

| Role | Architecture | Model | Artifact SHA-256 | Inventory SHA-256 | Byte size | Tensors | Metadata entries |
| --- | --- | --- | --- | --- | ---: | ---: | ---: |
| Source | qwen2 | qwen2\.5\-0\.5b\-instruct | 8e0ae26000627ed62de0e78e41860af70094558b9d2913385c842a6aa06cf3fc | c4aab57a9016bc928d5151a1e47c2980e63a591acd19ab40b1812998535f5592 | 1266425696 | 291 | 26 |
| Target | qwen2 | qwen2\.5\-0\.5b\-instruct | ca59ca7f13d0e15a8cfa77bd17e65d24f6844b554a7b6c12e07a5f89ff76844e | c34832de69bbb6bd9f148753c719c3bc06cfa10ee7856304575e78121d8b867b | 675710816 | 291 | 26 |

## Policy

- Policy ID: qwen2\.5\-0\.5b\-fp16\-to\-q8\_0
- Policy digest: e12b69c62a6c3d693ef8c8c0c1a342e72efd0da4fcbfb45abd7ba045dfee1db7
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
- Accepted transition groups: 2

    {"matched_selectors":["*"],"source_type":"F16","target_type":"Q8_0","tensor_count":170,"tensor_examples":["blk.0.attn_k.weight","blk.0.attn_output.weight","blk.0.attn_q.weight","blk.0.attn_v.weight","blk.0.ffn_down.weight","blk.0.ffn_gate.weight","blk.0.ffn_up.weight","blk.1.attn_k.weight","blk.1.attn_output.weight","blk.1.attn_q.weight"]}

    {"matched_selectors":["*"],"source_type":"F32","target_type":"F32","tensor_count":121,"tensor_examples":["blk.0.attn_k.bias","blk.0.attn_norm.weight","blk.0.attn_q.bias","blk.0.attn_v.bias","blk.0.ffn_norm.weight","blk.1.attn_k.bias","blk.1.attn_norm.weight","blk.1.attn_q.bias","blk.1.attn_v.bias","blk.1.ffn_norm.weight"]}
- Rejected transition groups: 0
- Checked tensors: 291

### GGUF\-DIFF\-005

- Status: WARN
- Rule ID: GGUF\-DIFF\-005
- Message: Metadata drift requires review
- Evidence:
- Allowed differences: 1

    {"key":"general.file_type","source":{"array_element_type":null,"array_length":null,"key":"general.file_type","value":1,"value_sha256":null,"value_type":"UINT32"},"target":{"array_element_type":null,"array_length":null,"key":"general.file_type","value":7,"value_sha256":null,"value_type":"UINT32"}}
- Warning differences: 1

    {"key":"qwen2.context_length","source":{"array_element_type":null,"array_length":null,"key":"qwen2.context_length","value":8192,"value_sha256":null,"value_type":"UINT32"},"target":{"array_element_type":null,"array_length":null,"key":"qwen2.context_length","value":32768,"value_sha256":null,"value_type":"UINT32"}}
- Required equality failures: 0
- Ignored differences: 0

## Integrity

- Report schema: omiv\.gguf\-comparison\-report\.v1
- Canonicalization: omiv\-json\-v1
- Report SHA-256: e04b477a2b603c9f052b0e2d03f9c0f5d13e152bc5af2a728214242a90242b56
- Tool version: 0\.1\.0
