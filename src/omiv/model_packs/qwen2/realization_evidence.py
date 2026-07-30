"""Trusted, source-reviewed Qwen2 target-realization evidence."""

from omiv.mapping.models import RealizationEvidence

LLAMA_QWEN2_OUTPUT_FALLBACK = RealizationEvidence(
    evidence_schema="omiv.realization-evidence.v1",
    evidence_id="llama-qwen2-output-fallback-v1",
    backend="llama.cpp",
    repository="ggml-org/llama.cpp",
    revision="e3546c7948e3af463d0b401e6421d5a4c2faf565",
    architecture="qwen2",
    policy_symbol="llama_model_qwen2::load_arch_tensors",
    logical_identity="qwen2.output_projection.weight",
    fallback_identity="qwen2.token_embedding.weight",
    runtime_consumer="logits output projection",
    evidence_kind="source-reviewed",
)

REALIZATION_EVIDENCE = (LLAMA_QWEN2_OUTPUT_FALLBACK,)
