# Limitations

- Historical reproducibility is classified as `HISTORICAL_C1_MATCH` because current
  file sizes and SHA-256 values match retained C1 observations. Historical C1 bytes
  are unavailable, and no new direct C1/C2 file comparison was performed.
  (P1-C009; A1-REPRODUCIBILITY)
- Published SHA-256 commitments bind the identity of retained private evidence
  records, but commitments alone do not make undisclosed private records
  independently reviewable. The public case study provides claim summaries and
  commitments; it is not a standalone exporter reproduction recipe. This public
  availability boundary is not an artifact-production failure.
- No model inference, model service, tokenizer execution, template rendering, or
  semantic probe was performed. (P1-C020; A1-LIMITATIONS)
- Semantic fidelity and numerical quantization fidelity were not evaluated. File
  hashes and structural inventories do not answer those questions. (P1-C015;
  A1-CAPABILITY-COVERAGE, A1-LIMITATIONS)
- Q8_0 identifies the observed tensor representation; it is not a model-quality
  result. (P1-C005, P1-C015; A1-MAIN-GGUF, A1-LIMITATIONS)
- The structural checks establish header/count consistency and tensor-range bounds
  and non-overlap. They do not establish runtime compatibility. (P1-C008, P1-C016;
  A1-MAIN-GGUF, A1-MMPROJ-GGUF, A1-LIMITATIONS)
- Neither target GGUF metadata inventory contained the exact source revision. This
  is a provenance-observability gap, not evidence that model weights are incorrect,
  and it must not be attributed solely to Unsloth. (P1-C010, P1-C017, P1-C021;
  A1-LINEAGE, A1-LIMITATIONS)
- The main/mmproj association is contextual and moderate. No cryptographic or
  format-native binding was observed; this is not evidence that the artifacts are
  incompatible, and it must not be attributed solely to Unsloth. (P1-C011,
  P1-C012, P1-C018, P1-C021; A1-ASSOCIATION, A1-LIMITATIONS)
- The 195-change tokenizer configuration result is a semantic JSON-pointer diff
  linked by retained raw size/SHA-256 observations; original raw formatting is not
  reconstructible from the retained parsed wrappers. The mutation is not
  automatically a defect and cannot be attributed to a specific component without
  root-cause evidence. (P1-C013, P1-C021; A1-LINEAGE, A1-LIMITATIONS)
- This study did not determine whether the observed provenance, association, or
  tokenizer-lineage behavior originated in Unsloth, llama.cpp tooling, GGUF
  conventions, llm-compressor, or the surrounding export workflow. (P1-C021;
  A1-LINEAGE, A1-ASSOCIATION, A1-LIMITATIONS)
- Full source configuration and tokenizer assets were not in A1 custody. Missing
  values were treated as unavailable or not observable rather than inferred from
  target metadata. (P1-C019; A1-CAPABILITY-COVERAGE, A1-LIMITATIONS)
- A successful export does not by itself establish correct behavior in a particular
  runtime. (P1-C003, P1-C016; A1-EXPORT-HISTORY, A1-LIMITATIONS)
