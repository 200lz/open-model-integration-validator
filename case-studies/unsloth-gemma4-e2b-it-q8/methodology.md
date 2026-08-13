# Methodology

## Scope

This study evaluated artifact custody, GGUF structure, source/work-copy/target
lineage, historical reproducibility evidence, and the association between a main
GGUF and its mmproj. The analysis was offline and did not load a model, run
inference, invoke an exporter, use a GPU, or evaluate tensor payload values for
semantic or numerical fidelity. (P1-C020; A1-CAPABILITY-COVERAGE, A1-LIMITATIONS)

## Evidence model

Public claims use stable claim IDs and evidence IDs. Every evidence ID is defined
in [evidence-index.json](evidence-index.json), including its disclosure class,
supporting public claims, derivative files, and a SHA-256 commitment where a safe
canonical private A1 source record was available. Public files disclose only
hashes, counts, classifications, and short derived summaries. They do not contain
model weights, tokenizer vocabulary, full configuration files, full chat templates,
internal transcripts, credentials, private infrastructure details, or local paths.

Published SHA-256 commitments bind the identity of retained private evidence
records. Commitments alone do not make undisclosed private records independently
reviewable. The public case study provides claim summaries and commitments, but it
is not a standalone exporter reproduction recipe. This availability boundary does
not change the reported artifact-production result.

The public result distinguishes:

- directly verified current artifact facts;
- retained historical observations;
- contextual inferences;
- explicit limitations and attribution boundaries.

## Procedure

1. **Custody.** Recompute the size and SHA-256 identity of each retained GGUF and
   compare it with the authorized A1 custody record. (P1-C004, P1-C006;
   A1-INPUT-CUSTODY)
2. **Structure.** Parse GGUF headers, typed metadata, and tensor descriptors;
   confirm declared counts; validate that tensor ranges are inside the file and do
   not overlap. Tensor payload values are not interpreted. (P1-C005, P1-C007,
   P1-C008; A1-MAIN-GGUF, A1-MMPROJ-GGUF)
3. **Repeatability of reporting.** Run the deterministic OMIV-native inventory,
   manifest, self-comparison, and structural-contrast operations twice and compare
   the resulting reports byte-for-byte. (P1-C014; A1-NATIVE-REPEATABILITY)
4. **Lineage.** Compare retained source and work-copy manifests with complete
   target metadata inventories. Report the `tokenizer_config.json` JSON-pointer
   change counts without disclosing its full content or vocabulary. (P1-C002,
   P1-C010, P1-C013; A1-LINEAGE)
5. **Reproducibility classification.** Compare current artifact size/SHA-256
   identities with retained historical C1 observations. Because historical C1
   bytes are unavailable, do not describe this as a new direct C1/C2 file
   comparison. (P1-C009; A1-REPRODUCIBILITY)
6. **Companion association.** Evaluate shared execution context, exporter
   metadata, model-family/projector-role compatibility, explicit revision linkage,
   cryptographic identifiers, and format-native cross-references. (P1-C011,
   P1-C012; A1-ASSOCIATION)

## Interpretation rules

- Export success is reported separately from evidence gaps. (P1-C003, P1-C017,
  P1-C018; A1-EXPORT-HISTORY, A1-LINEAGE, A1-ASSOCIATION)
- Missing revision metadata is a provenance-observability gap, not evidence of
  incorrect model weights, and must not be attributed solely to Unsloth. (P1-C017,
  P1-C021; A1-LINEAGE, A1-LIMITATIONS)
- Weak companion binding is an artifact-association gap, not evidence of
  incompatibility, and must not be attributed solely to Unsloth. (P1-C018,
  P1-C021; A1-ASSOCIATION, A1-LIMITATIONS)
- Tokenizer/config mutation is a lineage event and is not automatically a defect;
  no originating component is identified without root-cause evidence. (P1-C013,
  P1-C021; A1-LINEAGE, A1-LIMITATIONS)
- Structure, representation, numerical fidelity, semantic fidelity, and runtime
  compatibility are separate questions. (P1-C015, P1-C016;
  A1-CAPABILITY-COVERAGE, A1-LIMITATIONS)

This is a case-study evidence workflow, not a representation of a long operational
harness as normal OMIV user experience.
