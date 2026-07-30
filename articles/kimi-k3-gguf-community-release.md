# Kimi K3 split-GGUF structural validation package

OMIV has prepared an evidence-linked structural validation package for
`unsloth/Kimi-K3-GGUF` at immutable revision
`3d4b61ab4b6789d401191c476cbb4567246db8f5`.

The package covers UD-IQ1_M and UD-Q4_K_XL repository layouts, bounded GGUF
header reads, split aggregation, 2,573 target descriptors, Kimi K3 ontology,
grouped source-to-target mapping, independent validation, and directional
cross-quantization comparison. Remote structural inspection accepted zero tensor
payload bytes.

Both variants are structurally validated with limitations. Their normalized
target identities and shapes match. The 276 observed type changes are confined to
packed routed-expert gate/up/down tensors and are structurally permitted by the
recorded policies.

This package does not establish payload equality, numerical quantization
fidelity, tokenizer parity, runtime parity, model quality, or artifact-specific
conversion provenance.

To review the evidence offline:

```bash
omiv article-evidence-verify --root .
omiv article-claims-verify --root .
omiv article-preflight --root . \
  --article articles/validating-kimi-k3-gguf-with-omiv.md
```

The technical article, claim registry, reproducibility manifest, and canonical
artifact index are under `articles/`. Review of the evidence and contributions of
additional model packs or explicit policies are welcome.

Thanks to Moonshot AI, Unsloth, llama.cpp/GGML maintainers, and open-model
community contributors. This acknowledgement does not imply endorsement.
