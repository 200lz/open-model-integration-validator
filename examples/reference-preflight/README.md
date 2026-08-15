# Muse Glimmer no-payload Reference Preflight

This acceptance example turns one model reference into a concise result by
replaying a reviewed official-metadata fixture. It performs no live network
access, model download, GGUF read, runtime invocation, conversion, or GPU work.

```console
omiv reference-preflight plan \
  --profile fixtures/reference-preflight/muse-glimmer-30b.json \
  --reference meta-models/Muse-Glimmer-30B-GGUF \
  --root . \
  --output muse-reference-evidence.json \
  --assurance-request-output muse-assurance-request.json

omiv reference-preflight verify --evidence muse-reference-evidence.json
omiv assurance plan \
  --request muse-assurance-request.json \
  --root . \
  --output muse-assurance-plan.json
```

The Assurance request deliberately stores the candidate JSON as opaque
`EXTERNAL` supporting evidence. Phase 6F therefore preserves its bytes and
future GPU cost without registering it as Phase 5/6A–6E verdict evidence. The
bundle's semantic verdict remains `UNKNOWN`; bundle `COMPLETE` describes a
complete portable container, not verified model, runtime, or fidelity claims.

The embedded future plan pins the 17 GB main GGUF, perception projector,
DFlash drafter, llama.cpp `b10353` commit, and fixed text and image probes. The
three GGUF artifact declarations total exactly 19,788,220,960 bytes. A direct
llama.cpp test requires at least 50 GB of workspace/disk; a separate Ollama
representation in the same workspace raises the recommendation to at least
80 GB. No byte identity between the Hugging Face and Ollama representations is
assumed without matching digest evidence.

The runtime image is the deterministic 64x64 raster PNG
`probes/red-square.png` (SHA-256
`53bf31df09c932233812a2c7b61c89a0ecbbaee90ab63f36058099e5d008e852`).
The SVG beside it is documentation/source only and is not a runtime input.

The future envelope authorizes one RTX 5090 with 32 GB VRAM, at most USD 5 of
total compute, and at most four hours of work, with no new work in the final
30 minutes and no additional GPU or Pod. It retains artifact hashes/sizes,
runtime and executable identity, canonical invocations, bounded process
captures and outcomes, GPU/backend observation, and probe outputs. After
evidence transfer, the exact authorized Pod must always be terminated and its
termination verified.

Ollama remains a secondary observation. Its `muse-glimmer:30b` and
`muse-glimmer:latest` tags are mutable and must be re-resolved immediately
before execution; manifest drift aborts execution unless a new plan is
reviewed. The direct llama.cpp test is independently completable without an
Ollama download. The plan's execution status is `NOT_RUN`, all runtime stages
begin `UNKNOWN`, and no performance, fidelity, safety, or production-readiness
claim follows from a bounded probe.
