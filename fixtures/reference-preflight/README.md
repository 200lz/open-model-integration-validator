# Reference Preflight fixtures

`muse-glimmer-30b.json` is a normalized, bounded replay fixture built from
official public metadata observed on 2026-08-15. It contains no model bytes,
signed URLs, cookies, credentials, or transient request headers.

The fixture preserves exact repository revisions, provider-exposed file
identities and sizes, pinned small-document identities, the llama.cpp support
and release commits, and the Ollama manifest/layer identities needed to audit
the normalization. Provider declarations remain declarations: they do not
establish local payload verification, GGUF structure, source binding,
companion cryptographic binding, runtime compatibility, or fidelity.

Default tests replay this fixture offline. Updating it requires a separate,
bounded observation of the listed official sources and review of every changed
identity; the CLI never refreshes the fixture automatically.

The future-plan raster input is the deterministic 64x64
`../../examples/reference-preflight/probes/red-square.png` fixture with
SHA-256 `53bf31df09c932233812a2c7b61c89a0ecbbaee90ab63f36058099e5d008e852`.
Its three GGUF declarations total 19,788,220,960 bytes. The plan recommends at
least 50 GB for direct llama.cpp work or at least 80 GB when a separately
downloaded Ollama representation is also retained; these workspace values are
not artifact-size totals.
