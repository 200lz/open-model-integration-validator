# Phase 6B — Provider-neutral shard completeness and remote/local reconciliation

Phase 6B reconciles a bounded remote snapshot observation with the exact local byte observation
produced by Phase 6A. The core has no model-family dependency. Kimi/Moonshot, DeepSeek, and xAI are
practice profiles outside the core and cannot change its evidence semantics.

## Layers and dependency direction

The canonical graph is acyclic:

```text
locator -> plan -> execution -> snapshot -> topology -> completeness
                                snapshot -> expectation -> comparison
Phase 6A observed payload manifest --------------------/
expectation signature -> trust report -> publisher authority
exact references + policy -> evidence -> report/adapters
```

The execution record deliberately has no result reference. A snapshot binds the finalized execution
ID and digest. Reports derive from evidence and are not evidence sources. The external index excludes
itself.

The v1 schema IDs are:

- `omiv.remote-artifact-locator.v1`
- `omiv.remote-snapshot-plan.v1`
- `omiv.remote-collection-execution-record.v1`
- `omiv.remote-digest-descriptor.v1`
- `omiv.remote-member-record.v1`
- `omiv.remote-snapshot-manifest.v1`
- `omiv.shard-topology.v1`
- `omiv.shard-completeness-assessment.v1`
- `omiv.remote-snapshot-expectation.v1`
- `omiv.remote-publisher-authority-evaluation.v1`
- `omiv.remote-local-reconciliation-policy.v1`
- `omiv.remote-local-reconciliation-comparison.v1`
- `omiv.remote-local-reconciliation-evidence.v1`
- `omiv.remote-local-reconciliation-report.v1`
- `omiv.remote-local-integration.v1`
- `omiv.reconciliation-artifact-index.v1`

## Revisions, observation, and digest semantics

A locator is a declaration. A requested branch or tag remains mutable. A snapshot records requested
and resolved revisions separately and classifies the resolved identity. Only an explicitly immutable
commit, content digest, or provider snapshot supports reproducible identity without a mutable-revision
limitation.

`available_at` and `observed_at` are caller supplied; the implementation does not read the host clock.
`NOT_RECORDED` cannot establish knowledge at a historical cutoff. Provider listing completeness is
limited to the bounded response or imported scope, not current remote reality.

Remote identifiers carry syntax and semantic target. Payload SHA-256 is byte-comparable. An LFS OID
becomes comparable only when pointer semantics were observed and validated. An explicitly labeled
Xet payload SHA-256 becomes comparable only at the declared-payload-digest observation level. Xet
object IDs, Git object hashes, HTTP ETags, and provider-opaque IDs are not local payload SHA-256.
Hexadecimal length never determines semantics. Without a comparable digest, OMIV can report path,
role, and size findings plus `DIGEST_NOT_COMPARABLE`, but cannot report byte match or digest mismatch.

## Safe indexes, topology, and Phase 6A

The index reader accepts supplied local strict-UTF-8 JSON, including Hugging Face-style `weight_map`
objects. It rejects duplicate keys, excessive bytes/nesting/entries, long logical names, and unsafe
portable paths. The v1 ceiling is 500,000 logical mappings. It extracts only logical-key to shard-path
declarations; it does not open shards, load tensors, deserialize weights, or execute hooks.

Explicit indexes, provider manifests, and user declarations may establish declared membership.
Filename heuristics are discovery hints only. Completeness separately records index coverage, remote
presence, local presence, digest comparability, local byte match, and mandatory companions. Its
strongest status is `COMPLETE_FOR_EXPLICIT_TOPOLOGY_SCOPE`, not tensor-semantic completeness.

`ObservedPayloadManifest` remains the only local byte-observation source. Phase 6B reconstructs its
exact identity, preserves coverage and race/path/hardlink limitations, requires exact subject and
logical-root compatibility, and compares only explicitly compatible payload-digest semantics.

## Authority, sources, and practice profiles

An observed snapshot does not automatically become an authorized expectation. Publisher authority
binds the exact expectation, trust report, subject, provider, namespace, revision, purpose,
tenant/project/trust domain, signer/key binding, validity, delegation, and revocation context. A
verified namespace or trusted collector signature is not sufficient. Official and mirror snapshots
remain distinct; matching names, bytes, or digests do not transfer authority.

The Kimi profile references prior pinned evidence by exact file digest and preserves header-only,
metadata-only, payload-not-checked, and unavailable-provenance limitations. No verified pinned
DeepSeek snapshot is supplied, so its non-operational profile records
`DEEPSEEK_PINNED_REMOTE_SNAPSHOT_NOT_SUPPLIED`. The xAI profile imports two reviewed, normalized
`PINNED_PUBLIC_PROVIDER_METADATA_FIXTURE` source fixtures for exact Grok-1 and Grok-2 revisions.
They are public-provider metadata, not official xAI attestations, publisher-authorized manifests,
payload verification, authenticity evidence, current repository state, or affiliation evidence.

## Bounded public metadata validation

Live collection is separate from deterministic generation and requires explicit opt-in and a
caller-supplied observation time. Allowed hosts are `huggingface.co`, `api.github.com`, `github.com`,
and `raw.githubusercontent.com`. Limits are 50 requests, three allowlisted redirects per request,
16 MiB per response, 128 MiB total, 100,000 members, and 2 MiB for an explicitly small non-weight
metadata file. Weight, archive, executable, and payload byte limits are zero. Credentials, signed
URLs, redirect escapes, and weight-file GETs fail closed. Tests use injected transports only.

The reviewed captures pinned `xai-org/grok-2` revision
`daf4395a80ad177386cfe39641b64fc12b1d70ed` (44 members, 539,040,431,665 declared
bytes; 39 Xet-backed and 5 direct) and `xai-org/grok-1` revision
`5de83eb225f49624b424f1c8aa74f96983b5885c` (773 members, 318,239,889,830 declared
bytes; 770 Xet-backed and 3 direct). Each capture used two successful metadata responses, zero
redirects, zero weight-file GETs, and zero payload bytes. LFS OIDs, Xet object IDs, and provider
object IDs remain distinct; all 817 members remain `DIGEST_NOT_COMPARABLE`. Complete pinned
provider listing scope does not establish model topology, local presence, payload equality, current
state, publisher authority, authenticity, safety, tensor completeness, or runtime behavior.

## Preservation audit

The Phase 6A release audit's 592 count used every tracked file under the established
canonical/generated roots at pre-Phase-6A commit
`e2a80e60be70c275dbefd8fda7ded7f65f4e933d`. The later 497 count instead selected only the
Phase 5A-through-6A commit-range delta and excluded implementation, tests, tools, docs, and project
configuration. That narrower phase-origin rule was valid as a change count but defective as a
preservation universe because it omitted older canonical evidence.

`tools/audit_phase6b_preservation.py` applies the exhaustive baseline rule to commit
`944dafd1d3667e21bbeda6bd7b01e60e651fe7c3`: all established canonical/generated roots, the Phase
6A root, the schema registry, every prior artifact index, and every prior index member. The result is
627 artifacts with path-set digest
`ece522cc790276b7b68e04b86fb927c8ab8b6d3d84d3428c3cffe8368fb5834e`. This includes 626
baseline Git blobs and the already-present ignored `reports/raw/kimi_k3_tensors.json`, whose prior
index declaration and current bytes both have size 115,542,096 and SHA-256
`15a6757becb69c56492fdb630d6853696082a9ec6109bcea05f387a5052ea469`; its Git blob identity is
truthfully `NOT_TRACKED_AT_BASELINE`.

## CLI, outputs, and limitations

Offline commands are:

```text
omiv reconcile import-snapshot SNAPSHOT.json
omiv reconcile inspect-index INDEX.json
omiv reconcile shards --snapshot SNAPSHOT.json --index INDEX.json
omiv reconcile local --expectation EXPECTATION.json --local-manifest LOCAL.json
omiv reconcile verify OBJECT.json
omiv reconcile collect-hf-metadata --repo NAMESPACE/NAME --revision REF \
  --revision-kind BRANCH --subject SUBJECT.json --observed-at TIME \
  --metadata-only --no-payload --allow-network --output SNAPSHOT.json \
  --execution-output EXECUTION.json --raw-response-dir ./phase6b-raw
```

Exit 0 means the requested declared scope is satisfactory. Exit 1 covers mismatch, incomplete or
metadata-only results, mutable revisions, unauthorized expectations, non-comparability, and bounded
live gaps. Exit 2 covers invalid/unsafe inputs, prohibited payload requests, unsupported semantics,
and execution failures. Output never claims a model was verified safe.

Run `python tools/generate_reconciliation_examples.py` to regenerate deterministic offline artifacts
under `reconciliation/` and `reports/reconciliation/`. It reads only the reviewed source fixtures in
`fixtures/reconciliation/xai/` and never calls the network. Live responses and candidate reports
remain temporary and do not feed their own source-fixture identities. There are 60 indexed
artifacts; the external artifact index excludes itself.

Passport output is a derived summary; custody is append-only; governance creates no approval;
security requires exact local identity and infers no pass; runtime carries expected identity only;
historical integration preserves explicit availability; and audit integration reserves future typed
membership without regenerating Phase 5H bundles. Phase 6B does not establish loadability,
authenticity, safety, tokenizer/config parity, continuous monitoring, or runtime identity.
Quantization fidelity and tensor-value comparison are deferred to Phase 6C.
