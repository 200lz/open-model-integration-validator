# OMIV xAI Public Artifact Metadata Assurance Case Study

Classification: `XAI_PUBLIC_PINNED_METADATA_SNAPSHOT_OBSERVED_WITHOUT_PAYLOAD_DOWNLOAD`

Large Grok repository snapshots exercise supply-chain separation between repository listing, storage identifiers, payload observation, topology, authority, and freshness.

## Pinned cases

- `xai-org/grok-1` at `5de83eb225f49624b424f1c8aa74f96983b5885c`: 773 members, 318239889830 declared bytes; storage `{"DIRECT_FILE": 3, "XET_BACKED_OBJECT": 770}`; digest semantics `{"LFS_OID_SHA256": 770, "PROVIDER_OPAQUE_ID": 773, "XET_OBJECT_ID": 770}`; 2 requests/2 responses/408080 response bytes; 0 payload bytes.

- `xai-org/grok-2` at `daf4395a80ad177386cfe39641b64fc12b1d70ed`: 44 members, 539040431665 declared bytes; storage `{"DIRECT_FILE": 5, "XET_BACKED_OBJECT": 39}`; digest semantics `{"LFS_OID_SHA256": 39, "PROVIDER_OPAQUE_ID": 44, "XET_OBJECT_ID": 39}`; 2 requests/2 responses/24003 response bytes; 0 payload bytes.

## Established

- Exact immutable repository revisions were pinned.
- Canonical member paths, declared sizes, storage representations, and typed provider identifiers were reconstructed.
- Bounded request/response accounting and zero payload download were preserved.

## Not established

- Publisher authority, endorsement, model authenticity, and current state.
- Payload-byte equality, security safety, tokenizer/config parity, and runtime identity.
- Complete shard or tensor topology in the absence of an explicit parsed index.

## Provider-neutral readiness

- The same core preserves Kimi evidence limitations without upgrading prior claims.
- DeepSeek remains a readiness profile until a reviewed pinned snapshot is supplied.
- Provider profiles import the core; the provider-neutral core imports no xAI profile.

No xAI endorsement, affiliation, or publisher authorization is claimed.
