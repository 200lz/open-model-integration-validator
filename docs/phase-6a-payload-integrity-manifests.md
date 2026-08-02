# Phase 6A — Local Payload Integrity and Manifest Verification

Phase 6A is an offline local byte-identity observation and expected-manifest
comparison foundation. It is complete only for a declared local inventory
scope, with explicit authority, filesystem-race, availability-time, and
semantic limitations. It implements neither Phase 6B remote reconciliation nor
Phase 6C–6F fidelity, tokenizer/configuration parity, numerical, behavioral, or
safety evaluation.

## Layers and schemas

The dependency order is acyclic: inventory plan → independent hash execution →
observed manifest; expectation + observed manifest → factual comparison;
comparison + policy → integrity evidence; unsigned representative object →
detached signed wrapper → trust report; evidence → narrow integration/report →
external self-excluding artifact index. Reports and signatures never feed the
unsigned identities they describe.

The v1 schemas are:

- `omiv.payload-inventory-plan.v1`
- `omiv.payload-expectation.v1`
- `omiv.payload-expectation-materialization.v1`
- `omiv.payload-publisher-authority-evaluation.v1`
- `omiv.payload-file-record.v1` (embedded typed record)
- `omiv.observed-payload-manifest.v1`
- `omiv.payload-hash-execution-record.v1`
- `omiv.payload-manifest-comparison.v1`
- `omiv.payload-integrity-policy.v1`
- `omiv.payload-integrity-evidence.v1`
- `omiv.payload-integrity-report.v1`
- `omiv.payload-integrity-integration.v1`
- `omiv.payload-artifact-index.v1`

Plans declare requested work; manifests record observations; execution records
describe how observation ran; comparisons record facts; policies decide
sufficiency; signatures authenticate finalized bytes; adapters only project
existing limitations.

## Roots, paths, and filesystem safety

`SINGLE_FILE_ROOT` requires an explicit portable logical name, so the same
bytes under different local temporary basenames can retain the same payload
identity. `DIRECTORY_ROOT` uses relative names below a logical root, includes
dotfiles, and has no implicit `.git`, weight, config, or large-file exclusion.

The `OMIV_PORTABLE_NFC_V1` policy requires NFC, forward-slash relative paths.
It rejects absolute/drive/UNC/URI forms, backslashes, empty/dot/parent
components, NUL and ASCII controls, surrogates, Unicode noncharacters, trailing
spaces/dots, case-fold or Unicode normalization collisions, file/directory
prefix conflicts, and Windows `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, and
`LPT1`–`LPT9` basenames even with extensions. Unsafe names are rejected, never
rewritten. Surrogateescape names fail closed without serializing raw bytes.

Traversal is iterative and no-follow. The root cannot be a symlink. Symlinks
and special entries are unsupported, and the v1 default
`REJECT_HARDLINK_ALIASES` prevents aliases from becoming independent members.
When transient identity is unavailable, `HARDLINK_DETECTION_UNAVAILABLE`
prevents complete status. Hashing compares lstat/open/fstat state before and
after bounded reads and distinguishes `PATH_REBOUND_DURING_OBSERVATION`,
`OPENED_FILE_CHANGED_DURING_HASH`, and `ROOT_CHANGED_DURING_OBSERVATION` through
a second inventory comparing paths, types, logical sizes, and transient
identity. These are strong portable checks, not a claim of race-free or
continuous verification.

## Digests, roles, expectations, and comparison

V1 permits exactly one typed primary digest per file: lowercase SHA-256. Reads
are streamed in 1 MiB chunks by default, bounded from 64 KiB to 16 MiB, with no
whole-file buffering, parsing, decompression, deserialization, execution, or
network. Future multi-digest support requires a future schema and cannot change
v1 identity.

The artifact-set digest is a domain-separated canonical SHA-256 over root mode,
logical root, and path-byte-ordered records containing path, logical size,
typed algorithm/value, explicit role, and declared role detail. It is not a
digest of ambiguous concatenated payload bytes. `ABSENT_ROLE`,
`OTHER_DECLARED`, `PRIMARY`, `MANDATORY_COMPANION`, and `OPTIONAL_COMPANION` are
distinct identity-bearing declarations; adapters do not infer roles.

Expectations are `EMBEDDED_EXPECTATION` or `REFERENCED_EXPECTATION`, with
`FULL_EXPECTATION_AVAILABLE`, `DIGEST_REFERENCE_ONLY`,
`EXPECTATION_UNAVAILABLE`, or `EXPECTATION_INVALID` materialization. Referenced
content is usable only after schema, ID, digest, subject, root mode, logical
scope, and expectation scope reconstruct exactly. The immutable reference,
independently supplied expectation, and materialization result retain separate
IDs, digests, authority, and availability. Materialization never rewrites an
input or transfers authority; a comparison using it binds all three records.
Scopes are
`COMPLETE_DECLARED_FILE_SET`, `SELECTED_REQUIRED_MEMBERS`, and
`PARTIAL_REFERENCE_SET`. The only exact status is
`EXACT_MATCH_FOR_EXPECTATION_SCOPE`; selected or partial matches never imply a
complete artifact. Missing, extra/outside-scope, size, digest, role, and type
dimensions remain independent and deterministic. Matching digest does not
infer rename.

## Authority, time, integration, and limits

A valid/trusted signature is separate from publisher authorization. Authority
is scoped by object/purpose, key usage, subject, provider/namespace, tenant,
project, trust domain, validity/revocation, delegation, and expectation scope.
A trusted internal CI key is not an authorized publisher, and authority for one
subject does not cover another.

Availability and observation context are explicit canonical UTC values or
`NOT_RECORDED`; no host clock, mtime, ctime, duration, hostname, username,
inode, device, or absolute path enters canonical identity. `NOT_RECORDED`
evidence cannot independently establish `KNOWN_AS_OF_CUTOFF` availability.

Passport summaries preserve expectation scope and authority. Custody linkages
are append-only derived records. Governance distinguishes observation,
selected/complete/authorized match, mismatch, incomplete state, and limits
without approving or promoting. Phase 5F linkage requires the same subject and
artifact-set digest; byte identity does not imply security. A local identity
may be an expected Phase 5G runtime identity but cannot populate an observed
runtime identity. Phase 5H may later include these typed records without
changing Phase 5H artifacts or introducing a bundle cycle.

V1 bounds are 100,000 files, depth 64, canonical path 1,024 characters,
component 255 characters, 256 exclusions, 100,000 comparison findings,
100,000 report entries, 140 artifact-index entries, and 64 MiB canonical
metadata. An optional logical-byte budget is explicit. Limit failures use
`LIMIT_EXCEEDED:<CATEGORY>`, never truncate silently, and never produce
complete status. Sorting retains only bounded metadata; payload bytes are not
aggregated.

The CLI exits 0 for the requested exact/satisfactory result, 1 for a valid
mismatch, incomplete/limited, digest-only, or policy-unsatisfied result, and 2
for invalid/unsafe input or execution failure. Canonical stdout/output omits the
local root; immediate local failure diagnostics may name it only on stderr.

Payload digest match != model semantic correctness. Local file-set completeness
!= remote repository completeness. File-set completeness != tokenizer parity.
Payload integrity != quantization fidelity, behavioral safety, runtime safety,
approval, deployment, or observed runtime continuity. Expected manifest !=
observed manifest. Digest-only reference != fully available expectation.
Selected-member expectation != complete artifact expectation. Signed expected
manifest != correct expected manifest. Trusted signer != authorized publisher.
Hashing completed != every intended byte was hashed. Opened descriptor
stability != stable path binding. Local payload identity != observed runtime
identity. Successful local verification != continuously verified artifact.
