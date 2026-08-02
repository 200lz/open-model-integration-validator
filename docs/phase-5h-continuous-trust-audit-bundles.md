# Phase 5H — Continuous Trust, Historical Reevaluation, and Audit Bundles

Phase 5H provides deterministic offline historical reconstruction over explicitly
supplied, finite evidence. It adds immutable trust snapshots, normalized historical
events, timelines, transitions, revocation propagation, freshness transitions,
supersession, observation renewal, policy-version reevaluation, and portable
directory-form audit bundles.

## Permanent evidence boundary

OMIV core models evidence and policy-scoped conclusions. Products and adapters collect
or import evidence. A signature proves that a key signed bytes; it does not prove the
claim is true or that the signer was authorized for every assertion. Authority, scope,
origin, trust, freshness, coverage, and corroboration remain separate dimensions.

A `TrustSnapshot` records reconstructed state for one finite evidence set, exact policy
set, and explicit evaluation context. It does not represent continuous real-world state.
Historical snapshots are immutable. Revocation, withdrawal, supersession, renewal, or a
policy change creates a new snapshot or historical result and never rewrites the old one.

No new evidence does not prove that no real-world change occurred. “Latest supplied
snapshot” therefore never means “current real-world state.”

## Evidence sets and snapshots

`EvidenceSetManifest` identifies every canonical member by schema, object ID, digest,
source phase, role, availability, verification mode, origin, and authority status.
Duplicate IDs, conflicting digests, cross-scope members, unsafe paths, implicit time, and
caller-selected reconstructed results fail closed.

Snapshots preserve separate artifact, provenance, custody, trust, authority, security,
governance, approval, deployment, observation, continuity, payload, tokenizer,
quantization, numerical, behavioral, revocation, and freshness states. Phase 5F limited
security evidence remains limited; Phase 5G PASS retains snapshot-only scope, behavioral
parity `NOT_CHECKED`, runtime safety `NOT_VERIFIED`, and continuous continuity
`NOT_ESTABLISHED`.

## Events, timelines, and transitions

Historical events retain declared/imported/structural/signature/trust/authority/
corroboration/trusted-time distinctions. A signed revocation or policy-change event is
accepted only when its issuer is authorized for the target, assertion, sequence, and
tenant/project/product/environment/trust-domain scope.

Timelines order events by canonical namespace, epoch, sequence, and predecessor—not by
filename, filesystem order, mtime, or host clock. OMIV detects duplicate sequence
content, multiple successors, missing predecessors, rollback, and cross-scope reuse. It
records forks but does not resolve them automatically. “Complete” means complete only
for the supplied declared sequence range.

Transitions show changed and unchanged dimensions. They distinguish evidence changes
from policy reclassification and never describe an overall improvement without the
dimension-level comparison.

## Historical cutoff and knowledge mode

Phase 5H supports exactly `KNOWN_AS_OF_CUTOFF`. Evidence and events are filtered by
their canonical `available_at` value and sequence before timeline construction,
dependency traversal, revocation propagation, renewal, supersession, policy evaluation,
and snapshot reconstruction. Availability exactly equal to the cutoff is included.
Evidence first available after the cutoff is late-arriving evidence even when it asserts
an earlier `effective_at`; it can produce a later reevaluation but cannot rewrite the
original snapshot. Missing availability is rejected rather than optimistically inferred.

`effective_at`, `available_at`, `observed_at`, `evaluated_at`, and `cutoff` are distinct
canonical UTC values. Event time is not a trusted timestamp. Historically effective at a
cutoff is not the same as known to the evaluator at that cutoff.
`EFFECTIVE_AS_OF_CUTOFF` retrospective reconstruction is explicitly unsupported and is
rejected rather than silently mapped to the supported mode.

## Revocation, freshness, supersession, and renewal

Revocation propagation identifies direct targets and transitive dependents while
retaining every historical record. It traverses only explicit typed dependency edges;
shared signers, bundle membership, directories, names, metadata, or temporal proximity
do not create dependencies. Unrelated evidence is not revoked. Freshness uses an
explicit `EvaluationContext`; the workstation clock is never consulted. A historical T1
statement remains a statement about T1 after a T2 expiration or policy change.

Supersession selects preferred future evidence. It does not establish that the previous
record was false, and it never deletes history. Cycles and conflicting replacements fail
closed. Observation renewal applies only to named dimensions; it cannot renew security,
approval, trust-bundle, or behavioral evidence implicitly.

Revocation takes conservative precedence over supersession, renewal, later signatures,
and bundle completeness. Supersession and revocation remain simultaneous facts. A
successor is evaluated independently and inherits no authority, coverage, provenance,
freshness, validity, or truth from its predecessor.

## Audit bundles

Audit bundles use a deterministic directory layout with normalized relative paths.
Symlinks, special files, absolute paths, traversal, case conflicts, undeclared files,
missing members, duplicate canonical IDs, schema mismatches, and size/hash mismatches are
rejected. The manifest excludes itself, keeping the digest graph acyclic.

The canonical path policy requires slash-separated NFC Unicode. It rejects non-NFC
spellings, backslashes, absolute paths, dot and empty components, NUL/control characters,
trailing spaces or dots, Windows reserved basenames (`CON`, `PRN`, `AUX`, `NUL`,
`COM1`–`COM9`, `LPT1`–`LPT9`, including extensions), case-insensitive collisions,
Unicode-normalization collisions, and file/directory prefix conflicts. Unsafe paths are
never silently rewritten.

Canonical layering is evidence → unsigned manifest → signed manifest wrapper → bundle
verification result → optional signed verification-result wrapper → external artifact
index and derived reports. The manifest contains none of its wrappers or verification
outputs, the verification result contains no wrapper, and the index excludes itself.

Bundle completeness is scoped to the declared purpose and completeness policy. Every
omission is explicit. Synthetic enterprise bundles exclude model payloads and disclose
that continuous observation and trusted timestamps are unavailable. An audit-bundle
signature does not independently prove every claim inside the bundle.

Timeline completeness and bundle completeness are separate. A complete declared event
range can be packaged incompletely, while a purpose-complete bundle can retain a partial
or forked timeline. Neither state means current-world, continuous, or model-payload
completeness.

Offline verification reconstructs member integrity, schemas, identities, completeness,
snapshots, timeline ordering, limitations, and reports without a private key or network.

## Multi-product and scope support

The history model operates on generic canonical subject IDs and supports weights,
tokenizers, configurations, adapters, templates, engines, images, deployment packages,
tools, agents, datasets, policies, security bundles, and mixed artifact sets. Tenant,
organization, project, product, environment, target, trust-domain, policy-family, and
deployment-instance boundaries are explicit and fail closed across scope.

## CLI and operational boundary

`omiv audit` validates supplied local records, constructs no live state, and provides:

- `snapshot-create`, `snapshot-verify`, `event-create`;
- `timeline-build`, `timeline-verify`, `transition-evaluate`;
- `reevaluate`, `revocation-propagate`, `supersession-build`, `renewal-create`;
- `bundle-create`, `bundle-verify`, `bundle-show`, `report-verify`;
- `passport-summary`, `custody-link`, `governance-adapt`.

Phase 5H provides offline reevaluation capability, not a continuously running monitoring
service. It does not schedule work, receive webhooks, poll systems, fetch revocation,
contact timestamp authorities, execute models, deploy artifacts, or enforce decisions.

## Generated-artifact budget

Canonical objects are shared by reference, representative Markdown is limited to one
report, model payloads are excluded, the artifact index contains metadata rather than
file contents, and every generated file is bounded to 1 MiB. The representative bundle
and complete generated tree remain below the Phase 5H repository budget.

## Deterministic defensive limits

- revocation propagation: 256 nodes, 512 typed edges, depth 32;
- supersession: 128 nodes, 128 edges, depth 64;
- renewal chain: depth 64;
- timeline: 256 events, 256 transitions, 64 forks;
- bundle: 512 members, 256 characters per path, 2 MiB manifest metadata,
  64 MiB total declared member bytes, 1 MiB per member;
- artifact index: 180 entries;
- historical-result/report reconstruction: 512 combined event/fork inputs.

Limits are checked iteratively and deterministically. Exceeding one raises an explicit
`LIMIT_EXCEEDED:<CATEGORY>` failure; inputs are not truncated and no partial result is
reported as complete.
