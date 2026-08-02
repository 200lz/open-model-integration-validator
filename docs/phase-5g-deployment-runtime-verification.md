# Phase 5G — Deployment and Runtime Verification

Phase 5G is OMIV's portable, deterministic, offline foundation for modeling and
verifying approved-to-deployed-to-observed identity continuity. It performs no
deployment and no live runtime observation. Products and adapters collect or
import evidence; the core normalizes evidence without upgrading it; policies
decide whether it is sufficient.

## Canonical dependency order

```text
product subject and scope
→ deployment artifact set
→ assertion authority and target
→ normalized configuration, engine, and environment identities
→ deployment intent and deterministic instance
→ intended deployment manifest
→ deployment record with preserved origin/strength
→ observer identity and authority
→ replay-bound observation plan
→ runtime observation and exact dimension coverage
→ component continuity and drift reconstruction
→ continuity policy verdict
→ signed linkage, governance adapter, Passport summary, custody linkage, report
```

All IDs derive from canonical JSON. No UUID, current time, hostname, username,
address, process/container ID, or local path contributes to identity. Explicit
integer evaluation sequences provide freshness and authority intervals without a
wall-clock fallback.

## Multi-product subjects and artifact sets

The subject taxonomy includes weights, tokenizers, configs, adapters, LoRA,
prompt/chat templates, runtime engines, container images, deployment and tool
packages, agent packages, datasets, policy bundles, security evidence bundles,
and other explicitly declared subjects. A deployment artifact set has exactly
one primary member and separately typed mandatory, optional, engine, image,
startup, external, and runtime-generated members.

Each member preserves its artifact class, canonical artifact reference,
required status, expected observation method, continuity requirement, and
limitations. Continuity is reconstructed for each member. A matching primary
digest cannot hide a tokenizer, adapter, config, or template mismatch.

## Evidence strength, authority, and scope

Evidence strengths are `DECLARED`, `IMPORTED_UNVERIFIED`,
`STRUCTURALLY_VERIFIED`, `EVIDENCE_LINKED`, `SYSTEM_OBSERVED`, `SIGNED`,
`SIGNED_AND_TRUSTED`, and `INDEPENDENTLY_CORROBORATED`. These are not a single
verified Boolean. Signature status, trust, assertion authority, corroboration,
and limitations remain separate.

They are also not an ordinal strength ladder. A signed declaration is not a
system observation, a trusted signature is not independent corroboration, and
an unsigned direct observation remains directly observed. Adapter capability
checks use explicit accepted-origin sets rather than enum position.

Authority scopes constrain object and assertion type, artifact and target class,
tenant, organization, project, product, environment, target, trust domain,
action, explicit validity sequence, and delegation. Trust in tenant A is not
trust in tenant B; staging authority is not production authority. A scanner may
assert a scan but not deployment. A deployer may assert a deployment action but
not independent runtime observation unless policy explicitly accepts limited
self-observation.

## Deployment instances and replay

`DeploymentInstanceIdentity` binds intent, target, scope, artifact set,
configuration, engine, explicit evaluation context, generation, and predecessor.
The observation plan adds manifest digest, policy digest, observer, scope,
sequence namespace, epoch, expected sequence, and predecessor observation.
Wrong instance, manifest, target, artifact set, observer, namespace, epoch,
sequence, predecessor, or evaluation context yields fail-closed replay rejection.
Competing content at one sequence or competing successors are reported as a
deterministic chain fork.
Timestamp-only replay protection is not accepted.

## Configuration, engine, environment, and observer identities

Configuration identity uses ordered allowlisted fields, explicit default/alias
origin, normalization-policy digest, logical secret-reference IDs and digests,
and explicit unknown fields. It rejects secret values, raw environment dumps,
raw commands, credential paths, and local paths.
Secret-reference digests cover logical reference metadata and provider class,
not secret values; OMIV does not create a secret-value hash oracle.

Engine identity separates family, display version, revision, binary digest,
container image digest, build digest, dependency-lock digest, and configuration
schema. Version equality is weaker than binary equality. Environment identity is
privacy-safe and contains only logical classes and policy/dependency digests.

Observer identity is separate from deployer and engine. Capabilities are
explicit; behavioral observation remains reserved and non-operational. Policies
can require different actor/signer/key/trust root and independent corroboration.
A trusted observer is not proof that its implementation is correct or its host is
uncompromised.

## Observation coverage and proxy identity

Coverage records expected, observed, unsupported, inaccessible, errored, stale,
proxy-only, and independently corroborated dimensions. Complete means
`COMPLETE_FOR_REQUIRED_DIMENSIONS`, not universal runtime coverage.

Direct byte and artifact-set identity are distinguished from manifest identity,
registry references, container-image proxies, configuration proxies, declared
identity, and unobserved state. Image continuity proves only image identity.
Registry-reference continuity is only a proxy. Neither proves loaded artifact
bytes.

## Policies, verdicts, and drift

Policies specify accepted subjects and evidence strengths, required dimensions,
direct/proxy requirements, actor and observer authority, scope, signing, trust,
separation of duties, corroboration, freshness, replay behavior, drift behavior,
and whether limited Phase 5F security evidence is acceptable.

The air-gapped policy produces `PASS_WITH_LIMITATIONS` when online revocation or
continuing trust-bundle freshness is unavailable. It never converts absence of an
online check into unqualified PASS. The regulated policy emits structured gaps
and remains fail closed.

The fail-closed precedence is:

```text
EVIDENCE_BROKEN → REPLAY_REJECTED → MISMATCH → DRIFT_DETECTED
→ OBSERVER_UNAUTHORIZED → OBSERVER_UNTRUSTED → DEPLOYMENT_UNVERIFIED
→ COVERAGE_INCOMPLETE → STALE → NOT_OBSERVED → NOT_EVALUATED
→ IDENTITY_PROXY_MATCH → PARTIAL_CONTINUITY → PASS_WITH_LIMITATIONS → PASS
```

Drift categories cover primary and companion artifacts, artifact sets,
revision/variant, tokenizer/config/template/adapter, runtime configuration,
engine/binary/image, environment/target/scope/trust, stale upstream evidence,
observer identity/authority, replay, coverage gaps, and unknown components.
Configuration digest comparison does not establish semantic equivalence, and
tokenizer configuration identity does not establish tokenizer parity.

## Signing, adapters, and derived integration

The Phase 5D registries add deployment intent, manifest, record, runtime
observation, and continuity evaluation types with distinct issuance purposes.
Signing does not upgrade origin, deployment status, authority, coverage,
direct/proxy strength, freshness, continuity, security, behavior, or safety. A
signed mismatch remains a mismatch.

The static adapter registry operationally supports only explicit local JSON
normalization. OCI, Kubernetes, vLLM, Triton, TensorRT-LLM, llama.cpp, MLX,
Ollama, LM Studio, cloud, internal-platform, and air-gapped appliance adapters
are reserved identities and fail closed. There is no dynamic plugin loading or
platform SDK dependency.

Governance adapters preserve the Phase 5F source verdict and every limitation;
strict policy rejects `PASS_WITH_LIMITATIONS` unless explicitly configured.
Passport and custody integrations are separate versioned records. They never
mutate Passport v1/v2, custody ledgers, Phase 5E decisions, or Phase 5F evidence,
and never fabricate approval, deployment, behavior, safety, or continuous trust.

## Snapshot and operational boundary

A runtime observation records the state visible to an observer. It does not by
itself prove that the observer is correct or that the runtime is uncompromised.
Artifact continuity verifies identity continuity between approved, deployed, and
observed artifacts. It does not establish numerical, tokenizer, behavioral, or
safety parity. A continuity PASS is scoped to the selected policy and supplied
evidence.

Every report states `SNAPSHOT_ONLY`, trusted timestamp `NOT_AVAILABLE`, behavioral parity `NOT_CHECKED`, runtime
safety `NOT_VERIFIED`, continuous continuity `NOT_ESTABLISHED`, and deployment
performed by OMIV `NO`. Phase 5G does not deploy, upload, contact endpoints,
invoke Docker/Kubernetes/cloud tools, install agents, execute models, observe
production, poll, or continuously monitor.

Synthetic output is capped at 150 files, targets no more than 100, rejects
duplicate content and canonical IDs, and limits every indexed file to 1 MiB. The
Kimi record is analysis-only gap reporting: no deployment, observer, observation,
continuity PASS, or runtime-safety claim.
