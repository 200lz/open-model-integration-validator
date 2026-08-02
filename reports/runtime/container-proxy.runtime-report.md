# OMIV Deployment and Runtime Snapshot Report

- Deployment performed by OMIV: **NO**
- Deployment evidence origin: **SIGNED_AND_TRUSTED**
- Runtime observed: **YES**
- Observation strength: **INDEPENDENTLY_CORROBORATED**
- Source security verdict: **PASS**
- Required dimensions observed: **8/8**
- Proxy-only dimensions: `ARTIFACT_SET_DIGEST, PRIMARY_ARTIFACT_DIGEST`
- Unobserved dimensions: `None`
- Approved artifact set: `deployment_artifact_set_cd68f234c89aca95a9edbd9cef3391cd`
- Artifact-set continuity: **IDENTITY_PROXY_MATCH**
- Configuration continuity: **FULL_CONTINUITY**
- Engine binary continuity: **FULL_CONTINUITY**
- Observer authority: **AUTHORIZED**
- Replay status: **BOUND**
- Observation freshness: **CURRENT**
- Trusted timestamp: **NOT_AVAILABLE**
- Revocation status: **EVALUATED_NO_APPLICABLE_REVOCATION**
- Trust-bundle freshness: **CURRENT_FOR_EXPLICIT_CONTEXT**
- Policy-scoped verdict: **IDENTITY_PROXY_MATCH**
- Snapshot only: **YES**
- Behavioral parity: **NOT_CHECKED**
- Runtime safety: **NOT_VERIFIED**
- Continuous continuity: **NOT_ESTABLISHED**

## Limitations

- Continuity PASS is policy- and snapshot-scoped; behavior, safety, and continuous continuity remain unverified.
- Deployment intent records authorization and does not prove deployment.
- Deployment record evidence does not independently prove deployment success.
- Manifest defines intended state; it does not prove deployed or loaded state.
- OMIV performed no external deployment action.
- Observation plan defines required snapshot dimensions only.
- Runtime observation is a point-in-time observer assertion, not continuous trust.
- Security evidence remains policy- and declared-scope limited.
- Snapshot continuity does not establish continuously unchanged state.
- Trusted observer identity does not prove observer correctness or host integrity.

## Coverage remediation

- Capture direct identity evidence for proxy-only dimensions.

> A continuity PASS is scoped to the selected policy, supplied evidence, observed
> dimensions, deployment instance, scope, trust domain, and evaluation context.
> Snapshot continuity does not establish behavior, numerical parity, safety, or
> continuously unchanged state.
