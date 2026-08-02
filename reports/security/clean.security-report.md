# OMIV Artifact Security Evidence Report

- Report: `security_report_84d63be60337085a13c1d229017d1a66`
- Policy: `omiv.security-policy.personal_local_security_review.v1`
- Security verdict under policy: **PASS_WITH_LIMITATIONS**
- Scanner identities: `scanner_aea44a66e9a2227c6dce5dc97d92bc67`
- Scanner accepted by policy: **TRUSTED_BY_POLICY**
- Scanner correctness independently proven: **NOT_ESTABLISHED**
- Inspection type: `BOUNDED_PAYLOAD_INSPECTION, EXECUTABLE_CONTENT_INSPECTION, FILE_NAME_POLICY_CHECK, FILE_TYPE_POLICY_CHECK, FORMAT_STRUCTURE_INSPECTION, MAGIC_BYTE_INSPECTION, METADATA_INSPECTION, SCRIPT_CONTENT_INSPECTION, SERIALIZATION_FORMAT_INSPECTION, STATIC_PATTERN_INSPECTION`
- Declared-scope coverage: **COMPLETE_FOR_DECLARED_SCOPE**
- Policy coverage result: **COMPLETE**
- Scanner-capability coverage: **COMPLETE**
- Files declared/discovered/inspected: 1/1/1
- Bytes declared/discovered/inspected/not inspected: 10/10/10/0
- Payload bytes read: YES (BOUNDED)
- Code execution: **NO**
- Network access: **NO**
- Blocking findings: 0
- Payload integrity: **NOT_VERIFIED (SEPARATE)**
- Behavioral/runtime safety: **NOT_VERIFIED**
- Approval: **SEPARATE**
- Deployment: **NOT_PERFORMED**

## Declared inspection scope

- `clean.safetensors`

## Findings by severity

- CRITICAL: 0
- HIGH: 0
- MEDIUM: 0
- LOW: 0
- INFO: 0
- UNKNOWN: 0

## Unsupported scope

- None declared

## Limitations

- A policy PASS is scoped to supplied verified evidence and declared methods.
- No findings does not prove absence of vulnerabilities.
- Policy evaluation does not establish payload integrity, runtime safety, approval, or deployment.
- Policy permits a scope-limited result with explicit limitations.
- Static inspection does not establish runtime safety, behavior, integrity, or fidelity.

> No findings does not prove safety or absence of vulnerabilities. A PASS only means
> the supplied, verified evidence satisfies the selected policy for the declared scope.
> Static inspection does not establish runtime safety, behavior, payload integrity,
> tokenizer parity, or numerical fidelity.
