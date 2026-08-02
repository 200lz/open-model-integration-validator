# OMIV Artifact Security Evidence Report

- Report: `security_report_8f6724411e67c6e358473d0a253a0c87`
- Policy: `omiv.security-policy.team_release_security_gate.v1`
- Security verdict under policy: **FAIL**
- Scanner identities: `scanner_aea44a66e9a2227c6dce5dc97d92bc67`
- Scanner accepted by policy: **TRUSTED_BY_POLICY**
- Scanner correctness independently proven: **NOT_ESTABLISHED**
- Inspection type: `BOUNDED_PAYLOAD_INSPECTION, EXECUTABLE_CONTENT_INSPECTION, FILE_NAME_POLICY_CHECK, FILE_TYPE_POLICY_CHECK, MAGIC_BYTE_INSPECTION, METADATA_INSPECTION, SCRIPT_CONTENT_INSPECTION, SERIALIZATION_FORMAT_INSPECTION, STATIC_PATTERN_INSPECTION`
- Declared-scope coverage: **COMPLETE_FOR_DECLARED_SCOPE**
- Policy coverage result: **COMPLETE**
- Scanner-capability coverage: **UNSUPPORTED**
- Files declared/discovered/inspected: 1/1/1
- Bytes declared/discovered/inspected/not inspected: 30/30/30/0
- Payload bytes read: YES (BOUNDED)
- Code execution: **NO**
- Network access: **NO**
- Blocking findings: 1
- Payload integrity: **NOT_VERIFIED (SEPARATE)**
- Behavioral/runtime safety: **NOT_VERIFIED**
- Approval: **SEPARATE**
- Deployment: **NOT_PERFORMED**

## Declared inspection scope

- `unsafe-serialization.pkl`

## Findings by severity

- CRITICAL: 0
- HIGH: 1
- MEDIUM: 0
- LOW: 0
- INFO: 0
- UNKNOWN: 0

## Unsupported scope

- `unsafe-serialization.pkl`: Built-in scanner has no structure parser for this file type.

## Limitations

- A policy PASS is scoped to supplied verified evidence and declared methods.
- No findings does not prove absence of vulnerabilities.
- Policy evaluation does not establish payload integrity, runtime safety, approval, or deployment.
- Static inspection does not establish runtime safety, behavior, integrity, or fidelity.

> No findings does not prove safety or absence of vulnerabilities. A PASS only means
> the supplied, verified evidence satisfies the selected policy for the declared scope.
> Static inspection does not establish runtime safety, behavior, payload integrity,
> tokenizer parity, or numerical fidelity.
