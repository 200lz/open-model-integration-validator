# Public and future commercial boundary

The owner selected this original repository as the unique future public core:
`ORIGINAL_REPOSITORY_SELECTED_AS_UNIQUE_PUBLIC_CORE`. Its full preservation history,
stable canonical interfaces, and public verifier remain together here. This work does
not create a snapshot, mirror, specification repository, or enterprise repository.

```text
open-model-integration-validator       PUBLIC CORE
              |
              | stable canonical interfaces
              v
       future private services         NOT IMPLEMENTED
```

OMIV's public foundation includes canonical schemas, canonicalization, IDs and
digests, signature verification, trust/evidence semantics, policy-result semantics,
the offline CLI, local verification, Model Passports, bounded public-metadata
collectors, provider-neutral interfaces, public profiles, examples, synthetic
fixtures, and a future public GitHub Action. Future Assurance Bundles must remain
publicly and independently verifiable; Phase 6F is not implemented today.

Possible future commercial services may include a hosted control plane, private
evidence registry/history, continuous collection and monitoring, private connectors,
organization policy, approvals and promotion, a Private Runner, deployment admission,
runtime observation, SSO/RBAC, KMS/HSM integration, compliance mapping, customer
integrations, an enterprise API/dashboard, and contracted support or SLAs.

None of those commercial services exists in this repository. No `omiv-enterprise` or
`omiv-spec` repository is created by this release work.

**Invariant:** Commercial services may automate the trust lifecycle but may not
redefine or secretly strengthen canonical evidence semantics. A private service may
add evidence, policy, custody, or operational guarantees, but a public verifier must
be able to distinguish those additions from canonical OMIV facts.
