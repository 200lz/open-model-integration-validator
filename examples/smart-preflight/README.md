# Smart Preflight candidate example

This candidate Phase 7A example discovers one tracked local Phase 6A evidence
record and generates a Phase 6F request without downloading, converting, contacting
a remote collector, or using a GPU:

```console
omiv smart-preflight plan \
  --intent examples/smart-preflight/intent.json \
  --root . \
  --output smart-plan.json \
  --assurance-request-output assurance-request.json
omiv assurance plan \
  --request assurance-request.json \
  --root . \
  --output assurance-plan.json
```

The first command selects evidence only when a requested dimension has one unique,
canonical final evidence record. Distinct competing records remain ambiguous and
require an explicit caller choice. The second command is the unchanged Phase 6F
preflight boundary.
