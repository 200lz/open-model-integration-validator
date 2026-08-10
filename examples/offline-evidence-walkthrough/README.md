# Offline evidence walkthrough example

This example runs the real installed OMIV CLI through a fixed offline command
allowlist. Its manifest is `NON_CANONICAL_DEMONSTRATION_MANIFEST`, `SYNTHETIC`,
`DEMONSTRATION_ONLY`, `NOT_PROVIDER_EVIDENCE`, `NOT_AN_ASSURANCE_BUNDLE`, and
`NOT_A_SAFETY_OR_AUTHENTICITY_RESULT`.

From the repository root, run the read-only path:

```bash
python tools/run_offline_evidence_walkthrough.py
```

Expected final line:

```text
WALKTHROUGH_COMPLETE steps=10 expected_exit_1=2 malformed_demo=NOT_RUN network=NONE model_execution=NONE repository_writes=NONE
```

To exercise malformed-input exit `2`, give the runner an explicit temporary
directory outside the checkout:

```bash
walkthrough_tmp="$(mktemp -d)"
python tools/run_offline_evidence_walkthrough.py \
  --temporary-directory "$walkthrough_tmp"
rmdir "$walkthrough_tmp"
```

The runner treats the two tracked exit-`1` results as expected semantic limitations,
not command failures. It never invokes a shell, provider collector, conversion tool,
model, tokenizer, template, runtime, private key, or network interface. It does not
require or inspect the ignored Kimi raw inventory.

Read the [complete walkthrough](../../docs/offline-evidence-walkthrough.md) for every
input, command, expected exit, scoped conclusion, non-claim, and next evidence link.
Return to the [documentation index](../../docs/README.md) or the
[main README](../../README.md).
