# Runtime compatibility candidate example

This tracked offline example exercises the Phase 7B.1 candidate orchestration and
native-observation evidence path with a tiny synthetic artifact and executable. The
files are not a real GGUF model or llama.cpp build and perform no inference.

```console
omiv runtime-compat plan \
  --request examples/runtime-compatibility/request.json \
  --root . \
  --output runtime-compat-plan.json
omiv runtime-compat run \
  --plan runtime-compat-plan.json \
  --root . \
  --output runtime-compat-evidence.json
omiv runtime-compat verify --evidence runtime-compat-evidence.json
```

The executable accepts only the profile's llama.cpp-style model, prompt, seed,
temperature, token-count, and CPU-only native arguments and emits `Paris` as plain
native stdout. It emits no OMIV report or stage claims.

OMIV records an exact OUTPUT `PASS` but keeps LOAD, TOKENIZER, PREFILL, and DECODE
`UNKNOWN`, because this black-box fixture cannot independently establish those
internals. Consequently `run` and `verify` write/validate coherent evidence but exit
`1` with `NOT_VERIFIED`; this is the expected conservative result. Operators must
explicitly supply and trust any real executable. No binary is discovered from
`PATH`, and an unmodified real llama.cpp binary is not exercised by this example.
