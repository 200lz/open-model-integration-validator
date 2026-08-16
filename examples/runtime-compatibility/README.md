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

`controlled-request.json` exercises the Phase 7B.3 controlled loopback-server
profile with four deterministic text/image and DFlash-off/on probes. The executable
uses only Python's standard library and binds only the controller-selected
`127.0.0.1` port. It uses separate DFlash-off/on processes, embeds and digest-checks
the pinned PNG in llama-server `image_data`, and reports an explicitly request-bound
synthetic backend with no GPU offload. The three `.gguf.fixture` files are tiny text,
not models.

`muse-glimmer-controlled-request.json` contains no model payload or executable. It
is intentionally blocked until an operator supplies the exact locally observed
llama-server digest/version and reviewed exact expected contents. It references the
existing canonical Muse reference fixture and must not be described as executed
evidence.
