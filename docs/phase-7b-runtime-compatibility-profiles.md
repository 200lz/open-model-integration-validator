# Phase 7B.1 candidate hardening: Runtime Compatibility Profiles

## Status and boundary

Phase 7 scope is not frozen. This document describes a minimal Phase 7B.1 hardening
slice under active development; it is not a Phase 7, Phase 7B, or Phase 7B.1 release,
finalized scope, certification, or general runtime-compatibility claim.

The first profile is a local llama.cpp-compatible runner workflow. The core command
and evidence names are provider-neutral. A result applies only to one pinned artifact,
one explicitly supplied executable digest and version, one profile and command, one
CPU-only environment, one set of resource limits, and one supplied test vector.

## Local workflow

The tracked example is fully synthetic and offline:

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

For this fixture, `plan` exits `0`; `run` and `verify` intentionally exit `1` after
writing or validating the `NOT_VERIFIED` evidence described below.

`plan` is read-only. It never starts the executable. It reports whether the exact
executable and artifact are locally available, regular, bounded, executable where
required, and equal to their supplied SHA-256 pins. It also records the expected
version check and runtime work, and states that network, download, compilation,
conversion, and GPU work are absent.

`run` re-hashes both inputs, executes the explicit executable's bounded `--version`
command, checks the exact version pin, re-hashes again, then executes the native
profile argument array directly. It re-hashes both inputs after execution. A change
at any boundary fails closed. OMIV does not search `PATH`, inspect a runtime
installation, select a binary, find a model, or substitute another executable.

The successful synthetic native-output observation is intentionally not a complete
compatibility verification:

```text
llama.cpp
LOAD       UNKNOWN
TOKENIZER  UNKNOWN
PREFILL    UNKNOWN
DECODE     UNKNOWN
OUTPUT     PASS

Runtime compatibility: NOT_VERIFIED
```

The JSON evidence retains canonical identity, the complete canonical plan, duplicated
plan identity, profile, artifact and executable bindings, observed version, portable
native argument arrays, the exact controlled environment semantics, limits, complete
test vector and digest, bounded base64 stdout/stderr, return codes, timeouts,
work-file observations, OMIV-derived stage results, findings, unknowns, and
limitations. `HOME` and `TMPDIR` use the canonical `{WORK_DIRECTORY}` value together
with `FRESH_EMPTY_TEMPORARY_DIRECTORY`; this records that both were exactly the fresh
per-run directory without leaking an ephemeral host path.

## Native CLI contract and stage semantics

Candidate profile `omiv.runtime-compatibility-profile.llama-cpp-native-output.v1` uses
llama.cpp-style `--model`, `--prompt`, `--seed`, `--temp`, `--n-predict`,
`--gpu-layers 0`, `--simple-io`, and `--no-display-prompt` arguments. It passes no
OMIV-only report, profile, stage, test-vector, or digest flags to the runtime. Native
stdout is compared byte-for-byte after strict UTF-8 decoding; native stderr is also
retained and required to be valid UTF-8 for a complete output observation.

The five stage names have deliberately narrow meanings in this black-box profile:

| Stage | Candidate meaning | Current derivation |
| --- | --- | --- |
| LOAD | The runtime itself opened and consumed the pinned artifact. | `UNKNOWN`: OMIV can prove the file pin and argument binding, but native stdout and exit status do not independently prove consumption. |
| TOKENIZER | The runtime itself tokenized the supplied prompt. | `UNKNOWN`: the native CLI does not expose an independent tokenizer observation. |
| PREFILL | The runtime itself executed prompt prefill. | `UNKNOWN`: the native CLI does not expose an independent prefill observation. |
| DECODE | The observed bytes resulted from model decoding. | `UNKNOWN`: a black-box executable can emit bytes without proving their origin. |
| OUTPUT | Native stdout exactly equals the supplied expected output. | `PASS` only for an exact match after a zero exit with complete bounded UTF-8 stdout/stderr; exact mismatch is `FAIL`, and incomplete observations are `UNKNOWN`. |

A blocked invocation leaves every stage `NOT_TESTED`. Timeout, nonzero exit, stream
overflow, or non-UTF-8 native output leaves every executed stage `UNKNOWN`. JSON that
declares OMIV stage names or a top-level `PASS` is treated only as native stdout
bytes; it receives no privilege even when those bytes are the expected output.

The current profile therefore does not emit `VERIFIED_WITHIN_PROFILE`: four internal
stages cannot be independently established. That status remains reserved for a
future explicitly versioned profile only if complete pinned end-to-end observations
support every stage. Even then it would mean a bounded compatibility probe, not
authenticity, numerical or semantic equivalence, safety, performance, production
approval, or proof that particular weights produced an output.

## Canonical plan binding and offline verification

Evidence embeds the complete `omiv.runtime-compatibility-plan.v1`. Offline parsing
recomputes its `plan_id` and `plan_digest`, reconstructs the profile-defined native
invocation, and verifies the plan's request-to-file bindings and availability state.
It then checks every duplicated or derived evidence field against the embedded plan:
request identity, plan identity, profile, artifact and executable paths and pins,
version pin, invocation, environment, limits, test vector, test-vector digest, and
captured process arguments and limits. Stages and unknowns are reconstructed from the
raw native capture. Recomputing only the outer evidence digest cannot make an
incoherent mutation valid.

Canonical hashing establishes integrity and self-consistency. It does not establish
who originated the request, plan, executable, artifact, or evidence. A party able to
replace a complete coherent object and recompute every identity can create a new
self-consistent object; origin authenticity requires a separate trust mechanism.

## Process, output, and file controls

OMIV uses an argument array with `shell=False`, closed stdin, a fresh empty working
directory, a new process session, bounded wall time, bounded stdout and stderr, and a
minimal environment. The environment sets only `PATH=/usr/bin:/bin`, UTF-8 C locale,
an isolated `HOME` and `TMPDIR`, and empty CUDA/HIP visibility. The command pins
`--gpu-layers 0`.

The profile expects no work files. A Linux child file-size limit bounds an individual
created file, and post-execution inspection bounds the entry count, individual size,
and cumulative captured size. Any file, directory, symlink, unsafe object, or exceeded
bound prevents verification. Captured stream bytes never exceed their declared
limits, including on timeout or overflow.

The operator must trust the explicitly supplied executable. These controls limit and
record execution; they are not an OS security sandbox and do not make an untrusted
binary safe. Candidate execution currently requires POSIX process-group and file-size
controls; unsupported platforms fail during preflight rather than dropping a bound.

## Exit behavior

- `0`: `plan` is ready, or a future supported `run`/`verify` result yields
  `VERIFIED_WITHIN_PROFILE`;
- `1`: preflight is blocked, or bounded evidence is valid but compatibility is not
  verified because of a failed, unknown, or untested stage or another fail-closed
  runtime finding; and
- `2`: a request, profile, plan, or evidence schema is unsupported or malformed; a
  path is unsafe; a blocked plan is passed to `run`; or an operational error prevents
  a coherent candidate record.

The current native-output profile returns `1` from `run` and `verify` even when OUTPUT
passes, because the four internal stages remain `UNKNOWN`. Timeout, output overflow,
nonzero exit, non-UTF-8 output, version mismatch, unexpected files, and output
mismatch normally produce bounded JSON evidence and exit `1`. Unsupported control
schemas and profiles are rejected before execution with exit `2`.

## Composition and non-goals

Phase 7B/7B.1 evidence is deliberately not added to the Phase 6F Phase 5/6A–6E schema
registry and is not auto-selected by Phase 7A. That preserves existing Assurance
Bundle projection, unknown, signature, trust-policy, and offline-verification
semantics. A future explicitly versioned composition may treat this candidate record
as supporting evidence without changing its meaning; no such boundary is claimed now.

This slice does not:

- run or validate an unmodified real llama.cpp build by default;
- download, install, compile, convert, quantize, or discover a runtime or model;
- probe CUDA or other accelerators, use a GPU, or select hardware;
- establish cross-version, cross-artifact, cross-device, cross-prompt, numerical, or
  semantic equivalence;
- establish throughput, production readiness, safety, authenticity, publisher
  authority, or freedom from malicious runtime behavior; or
- freeze Phase 7 scope.

The tracked executable and artifact are synthetic native-CLI fixtures, not a real
runtime or model. Direct real-runtime adapters, independently observable internal
stages, additional profiles, and stronger fidelity work require later candidate
slices and separate review.
