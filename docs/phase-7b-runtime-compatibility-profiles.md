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

## Phase 7B.2 candidate: external observation ingestion

Phase 7B.2 adds an offline external-observation envelope beside the unchanged v1
native-execution profile. The only parser implemented by this candidate is explicitly
discriminated as `llama.cpp-cuda-capture.v1`; it is not provider- or runtime-neutral.
It consumes a reviewed `omiv.external-runtime-observation-control.v2` document with
that required capture profile and a manifest root, and emits
`omiv.external-runtime-observation-evidence.v2`:

```console
omiv runtime-compat import-external \
  --control reviewed-external-control.json \
  --manifest-root external-capture \
  --output external-runtime-evidence.json
omiv runtime-compat verify-external \
  --evidence external-runtime-evidence.json
```

Both commands are offline. `import-external` never executes captured arguments and
`verify-external` needs no manifest root or runtime. A coherent partial observation
exits `1`; malformed, unsafe, unsupported, or incoherent input exits `2`. There is no
external-import path to an all-stage PASS in this schema version.

The control is mapping data, not a verdict. OMIV opens the root directory once and
traverses every component descriptor-relatively with no-follow semantics. It hashes
and reads only the opened regular-file descriptor, compares stable descriptor and
directory-member identity, then rechecks manifest bytes, complete membership, and
root identity after all reads. Platforms without the required safe primitives fail
closed. `SHA256SUMS` uses the strict grammar
`<64 lowercase hex><two spaces><portable relative path><LF>`. Duplicate or malformed
lines, self-listing, absolute paths, traversal, symlinks, special files, directories
in place of members, portable case collisions, file/directory-prefix collisions,
missing or extra files, count/size limits, changed files, and digest mismatches fail
closed. The manifest text itself has a 4 MiB parser cap. Directory-entry limits are
enforced while iterating. Every listed member is opened and hashed incrementally in
64 KiB reads without an aggregate raw-byte map. Unused members are never retained.
Parser-required roles are reopened one at a time, checked against their manifest
binding, and bounded independently: reference JSON is at most 2 MiB, argv 128 KiB,
stdout and stderr 2 MiB each, telemetry 1 MiB, runtime/finding text 512 KiB, and other
small text grammars 64 KiB. Selected JSON is strict bounded UTF-8 with duplicate keys
rejected. Telemetry uses incremental UTF-8 decoding directly over the safely opened
descriptor; it is not copied into a whole-file string buffer. Argument evidence is
parsed as an exact,
bounded option/value structure in either `--flag value` or `--flag=value` form and is
bound to the reviewed executable, main model, projector, DFlash draft, and fixed image
roles—including the control-bound image byte count and plan-bound image SHA-256—before
paths are normalized. Process and environment records use documented unique typed
`key=value` fields; unknown or secret-shaped environment facts are rejected. GPU
telemetry is streamed under explicit row, column, and field limits.
No shell command text, `command.txt`, report, event stream, filename, or runner-authored
PASS receives privilege.

Attempt capture ownership is explicit. Argv, process, environment, input identities,
stdout, stderr, their digest records, telemetry, predicate-bearing stdout, and DFlash
activation evidence belong to exactly one attempt and cannot be reused by another,
even when timestamps overlap. Runtime build/version identity, artifact reports and
payloads, the embedded reference plan, source identity, and reviewed skip/finding
sources have explicit global roles; a source cannot be silently reassigned across
incompatible global roles. A finding may annotate a source already owned by its one
attempt, but does not transfer or duplicate that attempt ownership.

The two artifact-report formats have closed grammars. `BARE_FILENAME_V1` is exactly a
filename line followed, in order, by `observed_bytes`, `observed_sha256`,
`transfer_exit`, and `source_url`. `LABELED_V1` is exactly `artifact_role`, `filename`,
`source_repository`, `pinned_revision`, `source_url`, `transfer_exit`,
`observed_bytes`, `expected_bytes`, `observed_sha256`, `expected_sha256`, then `MATCH`.
Every field is required; duplicates, unknown fields, reordered or trailing content,
and cross-format mixtures are rejected. No planned filename is substituted for an
absent reported filename.

Canonical evidence embeds the already self-verifying reference-preflight evidence and
a bounded typed normalized source record. That record contains the facts needed to
reconstruct manifest membership, normalized argv, the strict environment projection,
process times and completeness, stream byte/hash bindings, telemetry samples and
summary, fixed-predicate occurrences, DFlash digest/count facts, retry links, findings,
skips, stages, unknowns, and overall classification. Host-absolute paths, endpoints,
credentials, raw GPU names/UUIDs, provider state, arbitrary environment text, and
import timestamps are excluded; GPU name and identity are retained only as digests.
Offline verification rebuilds every emitted projection from this record and the
embedded plan/control. Rehashing a mutated outer object cannot validate an incoherent
inner projection. It also re-enforces the embedded file count, every member bound, the
reconstructed manifest-text bound, total bytes, role-specific parser caps, and all
count/size totals; therefore it rejects a rehashed object that import could not have
produced.

For `llama.cpp-cuda-capture.v1`, a superseding attempt is valid only when it is
`ACCEPTED`, follows and names a `RETAINED_FAILED` attempt, keeps
`require_single_turn=true`, and contains exact normalized `--single-turn`. Its source
environment must contain the fixed reviewed correction fact, normalized as typed
`SINGLE_TURN_RETRY` evidence with the superseded attempt identifier. A non-retry may
not carry either correction field. These invariants are reconstructed offline and do
not depend on reviewer prose.

All five Phase 7B.1 stages remain `UNKNOWN`. Process `PASS` additionally requires
explicit machine-readable complete/overflow facts for both streams, each capture to
remain below its bound, strict UTC timestamps with end at or after start, and elapsed
time agreement within 25 milliseconds. Exit zero never supplies missing completeness.
Legacy A5 records without those facts remain `INCOMPLETE`; every matching text or fixed
PNG predicate is only `OBSERVED`, including when the separate process status is `PASS`.
No predicate string, including a literal runner-authored `PASS`, can produce predicate
`PASS`. A fixed PNG substring predicate is one narrow output observation,
not general visual understanding. Artifact prose matching a plan is
`MATCHED_PLAN_OBSERVATION` and explicitly says payload bytes were not verified;
artifact `VERIFIED` is reserved for actual safely opened manifest-bound payload bytes.
DFlash activation requires the plan-bound draft, `draft-dflash` argv, and separately
bound positive activation/token-count evidence; it establishes neither speed nor quality.
Skipped probes are `NOT_RUN`. Source binding, companion publisher binding,
numerical/semantic fidelity, performance, safety, production readiness, and origin
authenticity remain explicitly unestablished or unknown. Phase 6F registry and
Assurance verdict semantics remain unchanged.

`control_id` is a bounded lowercase ASCII identifier using only letters, digits, dot,
underscore, and hyphen, with an alphanumeric first and last character. Other serialized
control labels and prose are bounded and screened against OMIV's canonical unsafe-value
policy plus the stricter external-observation rules. The bounded policy inventory
`omiv.external-runtime-privacy.v1` rejects established OMIV credential signatures
(including the release-audit token families, authorization and signed-URL fields,
private-key markers, and selected Google/API-key forms), general host-absolute POSIX paths, control
characters, traversal, URLs/endpoints, user/home and Windows/UNC paths, and private-host
forms. Token-shaped credential families use the release audit's Unicode-aware word
boundaries on both sides; punctuation other than underscore, including a preceding
hyphen, is therefore a delimiter. Header and assignment families use the same leading
word-boundary rule, while private-key markers are intentionally unbounded. Its POSIX
rule treats a slash at the start of a value or after any character
outside the documented portable path-token alphabet as an absolute-path boundary, so it
does not depend on a punctuation allowlist. Every non-path scalar argv value passes
through that same policy before normalization and again during offline reconstruction;
every serialized manifest member path is also screened. Invalid CLI input is rejected
without reflecting the unsafe value or creating partial output.

This bounded pattern screen is not exhaustive secret detection and is not a general
DLP guarantee. Callers remain responsible for sanitizing capture inputs and for
operating the importer from a secret-free evidence directory. A value that does not
match the versioned signatures is not thereby established to be public or safe.
