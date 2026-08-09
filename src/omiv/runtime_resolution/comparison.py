"""Bounded comparison of explicitly supplied backend results."""

from __future__ import annotations

from collections.abc import Sequence
from decimal import Decimal, localcontext
from typing import Any

from omiv.canonical import canonical_sha256
from omiv.quantization.models import decimal_context, parse_bounded_decimal
from omiv.quantization.numerical import canonical_decimal
from omiv.runtime_resolution.building import build_comparison
from omiv.runtime_resolution.models import (
    BackendComparisonStatus,
    BackendResult,
    BackendResultObservation,
    ComparisonFinding,
    CrossBackendComparison,
    CrossBackendProbeSet,
    ModelRuntimeBinding,
    ResultDimension,
    RuntimeResolutionPolicy,
)


def compare_backend_results(
    probe_set: CrossBackendProbeSet,
    bindings: Sequence[ModelRuntimeBinding],
    observations: Sequence[BackendResultObservation],
    *,
    policy: RuntimeResolutionPolicy | None = None,
) -> CrossBackendComparison:
    """Compare matching supplied probes while keeping stochastic scope explicit."""
    if len(bindings) < 2 or len(observations) < 2:
        return build_comparison(
            probe_set.subject,
            probe_set,
            bindings,
            observations,
            status=BackendComparisonStatus.INSUFFICIENT_EVIDENCE,
            findings=(),
            policy=policy,
        )
    maps = [
        {result.probe_id: result for result in observation.results} for observation in observations
    ]
    findings: list[ComparisonFinding] = []
    stochastic_difference = False
    mismatch = False
    tolerance_pass = False
    for probe in probe_set.probes:
        supplied = [mapping.get(probe.probe_id) for mapping in maps]
        if any(result is None for result in supplied):
            mismatch = True
            findings.append(
                _finding(
                    probe.probe_id,
                    ResultDimension.FINAL_OUTPUT_BYTES,
                    "RESULT_MISSING",
                    None,
                    None,
                    "A required supplied result is missing.",
                )
            )
            continue
        values = [result for result in supplied if result is not None]
        has_error = any(
            result.error_class is not None or result.error is not None for result in values
        )
        for dimension in probe.dimensions:
            if has_error and dimension != ResultDimension.ERROR_CLASS:
                mismatch = True
                findings.append(
                    _finding(
                        probe.probe_id,
                        dimension,
                        "ERROR_RESULT_NOT_COMPARABLE_AS_SUCCESS",
                        None,
                        None,
                        "Error observations remain distinct from successful output dimensions.",
                    )
                )
                continue
            equal, left, right = _dimension_equal(values, dimension)
            if dimension == ResultDimension.SELECTED_LOGIT_SAMPLES and not equal:
                threshold = policy.numerical_tolerance if policy is not None else None
                metric = selected_logit_max_absolute_error(values[0], values[1])
                within = threshold is not None and parse_bounded_decimal(
                    metric
                ) <= parse_bounded_decimal(threshold)
                tolerance_pass |= within
                mismatch |= not within
                findings.append(
                    ComparisonFinding(
                        dimension=dimension,
                        probe_id=probe.probe_id,
                        status="WITHIN_TOLERANCE" if within else "OUTSIDE_TOLERANCE",
                        reference_value_digest=left,
                        candidate_value_digest=right,
                        metric="maximum.absolute.error",
                        metric_value=metric,
                        threshold=threshold,
                        limitation="Selected logits do not establish full-logit equivalence.",
                    )
                )
                continue
            status = "EXACT_FOR_DIMENSION" if equal else "MISMATCH_FOR_DIMENSION"
            findings.append(
                _finding(
                    probe.probe_id,
                    dimension,
                    status,
                    left,
                    right,
                    "Final aggregate and stream boundaries are independent dimensions.",
                )
            )
            if not equal:
                if probe.execution_mode.value == "DECLARED_STOCHASTIC":
                    stochastic_difference = True
                else:
                    mismatch = True
    if mismatch:
        status = BackendComparisonStatus.MISMATCH_FOR_DECLARED_PROBES
    elif stochastic_difference:
        status = BackendComparisonStatus.STOCHASTIC_RESULTS_NOT_DIRECTLY_COMPARABLE
    elif tolerance_pass:
        status = BackendComparisonStatus.WITHIN_EXPLICIT_NUMERICAL_POLICY_FOR_DECLARED_PROBES
    elif findings:
        status = BackendComparisonStatus.EXACT_FOR_DECLARED_PROBES
    else:
        status = BackendComparisonStatus.INSUFFICIENT_EVIDENCE
    return build_comparison(
        probe_set.subject,
        probe_set,
        bindings,
        observations,
        status=status,
        findings=findings,
        policy=policy,
    )


def selected_logit_max_absolute_error(left: BackendResult, right: BackendResult) -> str:
    left_values = {(sample.position, sample.token_id): sample for sample in left.selected_logits}
    right_values = {(sample.position, sample.token_id): sample for sample in right.selected_logits}
    if not left_values or left_values.keys() != right_values.keys():
        raise ValueError("selected-logit positions are not comparable")
    with localcontext(decimal_context()):
        errors = [
            abs(
                parse_bounded_decimal(left_values[key].value)
                - parse_bounded_decimal(right_values[key].value)
            )
            for key in sorted(left_values)
        ]
        return canonical_decimal(max(errors, default=Decimal(0)))


def _dimension_equal(
    values: Sequence[BackendResult], dimension: ResultDimension
) -> tuple[bool, str | None, str | None]:
    projected = [_project(value, dimension) for value in values]
    digests = [canonical_sha256({"domain": dimension.value, "value": value}) for value in projected]
    return len(set(digests)) == 1, digests[0], digests[1]


def _project(value: BackendResult, dimension: ResultDimension) -> Any:
    if dimension in {ResultDimension.FINAL_OUTPUT_BYTES, ResultDimension.FINAL_TEXT}:
        return value.output.model_dump(mode="json")
    if dimension == ResultDimension.TOKEN_ID_SEQUENCE:
        return value.token_ids
    if dimension == ResultDimension.STRUCTURED_JSON:
        return value.structured_json_digest
    if dimension == ResultDimension.TOOL_CALL_STRUCTURE:
        if value.tool_calls:
            return [call.model_dump(mode="json") for call in value.tool_calls]
        return value.tool_call_digest
    if dimension == ResultDimension.FINISH_REASON:
        return value.finish_reason
    if dimension == ResultDimension.SELECTED_LOGIT_SAMPLES:
        return [sample.model_dump(mode="json") for sample in value.selected_logits]
    if dimension == ResultDimension.ERROR_CLASS:
        return {
            "error_class": value.error_class,
            "error": value.error.model_dump(mode="json") if value.error is not None else None,
        }
    if dimension == ResultDimension.STREAM_FINAL_AGGREGATE:
        return value.stream_final_digest
    if dimension == ResultDimension.STREAM_CHUNK_BOUNDARIES:
        return value.stream_chunk_digests
    raise ValueError(f"unsupported result dimension: {dimension}")


def _finding(
    probe_id: str,
    dimension: ResultDimension,
    status: str,
    left: str | None,
    right: str | None,
    limitation: str,
) -> ComparisonFinding:
    return ComparisonFinding(
        dimension=dimension,
        probe_id=probe_id,
        status=status,
        reference_value_digest=left,
        candidate_value_digest=right,
        metric=None,
        metric_value=None,
        threshold=None,
        limitation=limitation,
    )
