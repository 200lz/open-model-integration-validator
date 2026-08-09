"""Bounded Decimal numerical reconstruction and metrics for Phase 6C v1."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from decimal import Decimal, DecimalException, localcontext

from omiv.quantization.models import (
    MAX_DECIMAL_INTERMEDIATE_ADJUSTED_EXPONENT,
    MAX_DECIMAL_OUTPUT_LENGTH,
    FindingKind,
    MetricState,
    MetricValue,
    NumericalCodec,
    QuantizationParameterObservation,
    TensorMetricSet,
    decimal_context,
    parse_bounded_decimal,
)


def canonical_decimal(value: Decimal) -> str:
    """Return a finite, rounded, non-exponent, negative-zero-free decimal string."""
    if not value.is_finite():
        raise ValueError("non-finite numerical value")
    if value != 0 and abs(value.adjusted()) > MAX_DECIMAL_INTERMEDIATE_ADJUSTED_EXPONENT:
        raise ValueError("LIMIT_EXCEEDED:DECIMAL_OUTPUT_MAGNITUDE")
    try:
        with localcontext(decimal_context()):
            rounded = +value
    except DecimalException as exc:
        raise ValueError("LIMIT_EXCEEDED:DECIMAL_OUTPUT_MAGNITUDE") from exc
    if rounded == 0:
        return "0"
    rendered = format(rounded, "f")
    if "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    if len(rendered) > MAX_DECIMAL_OUTPUT_LENGTH:
        raise ValueError("LIMIT_EXCEEDED:DECIMAL_OUTPUT_MAGNITUDE")
    return rendered


def decimal_values(values: Iterable[str]) -> tuple[Decimal, ...]:
    result: list[Decimal] = []
    for value in values:
        if value in {"NaN", "sNaN", "Infinity", "-Infinity"}:
            raise ValueError("NON_FINITE_INPUT")
        parsed = parse_bounded_decimal(value)
        result.append(parsed)
    return tuple(result)


def reconstruct_values(
    candidate_values: Sequence[str],
    parameters: QuantizationParameterObservation,
) -> tuple[str, ...]:
    """Reconstruct only the two explicitly supported v1 numerical codecs."""
    values = decimal_values(candidate_values)
    if parameters.numerical_codec == NumericalCodec.UNQUANTIZED_IDENTITY:
        return tuple(canonical_decimal(value) for value in values)
    if parameters.numerical_codec != NumericalCodec.UNIFORM_AFFINE_INTEGER:
        raise ValueError("FORMAT_NOT_NUMERICALLY_SUPPORTED")
    if not parameters.complete_for_supported_codec:
        raise ValueError("QUANTIZATION_PARAMETERS_INCOMPLETE")
    if parameters.scale is None or parameters.zero_point is None:
        raise ValueError("QUANTIZATION_PARAMETERS_INCOMPLETE")
    if parameters.storage_bit_width is None or parameters.storage_signed is None:
        raise ValueError("QUANTIZATION_PARAMETERS_INCOMPLETE")
    scale = parse_bounded_decimal(parameters.scale, maximum_adjusted_exponent=128)
    if scale <= 0:
        raise ValueError("invalid affine scale")
    bits = parameters.storage_bit_width
    if parameters.storage_signed:
        minimum, maximum = -(2 ** (bits - 1)), 2 ** (bits - 1) - 1
    else:
        minimum, maximum = 0, 2**bits - 1
    if not minimum <= parameters.zero_point <= maximum:
        raise ValueError("invalid affine zero point")
    if parameters.quantization_axis is not None:
        raise ValueError("FORMAT_NOT_NUMERICALLY_SUPPORTED:AXIS_PARAMETERS")
    if parameters.block_size is not None:
        raise ValueError("FORMAT_NOT_NUMERICALLY_SUPPORTED:BLOCK_PARAMETERS")
    if parameters.group_size is not None and parameters.group_size != len(values):
        raise ValueError("FORMAT_NOT_NUMERICALLY_SUPPORTED:GROUP_PARAMETERS")
    integers: list[int] = []
    for value in values:
        if value != value.to_integral_value():
            raise ValueError("normalized affine storage values must be integers")
        integer = int(value)
        if not minimum <= integer <= maximum:
            raise ValueError("affine storage value outside declared range")
        integers.append(integer)
    try:
        with localcontext(decimal_context()):
            reconstructed = tuple(+(scale * (value - parameters.zero_point)) for value in integers)
    except DecimalException as exc:
        raise ValueError("LIMIT_EXCEEDED:DECIMAL_INTERMEDIATE_MAGNITUDE") from exc
    return tuple(canonical_decimal(value) for value in reconstructed)


def measure_values(
    source_values: Sequence[str],
    reconstructed_values: Sequence[str],
    *,
    source_tensor_id: str,
    candidate_tensor_id: str,
    at_quantization_bound_count: int | None = None,
) -> TensorMetricSet:
    """Compute deterministic metrics while keeping zero-denominator states explicit."""
    source = decimal_values(source_values)
    reconstructed = decimal_values(reconstructed_values)
    if len(source) != len(reconstructed):
        raise ValueError("SIZE_MISMATCH")
    if not source:
        unavailable = MetricValue(state=MetricState.INSUFFICIENT_COVERAGE, value=None)
        return TensorMetricSet(
            source_tensor_id=source_tensor_id,
            candidate_tensor_id=candidate_tensor_id,
            compared_element_count=0,
            non_finite_source_count=0,
            non_finite_reconstructed_count=0,
            exact_equality_count=0,
            maximum_absolute_error=unavailable,
            mean_absolute_error=unavailable,
            mean_squared_error=unavailable,
            root_mean_squared_error=unavailable,
            source_l2_norm=MetricValue(state=MetricState.EXACT, value="0"),
            error_l2_norm=MetricValue(state=MetricState.EXACT, value="0"),
            relative_l2_error=MetricValue(
                state=MetricState.UNDEFINED_ZERO_REFERENCE_NORM, value=None
            ),
            dot_product=MetricValue(state=MetricState.EXACT, value="0"),
            cosine_similarity=MetricValue(state=MetricState.UNDEFINED_ZERO_VECTOR, value=None),
            signed_mean_error=unavailable,
            at_quantization_bound_count=at_quantization_bound_count,
            clipping_status="CLIPPING_NOT_EVALUATED",
            findings=(FindingKind.PAYLOAD_VALUES_UNAVAILABLE,),
        )
    try:
        with localcontext(decimal_context()):
            errors = tuple(
                +(candidate - expected)
                for expected, candidate in zip(source, reconstructed, strict=True)
            )
            abs_errors = tuple(abs(value) for value in errors)
            squared_errors = tuple(+(value * value) for value in errors)
            count = Decimal(len(source))
            maximum_absolute_error = max(abs_errors)
            mean_absolute_error = +(sum(abs_errors, Decimal(0)) / count)
            mean_squared_error = +(sum(squared_errors, Decimal(0)) / count)
            root_mean_squared_error = +mean_squared_error.sqrt()
            source_squared = sum((+(x * x) for x in source), Decimal(0))
            candidate_squared = sum((+(x * x) for x in reconstructed), Decimal(0))
            error_squared = sum(squared_errors, Decimal(0))
            source_l2 = +source_squared.sqrt()
            candidate_l2 = +candidate_squared.sqrt()
            error_l2 = +error_squared.sqrt()
            dot = +sum((+(a * b) for a, b in zip(source, reconstructed, strict=True)), Decimal(0))
            bias = +(sum(errors, Decimal(0)) / count)
            exact_count = sum(a == b for a, b in zip(source, reconstructed, strict=True))
            exact = exact_count == len(source)
            metric_state = MetricState.EXACT if exact else MetricState.AVAILABLE
            relative = (
                MetricValue(state=MetricState.UNDEFINED_ZERO_REFERENCE_NORM, value=None)
                if source_l2 == 0
                else MetricValue(
                    state=metric_state,
                    value=canonical_decimal(+(error_squared / source_squared).sqrt()),
                )
            )
            if source_l2 == 0 or candidate_l2 == 0:
                cosine = MetricValue(state=MetricState.UNDEFINED_ZERO_VECTOR, value=None)
            elif exact:
                cosine = MetricValue(state=MetricState.EXACT, value="1")
            else:
                cosine = MetricValue(
                    state=metric_state,
                    value=canonical_decimal(+(dot / +(source_squared * candidate_squared).sqrt())),
                )
    except DecimalException as exc:
        raise ValueError("LIMIT_EXCEEDED:DECIMAL_INTERMEDIATE_MAGNITUDE") from exc
    finding = () if exact else (FindingKind.NUMERICAL_DIFFERENCE_OBSERVED,)
    return TensorMetricSet(
        source_tensor_id=source_tensor_id,
        candidate_tensor_id=candidate_tensor_id,
        compared_element_count=len(source),
        non_finite_source_count=0,
        non_finite_reconstructed_count=0,
        exact_equality_count=exact_count,
        maximum_absolute_error=MetricValue(
            state=metric_state, value=canonical_decimal(maximum_absolute_error)
        ),
        mean_absolute_error=MetricValue(
            state=metric_state, value=canonical_decimal(mean_absolute_error)
        ),
        mean_squared_error=MetricValue(
            state=metric_state, value=canonical_decimal(mean_squared_error)
        ),
        root_mean_squared_error=MetricValue(
            state=metric_state, value=canonical_decimal(root_mean_squared_error)
        ),
        source_l2_norm=MetricValue(state=MetricState.AVAILABLE, value=canonical_decimal(source_l2)),
        error_l2_norm=MetricValue(state=metric_state, value=canonical_decimal(error_l2)),
        relative_l2_error=relative,
        dot_product=MetricValue(state=MetricState.AVAILABLE, value=canonical_decimal(dot)),
        cosine_similarity=cosine,
        signed_mean_error=MetricValue(state=metric_state, value=canonical_decimal(bias)),
        at_quantization_bound_count=at_quantization_bound_count,
        clipping_status="CLIPPING_NOT_EVALUATED",
        findings=finding,
    )
