"""Centralized defensive limits for local HF checkpoint parsing."""

from typing import Final

MAX_CONFIG_BYTES: Final = 1 * 1024 * 1024
MAX_INDEX_BYTES: Final = 16 * 1024 * 1024
MAX_PROVENANCE_BYTES: Final = 64 * 1024
MAX_SAFETENSORS_HEADER_BYTES: Final = 64 * 1024 * 1024
MAX_TENSOR_COUNT: Final = 1_000_000
MAX_SHARD_COUNT: Final = 10_000
MAX_TENSOR_NAME_LENGTH: Final = 4_096
MAX_TENSOR_RANK: Final = 16
MAX_DIMENSION_VALUE: Final = 1 << 40
MAX_ELEMENT_COUNT: Final = (1 << 63) - 1
MAX_JSON_NESTING: Final = 128
