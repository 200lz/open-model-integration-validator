"""Deterministic raster fixtures for reference-runtime acceptance probes."""

from __future__ import annotations

import struct
import zlib

PNG_HEIGHT = 64
PNG_WIDTH = 64
RED_SQUARE_END = 48
RED_SQUARE_START = 16


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    payload = kind + data
    return struct.pack(">I", len(data)) + payload + struct.pack(">I", zlib.crc32(payload))


def _uncompressed_zlib_stream(data: bytes) -> bytes:
    """Return a fixed zlib stream containing one uncompressed DEFLATE block."""
    if len(data) > 0xFFFF:
        raise ValueError("probe payload exceeds one deterministic DEFLATE block")
    length = len(data)
    return (
        b"\x78\x01"
        + b"\x01"
        + struct.pack("<H", length)
        + struct.pack("<H", 0xFFFF - length)
        + data
        + struct.pack(">I", zlib.adler32(data))
    )


def build_red_square_png() -> bytes:
    """Build a fixed 64x64 indexed PNG with one red square on white."""
    rows = bytearray()
    for y in range(PNG_HEIGHT):
        rows.append(0)  # PNG filter: None
        for x in range(PNG_WIDTH):
            inside_square = (
                RED_SQUARE_START <= x < RED_SQUARE_END
                and RED_SQUARE_START <= y < RED_SQUARE_END
            )
            rows.append(1 if inside_square else 0)

    header = struct.pack(">IIBBBBB", PNG_WIDTH, PNG_HEIGHT, 8, 3, 0, 0, 0)
    palette = bytes((255, 255, 255, 212, 0, 0))
    return b"".join(
        (
            b"\x89PNG\r\n\x1a\n",
            _png_chunk(b"IHDR", header),
            _png_chunk(b"PLTE", palette),
            _png_chunk(b"IDAT", _uncompressed_zlib_stream(bytes(rows))),
            _png_chunk(b"IEND", b""),
        )
    )
