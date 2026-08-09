"""Deterministic bounded Phase 6E rendering."""

from __future__ import annotations

import json
import unicodedata

from pydantic import BaseModel

from omiv.runtime_resolution.models import RuntimeResolutionReport


def pretty_json(value: BaseModel) -> str:
    return (
        json.dumps(
            value.model_dump(mode="json", by_alias=True),
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    )


def safe_text(value: str) -> str:
    result: list[str] = []
    for char in value:
        code = ord(char)
        if (
            code < 32
            or 0x7F <= code <= 0x9F
            or code in {0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2060}
            or 0x202A <= code <= 0x202E
            or 0x2066 <= code <= 0x2069
            or unicodedata.category(char) == "Cf"
        ):
            result.append(f"\\u{code:04x}")
        elif char in "`*_[]<>#|":
            result.append("\\" + char)
        else:
            result.append(char)
    return "".join(result)


def render_markdown(report: RuntimeResolutionReport) -> str:
    lines = [
        f"# {safe_text(report.title)}",
        "",
        f"- Evidence: `{report.evidence.object_id}`",
        f"- Status: `{report.status.value}`",
        f"- Scope: `{report.scope}`",
        f"- Findings: {report.included_findings}/{report.total_findings}",
        f"- Truncation: `{report.truncation_status}`",
        "",
        "## Findings",
        "",
    ]
    lines.extend(f"- {safe_text(finding)}" for finding in report.findings)
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {safe_text(value)}" for value in report.limitations)
    return "\n".join(lines) + "\n"
