"""Deterministic safe rendering for Phase 6D records."""

from __future__ import annotations

import json
from typing import Any

from omiv.tokenizer_parity.models import TokenizerConfigurationReport
from omiv.tokenizer_parity.observation import escape_untrusted_text


def pretty_json(value: Any) -> str:
    raw = value.model_dump(mode="json", by_alias=True) if hasattr(value, "model_dump") else value
    return json.dumps(raw, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True) + "\n"


def render_markdown(report: TokenizerConfigurationReport) -> str:
    lines = [
        f"# {escape_untrusted_text(report.title)}",
        "",
        f"- Status: `{report.overall_status.value}`",
        f"- Findings: {report.included_findings}/{report.total_findings}",
        f"- Truncation: `{report.truncation_status}`",
        "",
        "## Findings",
        "",
    ]
    for finding in report.findings:
        lines.append(
            f"- `{finding.code}` `{finding.status.value}`: {escape_untrusted_text(finding.detail)}"
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {escape_untrusted_text(item)}" for item in report.limitations)
    return "\n".join(lines) + "\n"
