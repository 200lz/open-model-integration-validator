"""Console formatting for structured validation findings."""

import json

from omiv.models import FindingStatus, ValidationFinding, ValidationReport


def format_finding(finding: ValidationFinding) -> str:
    line = f"{finding.status.value.upper()} {finding.rule_id} {finding.message}"
    if finding.status != FindingStatus.PASS:
        line += f"\n  evidence: {json.dumps(finding.evidence, sort_keys=True)}"
    return line


def format_report(report: ValidationReport) -> str:
    return "\n".join(format_finding(finding) for finding in report.findings)
