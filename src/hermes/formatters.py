"""
Hermes Review Sentinel - Output Formatters
Multi-formatter architecture supporting markdown, JSON, and SARIF output.
"""

import json
import re
from pathlib import Path
from typing import List, Dict, Any, Optional


class OutputFormat:
    """Supported output formats."""
    MARKDOWN = "markdown"
    JSON = "json"
    SARIF = "sarif"


class OutputConfig:
    """Configuration for output formatting."""

    def __init__(self, format: str = "markdown", detail: str = "full"):
        self.format = format
        self.detail = detail


class OutputFormatter:
    """Formats parsed diffs into various output formats."""

    def __init__(self, format_type: str = "markdown"):
        self.format_type = format_type.lower()

    def format(self, parsed: 'ParsedDiff') -> str:
        """Format the parsed diff according to the configured format."""
        if self.format_type == OutputFormat.MARKDOWN:
            return self._format_markdown(parsed)
        elif self.format_type == OutputFormat.JSON:
            return self._to_json(parsed)
        elif self.format_type == OutputFormat.SARIF:
            return self._to_sarif(parsed)
        else:
            raise ValueError(f"Unsupported format: {self.format_type}. Supported: markdown, json, sarif")

    def _format_markdown(self, parsed: 'ParsedDiff') -> str:
        """Format as markdown for PR comments and terminal display."""
        lines = []

        if parsed.is_truncated:
            lines.append(f"> ⚠️ **Diff Truncated**: {parsed.truncation_reason}\n")

        # Summary
        lines.append(f"**Summary**: {parsed.total_files} files, +{parsed.total_additions} -{parsed.total_deletions}\n")

        for hunk in parsed.files:
            if hunk.is_binary:
                lines.append(f"### {hunk.new_file or hunk.old_file} (binary)")
                lines.append("*Binary file changed*")
                continue

            file_name = hunk.new_file or hunk.old_file
            lines.append(f"### {file_name}")
            lines.append("")
            lines.append("```diff")
            lines.extend(hunk.lines)
            lines.append("```")
            lines.append("")

        return "\n".join(lines)

    def _to_json(self, parsed: 'ParsedDiff') -> str:
        """Convert to JSON format."""
        data = {
            "total_files": parsed.total_files,
            "total_additions": parsed.total_additions,
            "total_deletions": parsed.total_deletions,
            "is_truncated": parsed.is_truncated,
            "truncation_reason": parsed.truncation_reason,
            "files": [
                {
                    "file": hunk.new_file or hunk.old_file,
                    "old_file": hunk.old_file,
                    "new_file": hunk.new_file,
                    "diff_type": hunk.diff_type.value,
                    "additions": hunk.total_additions,
                    "deletions": hunk.total_deletions,
                    "lines": hunk.lines,
                    "is_binary": hunk.is_binary
                }
                for hunk in parsed.files
            ]
        }
        return json.dumps(data, indent=2)

    def _to_sarif(self, parsed: 'ParsedDiff') -> str:
        """Convert to SARIF format for GitHub Security Dashboard."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Hermes Review Sentinel",
                        "version": "2.1.0",
                        "informationUri": "https://github.com/jhoxgamer/hermes-review-sentinel",
                        "rules": []
                    }
                },
                "results": []
            }]
        }

        rule_id = 0
        rule_metadata = {}

        for hunk in parsed.files:
            if hunk.is_binary:
                continue

            for i, line in enumerate(hunk.lines):
                if line.startswith("+") and not line.startswith("+++"):
                    rule_id += 1
                    rule_id_str = "HRS{:04d}".format(rule_id)

                    if rule_id_str not in rule_metadata:
                        rule_metadata[rule_id_str] = {
                            "id": rule_id_str,
                            "name": "Added Line",
                            "shortDescription": {"text": "A new line was added"},
                            "fullDescription": {"text": "A line was added to the codebase, which may introduce security issues or changes in behavior."},
                            "defaultConfiguration": {"level": "warning"}
                        }

                    result = {
                        "ruleId": rule_id_str,
                        "level": "warning",
                        "message": {
                            "text": "Added line: " + line[1:].strip()
                        },
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {
                                    "uri": hunk.new_file or hunk.old_file
                                },
                                "region": {
                                    "startLine": hunk.new_start + i,
                                    "startColumn": 1
                                }
                            }
                        }]
                    }
                    sarif["runs"][0]["results"].append(result)

        # Add rule metadata to SARIF
        sarif["runs"][0]["tool"]["driver"]["rules"] = list(rule_metadata.values())

        return json.dumps(sarif, indent=2)


class FindingFormatter:
    """Formatter for security findings and SPP improvements."""

    def __init__(self, config: OutputConfig):
        self.config = config

    def format_findings(self, findings: List[Dict[str, Any]], format_type: str = "markdown") -> str:
        """Format security findings for output."""
        format_type = format_type.lower()

        if format_type == "markdown" or format_type == "md":
            return self._format_markdown(findings)
        elif format_type == "json":
            return self._to_json(findings)
        elif format_type == "sarif":
            return self._to_sarif(findings)
        else:
            raise ValueError("Unsupported format: {}. Supported: markdown, json, sarif".format(format_type))

    def _format_markdown(self, findings: List[Dict[str, Any]]) -> str:
        if not findings:
            return "✅ No issues found."

        # Group by severity
        by_severity = {}
        for finding in findings:
            severity = finding.get("severity", "low")
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)

        lines = ["## Security Findings\n"]

        for severity in ["critical", "high", "medium", "low", "info"]:
            if severity in by_severity:
                severity_icon = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🔵",
                    "info": "ℹ️"
                }.get(severity, "⚪")

                lines.append("### {} {} ({})".format(severity_icon, severity.capitalize(), len(by_severity[severity])))
                for finding in by_severity[severity]:
                    file_path = finding.get("file", "unknown")
                    line = finding.get("line", "?")
                    message = finding.get("message", "No message")
                    rule_id = finding.get("rule_id", "unknown")

                    lines.append("- **{}:{}** - {} (`{}`)".format(file_path, line, message, rule_id))
                lines.append("")

        return "\n".join(lines)

    def _to_json(self, findings: List[Dict]) -> str:
        return json.dumps({"findings": findings}, indent=2)

    def _to_sarif(self, findings: List[Dict]) -> str:
        """Convert findings to SARIF format."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Hermes Review Sentinel",
                        "version": "2.1.0",
                        "informationUri": "https://github.com/jhoxgamer/hermes-review-sentinel",
                        "rules": []
                    }
                },
                "results": []
            }]
        }

        rule_ids = set()
        for finding in findings:
            rule_id = finding.get("rule_id", "HRS0001")
            rule_ids.add(rule_id)

            result = {
                "ruleId": rule_id,
                "level": finding.get("level", "warning"),
                "message": {
                    "text": finding.get("message", "Finding")
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.get("file", "unknown")
                        },
                        "region": {
                            "startLine": finding.get("line", 1),
                            "startColumn": 1
                        }
                    }
                }]
            }
            sarif["runs"][0]["results"].append(result)

        # Add rule metadata to SARIF
        rules = []
        for rid in sorted(rule_ids):
            rules.append({
                "id": rid,
                "name": rid,
                "shortDescription": {"text": "Security finding"},
                "defaultConfiguration": {"level": "warning"}
            })
        sarif["runs"][0]["tool"]["driver"]["rules"] = rules

        return json.dumps(sarif, indent=2)