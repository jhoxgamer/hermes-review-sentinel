"""
Tests for hermes-review-sentinel
"""

import pytest
import asyncio
import tempfile
import os
from pathlib import Path

# Add src to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from sentinel_server import (
    Finding,
    run_semgrep_analysis,
    _evaluate_intent_alignment,
    _calculate_risk_contextual,
    _generate_actionable_fixes,
    _extract_files_from_diff,
)


class TestIntentAlignment:
    def test_short_description_warning(self):
        findings = _evaluate_intent_alignment("some diff", "short")
        assert len(findings) == 1
        assert findings[0]["type"] == "documentation"
        assert findings[0]["severity"] == "low"

    def test_empty_description_warning(self):
        findings = _evaluate_intent_alignment("some diff", "")
        assert len(findings) == 1
        assert findings[0]["type"] == "documentation"

    def test_no_description_warning(self):
        findings = _evaluate_intent_alignment("some diff", None)
        assert len(findings) == 1


class TestRiskCalculation:
    def test_base_risk(self):
        risk = _calculate_risk_contextual([], 10, {})
        assert risk == 0.1  # base risk

    def test_high_severity_increases_risk(self):
        findings = [{"severity": "high", "type": "security"}]
        risk = _calculate_risk_contextual(findings, 10, {})
        assert risk > 0.1

    def test_warning_increases_risk(self):
        findings = [{"severity": "medium", "type": "security"}]
        risk = _calculate_risk_contextual(findings, 10, {})
        assert risk > 0.1

    def test_large_pr_increases_risk(self):
        findings = []
        risk = _calculate_risk_contextual(findings, 500, {"max_lines_changed": 100})
        assert risk > 0.1

    def test_max_cap_at_1(self):
        findings = [{"severity": "high"} for _ in range(10)]
        risk = _calculate_risk_contextual(findings, 500, {})
        assert risk <= 1.0

    def test_auth_files_increase_risk(self):
        findings = [{"severity": "low", "file": "auth/login.py"}]
        risk = _calculate_risk_contextual(findings, 10, {})
        # Auth files multiply risk by 1.3
        assert risk > 0.1 * 1.3


class TestFixGeneration:
    def test_secret_fix(self):
        findings = [{"type": "secret", "message": "hardcoded secret", "rule_id": "secret"}]
        fixes = _generate_actionable_fixes(findings)
        assert len(fixes) > 0
        assert fixes[0]["action"] == "extract_to_env_var"

    def test_sql_injection_fix(self):
        findings = [{"type": "sql-injection", "message": "sql injection", "rule_id": "sql-injection"}]
        fixes = _generate_actionable_fixes(findings)
        assert len(fixes) > 0
        assert fixes[0]["action"] == "use_parameterized_query"

    def test_n_plus_one_fix(self):
        findings = [{"type": "n-plus-one", "message": "n+1 query", "rule_id": "n-plus-one"}]
        fixes = _generate_actionable_fixes(findings)
        assert len(fixes) > 0
        assert fixes[0]["action"] == "use_joinedload_or_bulk_fetch"

    def test_deduplication(self):
        findings = [
            {"type": "secret", "message": "secret 1", "rule_id": "secret"},
            {"type": "secret", "message": "secret 2", "rule_id": "secret"},
        ]
        fixes = _generate_actionable_fixes(findings)
        # Should deduplicate by action
        actions = [f["action"] for f in fixes]
        assert len(actions) == len(set(actions))


class TestModels:
    def test_finding_model(self):
        f = Finding(
            type="security",
            severity="high",
            message="Test",
            file="test.py",
            line=10,
            rule_id="test.rule"
        )
        assert f.type == "security"
        assert f.severity == "high"


class TestDiffParsing:
    def test_extract_files_from_diff(self):
        diff = """diff --git a/src/main.py b/src/main.py
--- a/src/main.py
+++ b/src/main.py
@@ -1,3 +1,4 @@
+import os
 def main():
     pass
diff --git a/tests/test_main.py b/tests/test_main.py
--- a/tests/test_main.py
+++ b/tests/test_main.py
@@ -1,2 +1,3 @@
+import pytest
 def test_main():
     pass
"""
        files = _extract_files_from_diff(diff)
        assert "src/main.py" in files
        assert "tests/test_main.py" in files
        assert len(files) == 2

    def test_extract_files_empty_diff(self):
        files = _extract_files_from_diff("")
        assert files == []


class TestSemgrepIntegration:
    @pytest.mark.skipif(
        not (os.path.exists("/usr/bin/semgrep") or os.path.exists("/usr/local/bin/semgrep") or 
             os.path.exists("C:/Users/Jhonatan/AppData/Local/hermes/hermes-agent/venv/Scripts/semgrep.exe")),
        reason="Semgrep not installed"
    )
    def test_semgrep_analysis_python(self):
        diff = """
diff --git a/test_secret.py b/test_secret.py
--- a/test_secret.py
+++ b/test_secret.py
@@ -1,2 +1,3 @@
+API_KEY = os.getenv("API_KEY", "CHANGE_ME_IN_PRODUCTION")
 def hello():
     pass
"""
        # This is an integration test - just verify it doesn't crash
        # We're not testing semgrep itself, just our wrapper
        findings = asyncio.run(run_semgrep_analysis(diff, ""))
        # Should return a list (may be empty if no rules match)
        assert isinstance(findings, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])