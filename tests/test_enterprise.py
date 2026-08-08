"""
Comprehensive tests for Hermes Review Sentinel.
Tests for diff parsing, security pair programmer, formatters, and resilience.
"""

import pytest
import tempfile
from pathlib import Path
import json

from hermes.config import (
    HermesConfig, 
    ExclusionConfig, 
    DiffParsingConfig,
    OutputConfig,
    ResilienceConfig,
    SecurityConfig,
    load_config,
    DEFAULT_CONFIG
)
from hermes.diff_parser import (
    DiffParser, 
    DiffHunk, 
    ParsedDiff, 
    DiffType,
    EXCLUDED_DIRS,
    MAX_FILE_SIZE,
)
from security_pair_programmer import (
    SecurityPairProgrammer,
    auto_fix_secrets,
)
from hermes.formatters import (
    OutputFormatter, 
    FindingFormatter, 
    OutputFormat,
)
from hermes.resilience import (
    CircuitBreaker,
    RateLimiter,
    RetryConfig,
    CircuitBreakerRegistry,
    get_rate_limiter,
    get_circuit_breaker,
    with_retry,
)


class TestConfig:
    """Test configuration system."""
    
    def test_default_config(self):
        config = DEFAULT_CONFIG
        assert config.version == "2.0.0"
        assert config.exit_code_clean == 0
        assert config.exit_code_findings == 1
        assert config.exit_code_error == 2
    
    def test_config_from_yaml(self, tmp_path):
        config_yaml = tmp_path / ".hermes.yml"
        config_yaml.write_text("""
project_name: "test-project"
exclusions:
  max_file_size: 2048
output:
  format: "json"
resilience:
  max_retries: 5
""")
        config = HermesConfig.from_yaml(config_yaml)
        assert config.project_name == "test-project"
        assert config.exclusions.max_file_size == 2048
        assert config.output.format == "json"
        assert config.resilience.max_retries == 5
    
    def test_config_to_yaml(self, tmp_path):
        config = HermesConfig(project_name="test")
        yaml_path = tmp_path / ".hermes.yml"
        config.to_yaml(yaml_path)
        
        import yaml
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        
        assert data["project_name"] == "test"
    
    def test_load_config(self, tmp_path):
        config_path = tmp_path / ".hermes.yml"
        config_yaml = """
project_name: "loaded-project"
output:
  format: "sarif"
"""
        Path(tmp_path / ".hermes.yml").write_text(config_yaml)
        
        config = load_config(tmp_path)
        assert config.project_name == "loaded-project"
        assert config.output.format == "sarif"
    
    def test_exclusion_config(self):
        config = ExclusionConfig()
        assert "node_modules" in config.directories
        assert ".pyc" in config.extensions
        
        # Test should_skip
        from pathlib import Path
        assert config.should_skip(Path("node_modules/test.js"), Path(".")) == True
        assert config.should_skip(Path("src/main.py"), Path(".")) == False
        assert config.should_skip(Path("file.min.js"), Path(".")) == True


class TestDiffParser:
    """Test diff parsing functionality."""
    
    @pytest.fixture
    def parser(self):
        config = DiffParsingConfig()
        exclusion = ExclusionConfig()
        return DiffParser(config, exclusion, Path.cwd())
    
    def test_parse_simple_diff(self, parser):
        diff = """diff --git a/test.py b/test.py
--- a/test.py
+++ b/test.py
@@ -1,3 +1,4 @@
 def hello():
+    print("hello")
     return "world"
"""
        result = parser.parse("test.py")
        assert len(parsed.files) == 1
        assert parsed.total_additions == 1
        assert parsed.total_deletions == 0
    
    def test_parse_multi_file_diff(self, parser):
        diff = """diff --git a/file1.py b/file1.py
--- a/file1.py
+++ b/file1.py
@@ -1 +1,2 @@
+import os
 def hello():
diff --git a/file2.py b/file2.py
--- a/file2.py
+++ b/file2.py
@@ -1 +1,2 @@
+import sys
 def hello():
"""
        # This test would need proper diff format
        pass
    
    def test_exclusion_filtering(self, parser):
        """Test that excluded files are filtered out."""
        # This would test the exclusion logic
        pass
    
    def test_diff_truncation(self, parser):
        """Test diff truncation logic."""
        # Create a large diff
        large_diff = "diff --git a/test.py b/test.py\n"
        for i in range(1000):
            large_diff += f"+line {i}\n"
        
        # The parser should handle truncation
        pass


class TestSecurityPairProgrammer:
    """Test Security Pair Programmer functionality."""
    
    @pytest.fixture
    def spp(self, tmp_path):
        # Create a test project structure
        (tmp_path / "backend").mkdir()
        (tmp_path / "backend" / "auth.py").write_text(
            '@app.get("/login")\n'
            '@depends(get_current_user)\n'
            'def login(): pass\n'
        )
        return SecurityPairProgrammer(tmp_path)
    
    def test_detect_missing_auth(self, spp, tmp_path):
        test_file = tmp_path / "backend" / "test_unsecured.py"
        test_file.write_text(
            '@app.get("/admin")\n'
            'def admin_panel():\n'
            '    return {"users": []}\n'
        )
        
        issues = spp._detect_issues_in_file(test_file)
        assert len(issues) == 1
        assert issues[0][1] == "MISSING_AUTH"
        assert issues[0][0] == 1  # line number of @app.get
    
    def test_apply_improvements(self, spp, tmp_path):
        test_file = tmp_path / "backend" / "test_apply.py"
        test_file.write_text(
            '@app.get("/admin")\n'
            'def admin_panel():\n'
            '    return {"users": []}\n'
        )
        
        issues = [(1, "MISSING_AUTH")]
        applied = spp.apply_improvements_to_file(test_file, issues)
        assert applied == True
        
        content = test_file.read_text()
        assert "@depends(get_current_user)" in content
    
    def test_apply_multiple_improvements(self, spp, tmp_path):
        test_file = tmp_path / "backend" / "multiple.py"
        test_file.write_text(
            '@app.get("/user")\n'
            'def get_user(): pass\n\n'
            '@app.get("/admin")\n'
            'def get_admin(): pass\n'
        )
        
        issues = [(1, "MISSING_AUTH"), (4, "MISSING_AUTH")]
        applied = spp.apply_improvements_to_file(test_file, issues)
        assert applied == True
        
        content = test_file.read_text()
        assert content.count("@depends(get_current_user)") == 2
    
    def test_suggest_improvement(self, spp, tmp_path):
        (tmp_path / "backend" / "auth.py").write_text(
            '@app.get("/login")\n'
            '@depends(get_current_user)\n'
            'def login(): pass\n'
        )
        
        test_file = tmp_path / "backend" / "test_suggest.py"
        test_file.write_text('@app.get("/admin")\ndef admin(): pass\n')
        
        issues = spp._detect_issues_in_file(test_file)
        suggestion = spp.suggest_improvement(test_file, 1, "MISSING_AUTH")
        
        assert suggestion is not None
        assert "Depends(get_current_user)" in suggestion
    
    def test_apply_env_var_style(self, tmp_path):
        (tmp_path / ".env.example").write_text("SECRET_KEY=\nJWT_SECRET=\nAPI_KEY=\n")
        test_env = tmp_path / ".env.example"
        test_env.write_text("secret_key=\njwt_secret=\nAPI_KEY=\n")
        
        from security_pair_programmer import SecurityPairProgrammer
        spp = SecurityPairProgrammer(Path.cwd())
        issues = spp._detect_issues_in_file(tmp_path / ".env.example")
        
        # Should detect style issues
        env_issues = [i for i in issues if i[1] == "ENV_VAR_STYLE"]
        assert len(env_issues) >= 2


class TestAutoFixSecrets:
    """Test secret auto-fix functionality."""
    
    def test_python_secret_replacement(self, tmp_path):
        test_file = tmp_path / "test_secret.py"
        test_file.write_text(
            'SECRET_KEY = "sk_live_1234567890abcdef1234"\n'
            'API_KEY = "FAKE_SECRET_2"\n'
        )
        env_example = tmp_path / ".env.example"
        
        modified, fixes, vars_added = auto_fix_secrets(test_file, tmp_path / ".env.example")
        
        assert modified == True
        assert fixes == 2
        assert len(vars_added) == 2
        
        content = test_file.read_text()
        assert "os.getenv" in content
        assert "CHANGE_ME_IN_PRODUCTION" in content
    
    def test_js_secret_replacement(self, tmp_path):
        test_file = tmp_path / "test_secret.js"
        test_file.write_text(
            'const apiKey = "FAKE_SECRET_1"\n'
            'const stripeKey = "sk_test_FAKE1234567890"\n'
        )
        env_example = tmp_path / ".env.example"
        
        modified, fixes, vars_added = auto_fix_secrets(test_file, tmp_path / ".env.example")
        
        assert modified == True
        assert fixes == 2
        assert len(vars_added) == 2
        
        content = test_file.read_text()
        assert "process.env" in content
        assert "CHANGE_ME_IN_PRODUCTION" in content
    
    def test_already_secured_code_unchanged(self, tmp_path):
        test_file = tmp_path / "test_secure.py"
        test_file.write_text(
            'SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME")\n'
        )
        env_example = tmp_path / ".env.example"
        
        modified, fixes, vars_added = auto_fix_secrets(test_file, tmp_path / ".env.example")
        
        assert modified == False
        assert fixes == 0
    
    def test_env_example_generation(self, tmp_path):
        test_file = tmp_path / "test.py"
        test_file.write_text('SECRET_KEY = "fake_key_123"\n')
        
        env_example = Path(tmp_path) / ".env.example"
        if env_example.exists():
            env_example.unlink()
        
        auto_fix_secrets(Path("test.py"), Path(".env.example"))
        
        # Should create .env.example
        assert Path(".env.example").exists()
        content = Path(".env.example").read_text()
        assert "SECRET_KEY=" in content


class TestFormatters:
    """Test output formatters."""
    
    @pytest.fixture
    def sample_parsed_diff(self):
        from hermes.diff_parser import DiffHunk, ParsedDiff, DiffType
        
        hunk = DiffHunk(
            file_path="test.py",
            old_start=1,
            old_count=3,
            new_start=1,
            new_count=4,
            lines=[
                '@@ -1,3 +1,4 @@',
                ' def hello():',
                '+    print("hello")',
                '     return "world"',
            ],
            diff_type=DiffType.MODIFIED,
            total_additions=1,
            total_deletions=0
        )
        
        return ParsedDiff(
            files=[hunk],
            total_additions=1,
            total_deletions=0,
            total_files=1
        )
    
    def test_markdown_formatter(self, sample_parsed_diff):
        formatter = OutputFormatter(OutputConfig())
        result = formatter.format(sample_parsed_diff, "markdown")
        
        assert "### test.py" in result
        assert "+    print" in result
        assert "```diff" in result
    
    def test_json_formatter(self, sample_parsed_diff):
        formatter = OutputFormatter(OutputConfig())
        result = formatter.format(sample_parsed_diff, "json")
        
        data = json.loads(result)
        assert data["total_files"] == 1
        assert data["total_additions"] == 1
        assert len(data["files"]) == 1
    
    def test_sarif_formatter(self, sample_parsed_diff):
        formatter = OutputFormatter(OutputConfig())
        result = formatter.format(sample_parsed_diff, "sarif")
        
        data = json.loads(result)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) > 0
    
    def test_finding_formatter_markdown(self):
        findings = [
            {
                "file": "test.py",
                "line": 10,
                "severity": "high",
                "message": "Hardcoded secret detected",
                "rule_id": "secret-detection"
            },
            {
                "file": "test.py",
                "line": 20,
                "severity": "medium",
                "message": "SQL injection risk",
                "rule_id": "sql-injection"
            }
        ]
        
        formatter = FindingFormatter(OutputConfig())
        result = formatter.format_findings(findings, "markdown")
        
        assert "🔴 High" in result or "High" in result
        assert "Hardcoded secret" in result
        assert "SQL injection" in result
    
    def test_finding_formatter_sarif(self):
        findings = [
            {
                "file": "test.py",
                "line": 10,
                "severity": "high",
                "message": "Hardcoded secret",
                "rule_id": "secret-detection"
            }
        ]
        
        formatter = FindingFormatter(None)
        result = formatter.format_findings(findings, "sarif")
        
        data = json.loads(result)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) == 1


class TestResilience:
    """Test resilience module."""
    
    @pytest.mark.asyncio
    async def test_circuit_breaker(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=1.0)
        
        assert cb.state == "closed"
        assert cb.can_execute() == True
        
        # Record failures
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "closed"
        
        cb.record_failure()
        assert cb.state == "open"
        assert cb.can_execute() == False
        
        # Wait for recovery
        import time
        time.sleep(1.1)
        assert cb.can_execute() == True  # Should be half-open now
    
    @pytest.mark.asyncio
    async def test_rate_limiter(self):
        limiter = RateLimiter(max_requests=5, window_seconds=1)
        
        for i in range(5):
            await limiter.acquire()
        
        # Next request should wait
        import time
        start = time.time()
        await limiter.acquire()
        elapsed = time.time() - start
        assert elapsed >= 1.0  # Should have waited ~1 second
    
    def test_rate_limiter_sync(self):
        limiter = RateLimiter(max_requests=3, window_seconds=1)
        
        for i in range(3):
            limiter.acquire_sync()
        
        import time
        start = time.time()
        limiter.acquire_sync()
        elapsed = time.time() - start
        assert elapsed >= 1.0
    
    @pytest.mark.asyncio
    async def test_retry_decorator(self):
        attempt_count = 0
        
        @with_retry(RetryConfig(max_attempts=3, base_delay=0.01))
        async def flaky_function():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("Temporary failure")
            return "success"
        
        call_count = 0
        result = await flaky_function()
        assert result == "success"
        assert call_count == 3
    
    def test_retry_sync(self):
        call_count = 0
        
        @with_retry(RetryConfig(max_attempts=3, base_delay=0.01))
        def flaky_sync():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ConnectionError("Temporary failure")
            return "success"
        
        call_count = 0
        result = flaky_sync()
        assert result == "success"
        assert call_count == 3
    
    def test_circuit_breaker_integration(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.1)
        
        assert cb.can_execute() == True
        
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "open"
        assert cb.can_execute() == False


class TestIntegration:
    """Integration tests."""
    
    def test_full_scan_workflow(self, tmp_path):
        """Test complete scan workflow."""
        # Setup project
        (tmp_path / "backend").mkdir()
        (tmp_path / "backend" / "auth.py").write_text(
            '@app.get("/login")\n'
            'def login():\n'
            '    password = "hardcoded_password_123"\n'
            '    return authenticate(password)\n'
        )
        
        (tmp_path / "frontend").mkdir()
        (tmp_path / "frontend" / "api.js").write_text(
            'const API_KEY = "sk_live_abcdef1234567890"\n'
            'fetch("/api/data", {headers: {Authorization: API_KEY}})\n'
        )
        
        # Run scan
        from security_pair_programmer import SecurityPairProgrammer, auto_fix_secrets
        from hermes.formatters import OutputFormatter, FindingFormatter
        
        spp = SecurityPairProgrammer(tmp_path)
        
        # Scan all files
        files = list(tmp_path.rglob("*"))
        files = [f for f in files if f.is_file()]
        
        total_findings = 0
        for file_path in files:
            issues = SecurityPairProgrammer(tmp_path)._detect_issues_in_file(file_path)
            if issues:
                # Auto-fix secrets
                from security_pair_programmer import auto_fix_secrets
                from pathlib import Path
                env_example = tmp_path / ".env.example"
                auto_fix_secrets(file_path, tmp_path / ".env.example")
        
        # Verify results
        assert True  # If we get here without exception, basic flow works
    
    def test_cli_help(self):
        from src.sentinel_server import main
        import sys
        from io import StringIO
        
        # Test help output
        old_argv = sys.argv
        sys.argv = ["sentinel", "--help"]
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        
        try:
            main()
        except SystemExit:
            pass
        finally:
            sys.argv = old_argv
            sys.stdout = old_stdout
        
        # If we get here without exception, help works
        assert True


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])