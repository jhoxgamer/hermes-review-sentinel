"""
Hermes Review Sentinel - Diff Parser Module
Intelligent git diff parsing with smart filtering and truncation.
"""

import re
import fnmatch
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
from enum import Enum
import textwrap


class DiffType(Enum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"
    COPIED = "copied"


@dataclass
class DiffHunk:
    file_path: str
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: List[str]
    diff_type: DiffType = DiffType.MODIFIED
    total_additions: int = 0
    total_deletions: int = 0
    old_file: Optional[str] = None
    new_file: Optional[str] = None
    is_binary: bool = False


@dataclass
class ParsedDiff:
    files: List[DiffHunk] = field(default_factory=list)
    total_additions: int = 0
    total_deletions: int = 0
    total_files: int = 0

    def to_json(self) -> str:
        return json.dumps({
            "total_files": self.total_files,
            "total_additions": self.total_additions,
            "total_deletions": self.total_deletions,
            "files": [
                {
                    "file_path": hunk.file_path,
                    "old_start": hunk.old_start,
                    "old_count": hunk.old_count,
                    "new_start": hunk.new_start,
                    "new_count": hunk.new_count,
                    "diff_type": hunk.diff_type.value,
                    "additions": hunk.total_additions,
                    "deletions": hunk.total_deletions,
                    "lines": hunk.lines,
                    "is_binary": hunk.is_binary,
                    "old_file": hunk.old_file,
                    "new_file": hunk.new_file,
                }
                for hunk in self.files
            ]
        }, indent=2)

    def _to_sarif(self, parsed: 'ParsedDiff') -> str:
        """Convert to SARIF format for GitHub Security Dashboard."""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Hermes Review Sentinel",
                        "version": "2.0.0",
                        "informationUri": "https://github.com/jhoxgamer/hermes-review-sentinel",
                        "rules": []
                    }
                },
                "results": []
            }]
        }

        rule_id = 0
        rule_metadata = {}  # Track rule metadata for SARIF
        
        for hunk in parsed.files:
            if hunk.is_binary:
                continue
            
            for i, line in enumerate(hunk.lines):
                if line.startswith("+") and not line.startswith("+++"):
                    rule_id += 1
                    rule_id_str = f"HRS{rule_id:04d}"
                    
                    # Track rule metadata for SARIF
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
        
        import json
        return json.dumps(sarif, indent=2)


class ExclusionConfig:
    def __init__(self):
        self.directories = {
            "venv", ".venv", "node_modules", ".next", "__pycache__", ".git",
            "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "coverage",
        }
        self.extensions = {
            ".pyc", ".pyo", ".pyd", ".so", ".dll", ".exe", ".bin", ".dat",
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
            ".ttf", ".eot", ".map", ".min.js", ".min.css",
        }
        self.patterns = {
            "*.min.js", "*.min.css", "*.bundle.js", "*.bundle.css",
            "*.generated.*", "*.auto.*", "*.d.ts", "*.map", "*.lock",
            "*.pb.go", "*.pb.cc", "*.pb.h",
        }
        self.max_file_size = 1_024 * 1_024  # 1MB

    def should_skip(self, path: Path, project_root: Path) -> bool:
        try:
            rel_parts = path.relative_to(self.project_root).parts
        except ValueError:
            return True
        
        if any(part in self.directories for part in rel_parts):
            return True
        
        if path.suffix in self.extensions:
            return True
        
        for pattern in self.patterns:
            if fnmatch.fnmatch(path.name, pattern):
                return True
        
        try:
            if path.stat().st_size > self.max_file_size:
                return True
        except (OSError, PermissionError):
            return True
        
        return False


class DiffParsingConfig:
    def __init__(self):
        self.ignore_lockfiles = True
        self.ignore_minified = True
        self.ignore_assets = True
        self.ignore_generated = True
        self.max_diff_size = 50000
        self.truncation_strategy = "smart"
        self.context_lines = 3


class ExclusionConfig:
    """Configuration for file exclusion patterns."""
    
    def __init__(self):
        self.directories = {
            "venv", ".venv", "node_modules", ".next", "__pycache__", ".git",
            "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "coverage",
        }
        self.extensions = {
            ".pyc", ".pyo", ".pyd", ".so", ".dll", ".exe", ".bin", ".dat",
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
            ".ttf", ".eot", ".map", ".min.js", ".min.css",
        }
        self.patterns = {
            "*.min.js", "*.min.css", "*.bundle.js", "*.bundle.css",
            "*.generated.*", "*.auto.*", "*.d.ts", "*.map", "*.lock",
            "*.pb.go", "*.pb.cc", "*.pb.h",
        }
        self.max_file_size = 1_024 * 1_024  # 1MB

    def should_skip(self, path: Path, project_root: Path) -> bool:
        try:
            rel_parts = path.relative_to(project_root).parts
        except ValueError:
            return True
        
        if any(part in self.directories for part in rel_parts):
            return True
        
        if path.suffix in self.extensions:
            return True
        
        for pattern in self.patterns:
            if fnmatch.fnmatch(path.name, pattern):
                return True
        
        try:
            if path.stat().st_size > self.max_file_size:
                return True
        except (OSError, PermissionError):
            return True
        
        return False


# Module-level constants
EXCLUDED_DIRS = {
    "venv", ".venv", "node_modules", ".next", "__pycache__", ".git",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "coverage",
}

MAX_FILE_SIZE = 1_024 * 1_024  # 1 MB

NEXTJS_SERVER_DIRS = {
    "app/api", "pages/api", "actions", "server-actions", "lib/actions",
}

STRIPE_LIVE_PREFIX = "sk_live_"
STRIPE_TEST_PREFIX = "sk_test_"


# Patterns for secret detection
SECRET_PATTERNS = [
    (re.compile(r'(?i)(?<![\'"#])(secret_key|jwt_secret|api_key|password|token)\s*=\s*["\']([^"\']{1,})["\']'), "GENERIC_SECRET_PY"),
    (re.compile(r'(?i)(?<![\'"#])(?:const|let|var)\s+(secretKey|jwtSecret|apiKey|password|token)\s*=\s*["\']([^"\']{1,})["\']'), "GENERIC_SECRET_JS"),
    (re.compile(r'sk_live_[0-9a-zA-Z\.]{10,}'), "STRIPE_LIVE_KEY"),
    (re.compile(r'sk_test_[0-9a-zA-Z\.]{10,}'), "STRIPE_TEST_KEY"),
    (re.compile(r'ghp_[0-9a-zA-Z]{36}'), "GITHUB_PERSONAL_TOKEN"),
    (re.compile(r'gho_[0-9a-zA-Z]{36}'), "GITHUB_OAUTH_TOKEN"),
    (re.compile(r'ghu_[0-9a-zA-Z]{36}'), "GITHUB_USER_TOKEN"),
    (re.compile(r'ghs_[0-9a-zA-Z]{36}'), "GITHUB_SERVER_TOKEN"),
    (re.compile(r'ghr_[0-9a-zA-Z]{36}'), "GITHUB_REFRESH_TOKEN"),
    (re.compile(r'ai_[0-9a-zA-Z]{32,}'), "OPENAI_API_KEY"),
    (re.compile(r'xoxb-[0-9a-zA-Z-]{50,}'), "SLACK_BOT_TOKEN"),
    (re.compile(r'xoxp-[0-9a-zA-Z-]{50,}'), "SLACK_USER_TOKEN"),
    (re.compile(r'xoxa-[0-9a-zA-Z-]{50,}'), "SLACK_APP_TOKEN"),
]

PYTHON_PATTERN_TYPES = [
    "STRIPE_LIVE_KEY", "STRIPE_TEST_KEY",
    "GITHUB_PERSONAL_TOKEN", "GITHUB_OAUTH_TOKEN", "GITHUB_USER_TOKEN",
    "GITHUB_SERVER_TOKEN", "GITHUB_REFRESH_TOKEN", "OPENAI_API_KEY",
    "SLACK_BOT_TOKEN", "SLACK_USER_TOKEN", "SLACK_APP_TOKEN",
    "GENERIC_SECRET_PY"
]

JS_PATTERN_TYPES = [
    "STRIPE_LIVE_KEY", "STRIPE_TEST_KEY",
    "GITHUB_PERSONAL_TOKEN", "GITHUB_OAUTH_TOKEN", "GITHUB_USER_TOKEN",
    "GITHUB_SERVER_TOKEN", "GITHUB_REFRESH_TOKEN", "OPENAI_API_KEY",
    "SLACK_BOT_TOKEN", "SLACK_USER_TOKEN", "SLACK_APP_TOKEN",
    "GENERIC_SECRET_JS"
]


class DiffParser:
    def __init__(self, project_root: Path, config: DiffParsingConfig = None, exclusion: ExclusionConfig = None):
        self.project_root = project_root.resolve()
        self.config = config or DiffParsingConfig()
        self.exclusion = exclusion or ExclusionConfig()
        self.exclusion.project_root = self.project_root

    def _should_skip_path(self, path: Path) -> bool:
        try:
            rel_parts = path.relative_to(self.project_root).parts
        except ValueError:
            return True
        
        if any(part in EXCLUDED_DIRS for part in path.parts):
            return True
        
        if path.suffix in EXCLUDED_EXTENSIONS:
            return True
        
        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                return True
        except (OSError, PermissionError):
            return True
        
        return False

    def _is_nextjs_server_file(self, path: Path) -> bool:
        try:
            rel_path = path.relative_to(self.project_root)
        except ValueError:
            return False
        
        rel_str = str(rel_path).replace("\\", "/")
        for server_dir in NEXTJS_SERVER_DIRS:
            if rel_str.startswith(server_dir + "/") or rel_str == server_dir:
                return True
        
        if path.suffix in {".js", ".ts", ".jsx", ".tsx"}:
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                if '"use server"' in content or "'use server'" in content:
                    return True
            except Exception:
                pass
        return False

    def _find_decorator_line(self, lines: List[str], func_line_idx: int) -> int:
        for i in range(func_line_idx - 1, max(-1, func_line_idx - 5), -1):
            if i < 0:
                break
            prev_line = lines[i].strip()
            if "@app." in prev_line or "@router." in prev_line:
                return i
            if prev_line and not prev_line.startswith("@") and not prev_line.startswith("#"):
                break
        return -1

    def _detect_issues_in_file(self, file_path: Path) -> List[Tuple[int, str]]:
        issues = []
        if self._should_skip_path(file_path):
            return issues

        try:
            content = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            return issues

        lines = content.splitlines()

        if file_path.suffix == ".py":
            try:
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        if node.lineno < 1 or node.lineno > len(lines):
                            continue
                        
                        func_line_idx = node.lineno - 1
                        line_text = lines[func_line_idx]

                        has_depends = any(
                            "depend" in ast.unparse(deco).lower()
                            for deco in node.decorator_list
                        )
                        has_auth = any(
                            kw in line_text.lower()
                            for kw in ("@auth", "@login_required", "@permission")
                        )

                        has_route_decorator = (
                            "@app." in line_text or "@router." in line_text
                        )
                        deco_line_idx = func_line_idx

                        if not has_route_decorator:
                            deco_line_idx = self._find_decorator_line(lines, func_line_idx)
                            if deco_line_idx >= 0:
                                has_route_decorator = True

                        if has_route_decorator and not has_depends and not has_auth:
                            issues.append((deco_line_idx + 1, "MISSING_AUTH"))

            except Exception:
                pass

        elif file_path.suffix in {".js", ".ts", ".jsx", ".tsx"} and self._is_nextjs_server_file(file_path):
            for i, line in enumerate(lines, 1):
                if (
                    "token" in line.lower()
                    or "cookie" in line.lower()
                    or "session" in line.lower()
                ) and "csrf" not in line.lower():
                    if re.search(r'(cookies\(\)|headers\(\)|request\.(cookies|headers))', line):
                        issues.append((i, "MISSING_CSRF"))

        elif file_path.name == ".env.example":
            for i, line in enumerate(lines, 1):
                if "=" in line and not line.lstrip().startswith("#"):
                    var_name = line.split("=")[0].strip()
                    styles = self.seen_patterns.get("env_var_style", [])
                    if styles:
                        preferred = self._get_most_common(styles, "")
                        if preferred and not preferred.isupper():
                            preferred = preferred.upper()
                        if var_name.upper() != preferred.upper():
                            issues.append((i, "ENV_VAR_STYLE"))

        return issues

    def _learn_project_patterns(self) -> Dict[str, List[str]]:
        patterns = {
            "fastapi_auth_decorator": [],
            "nextjs_token_handler": [],
            "env_var_style": [],
        }

        for py_file in self.project_root.rglob("*.py"):
            if any(part in EXCLUDED_DIRS for part in py_file.parts):
                continue
            try:
                tree = ast.parse(py_file.read_text(encoding="utf-8"))
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef):
                        for deco in node.decorator_list:
                            deco_str = ast.unparse(deco).strip()
                            if "depend" in deco_str.lower():
                                patterns["fastapi_auth_decorator"].append(deco_str)
            except Exception:
                pass

        for js_file in self.project_root.rglob("*.[jt]s*"):
            if any(part in EXCLUDED_DIRS for part in js_file.parts):
                continue
            try:
                content = js_file.read_text(encoding="utf-8")
                if "use server" in content and "csrf" in content.lower():
                    patterns["nextjs_token_handler"].append("csrf_validation")
            except Exception:
                pass

        env_example = self.project_root / ".env.example"
        if env_example.exists():
            try:
                content = env_example.read_text(encoding="utf-8")
                patterns["env_var_style"] = [
                    line.split("=")[0].strip()
                    for line in content.splitlines()
                    if "=" in line and not line.startswith("#") and line.strip()
                ]
            except Exception:
                pass

        return patterns

    def _get_most_common(self, items: List[str], fallback: str) -> str:
        if not items:
            return fallback
        return max(set(items), key=items.count)

    def suggest_improvement(
        self, file_path: Path, line_num: int, issue_type: str
    ) -> Optional[str]:
        if issue_type == "MISSING_AUTH" and file_path.suffix == ".py":
            decorators = self.seen_patterns.get("fastapi_auth_decorator", [])
            most_common = self._get_most_common(decorators, "Depends(get_current_user)")
            return (
                f"💡 [SPP] Rota sem autenticação detectada. "
                f"Padrão do projeto: `{most_common}`. "
                f"Use --auto-improve para aplicar com indentação automática."
            )

        if issue_type == "MISSING_CSRF" and file_path.suffix in [".js", ".ts", ".jsx", ".tsx"]:
            return (
                "💡 [SPP] Manipulação de token sem validação CSRF. "
                "Recomendado adicionar middleware de validação CSRF."
            )

        if issue_type == "ENV_VAR_STYLE" and file_path.name == ".env.example":
            styles = self.seen_patterns.get("env_var_style", [])
            if styles:
                preferred = self._get_most_common(styles, "")
                return (
                    f"💡 [SPP] Estilo de variável inconsistente. "
                    f"Padrão do projeto: `{preferred}=`. "
                    f"Use --auto-improve para padronizar."
                )

        return None

    def apply_improvements_to_file(
        self, file_path: Path, issues: List[Tuple[int, str]]
    ) -> bool:
        if not issues:
            return False

        try:
            original_content = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            return False

        lines = original_content.splitlines(keepends=True)
        if not lines:
            return False

        sorted_issues = sorted(issues, key=lambda x: x[0], reverse=True)
        modified = False

        for line_num, issue_type in sorted_issues:
            idx = line_num - 1
            if idx < 0 or idx >= len(lines):
                continue

            target_line = lines[idx]
            indentation = target_line[: len(target_line) - len(target_line.lstrip())] if target_line else ""

            if issue_type == "MISSING_AUTH" and file_path.suffix == ".py":
                decorators = self.seen_patterns.get("fastapi_auth_decorator", [])
                deco_to_add = self._get_most_common(decorators, "Depends(get_current_user)")
                if not deco_to_add.startswith("@"):
                    deco_to_add = f"@{deco_to_add}"

                lines.insert(idx, f"{indentation}{deco_to_add}\n")
                modified = True

            elif issue_type == "ENV_VAR_STYLE" and file_path.name == ".env.example":
                old_var = target_line.split("=")[0].strip()
                new_var = old_var.upper()
                new_line = target_line.replace(old_var, new_var, 1)
                lines[idx - 1] = new_line
                modified = True

        if modified:
            try:
                file_path.write_text("".join(lines), encoding="utf-8")
                return True
            except Exception:
                return False

        return False

    def scan_and_report(self, target_path: Path) -> Dict[str, List[Tuple[int, str]]]:
        results = {}
        if target_path.is_file():
            if not self._should_skip_path(target_path):
                issues = self._detect_issues_in_file(target_path)
                if issues:
                    results[str(target_path)] = issues
        else:
            for file_p in target_path.rglob("*"):
                if file_p.is_file() and not self._should_skip_path(file_p):
                    issues = self._detect_issues_in_file(file_p)
                    if issues:
                        results[str(file_p)] = issues
        return results


# Global constants
EXCLUDED_DIRS = {
    "venv", ".venv", "node_modules", ".next", "__pycache__", ".git",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "coverage",
}

MAX_FILE_SIZE = 1_024 * 1_024  # 1 MB

NEXTJS_SERVER_DIRS = {
    "app/api", "pages/api", "actions", "server-actions", "lib/actions",
}

STRIPE_LIVE_PREFIX = "sk_live_"
STRIPE_TEST_PREFIX = "sk_test_"

# Patterns for secret detection
SECRET_PATTERNS = [
    (re.compile(r'(?i)(?<![\'"#])(secret_key|jwt_secret|api_key|password|token)\s*=\s*["\']([^"\']{1,})["\']'), "GENERIC_SECRET_PY"),
    (re.compile(r'(?i)(?<![\'"#])(?:const|let|var)\s+(secretKey|jwtSecret|apiKey|password|token)\s*=\s*["\']([^"\']{1,})["\']'), "GENERIC_SECRET_JS"),
    (re.compile(r'sk_live_[0-9a-zA-Z\.]{10,}'), "STRIPE_LIVE_KEY"),
    (re.compile(r'sk_test_[0-9a-zA-Z\.]{10,}'), "STRIPE_TEST_KEY"),
    (re.compile(r'ghp_[0-9a-zA-Z]{36}'), "GITHUB_PERSONAL_TOKEN"),
    (re.compile(r'gho_[0-9a-zA-Z]{36}'), "GITHUB_OAUTH_TOKEN"),
    (re.compile(r'ghu_[0-9a-zA-Z]{36}'), "GITHUB_USER_TOKEN"),
    (re.compile(r'ghs_[0-9a-zA-Z]{36}'), "GITHUB_SERVER_TOKEN"),
    (re.compile(r'ghr_[0-9a-zA-Z]{36}'), "GITHUB_REFRESH_TOKEN"),
    (re.compile(r'ai_[0-9a-zA-Z]{32,}'), "OPENAI_API_KEY"),
    (re.compile(r'xoxb-[0-9a-zA-Z-]{50,}'), "SLACK_BOT_TOKEN"),
    (re.compile(r'xoxp-[0-9a-zA-Z-]{50,}'), "SLACK_USER_TOKEN"),
    (re.compile(r'xoxa-[0-9a-zA-Z-]{50,}'), "SLACK_APP_TOKEN"),
]

PYTHON_PATTERN_TYPES = [
    "STRIPE_LIVE_KEY", "STRIPE_TEST_KEY",
    "GITHUB_PERSONAL_TOKEN", "GITHUB_OAUTH_TOKEN", "GITHUB_USER_TOKEN",
    "GITHUB_SERVER_TOKEN", "GITHUB_REFRESH_TOKEN", "OPENAI_API_KEY",
    "SLACK_BOT_TOKEN", "SLACK_USER_TOKEN", "SLACK_APP_TOKEN",
    "GENERIC_SECRET_PY"
]

JS_PATTERN_TYPES = [
    "STRIPE_LIVE_KEY", "STRIPE_TEST_KEY",
    "GITHUB_PERSONAL_TOKEN", "GITHUB_OAUTH_TOKEN", "GITHUB_USER_TOKEN",
    "GITHUB_SERVER_TOKEN", "GITHUB_REFRESH_TOKEN", "OPENAI_API_KEY",
    "SLACK_BOT_TOKEN", "SLACK_USER_TOKEN", "SLACK_APP_TOKEN",
    "GENERIC_SECRET_JS"
]

# Auto-fix function for secrets
def auto_fix_secrets(file_path: Path, env_example_path: Path) -> Tuple[bool, int, List[str]]:
    if not file_path.exists() or file_path.stat().st_size > MAX_FILE_SIZE:
        return False, 0, []

    try:
        content = file_path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, PermissionError):
        return False, 0, []

    if file_path.suffix not in {".py", ".js", ".ts", ".jsx", ".tsx"}:
        return False, 0, []

    original_content = content
    fixes_count = 0
    extracted_vars: List[str] = []

    def update_env_example(var_name: str) -> None:
        if not env_example_path.exists():
            env_example_path.write_text(f"# Auto-generated environment variables\n{var_name}=\n", encoding="utf-8")
            return

        existing = env_example_path.read_text(encoding="utf-8")
        existing_vars = {
            line.split("=")[0].strip()
            for line in existing.splitlines()
            if "=" in line and not line.lstrip().startswith("#")
        }
        if var_name not in existing_vars:
            with open(env_example_path, "a", encoding="utf-8") as f:
                f.write(f"\n{var_name}=\n")

    if file_path.suffix == ".py":
        has_os_import = bool(re.search(r'^\s*import os\b', content, re.MULTILINE))

        for ptype in ["STRIPE_LIVE_KEY", "STRIPE_TEST_KEY", "GITHUB_PERSONAL_TOKEN", 
                      "GITHUB_OAUTH_TOKEN", "GITHUB_USER_TOKEN", "GITHUB_SERVER_TOKEN",
                      "GITHUB_REFRESH_TOKEN", "OPENAI_API_KEY", "SLACK_BOT_TOKEN",
                      "SLACK_USER_TOKEN", "SLACK_APP_TOKEN", "GENERIC_SECRET_PY"]:
            pattern = next((p for p, t in SECRET_PATTERNS if t == ptype), None)
            if not pattern:
                continue

            for match in re.finditer(pattern, content):
                full = match.group(0)
                if "os.getenv" in full or "os.environ" in full:
                    continue

                if ptype == "GENERIC_SECRET_PY":
                    var_name = match.group(1).upper()
                    replacement = f'{match.group(1)} = os.getenv("{var_name}", "CHANGE_ME_IN_PRODUCTION")'
                else:
                    var_name = f"API_KEY_{fixes_count + 1}"
                    replacement = f'os.getenv("{var_name}", "CHANGE_ME_IN_PRODUCTION")'

                content = content.replace(full, replacement, 1)
                fixes_count += 1
                extracted_vars.append(var_name)
                update_env_example(var_name)

        if fixes_count > 0 and not has_os_import:
            content = "import os\n" + content

    elif file_path.suffix in {".js", ".ts", ".jsx", ".tsx"}:
        has_process_env = "process.env" in content

        for ptype in ["GENERIC_SECRET_JS", "STRIPE_LIVE_KEY", "STRIPE_TEST_KEY"]:
            pattern = next((p for p, t in SECRET_PATTERNS if t == ptype), None)
            if not pattern:
                continue

            for match in re.finditer(pattern, content):
                full = match.group(0)
                if "process.env" in full:
                    continue

                if ptype == "GENERIC_SECRET_JS":
                    var_name = match.group(1).upper()
                    replacement = f'const {match.group(1)} = process.env.{var_name} || "CHANGE_ME_IN_PRODUCTION";'
                else:
                    var_name = f"API_KEY_{fixes_count + 1}"
                    replacement = f'process.env.{var_name} || "CHANGE_ME_IN_PRODUCTION"'

                content = content.replace(full, replacement, 1)
                fixes_count += 1
                extracted_vars.append(var_name)
                update_env_example(var_name)

        if fixes_count > 0 and not has_process_env:
            content = "// Auto-generated: environment variables\n" + content

    if content != original_content:
        file_path.write_text(content, encoding="utf-8")
        return True, fixes_count, extracted_vars

    return False, 0, []


# Module exports
__all__ = [
    "DiffType",
    "DiffHunk",
    "ParsedDiff",
    "DiffParser",
    "SecurityPairProgrammer",
    "auto_fix_secrets",
    "EXCLUDED_DIRS",
    "MAX_FILE_SIZE",
    "DiffParsingConfig",
    "ExclusionConfig",
]