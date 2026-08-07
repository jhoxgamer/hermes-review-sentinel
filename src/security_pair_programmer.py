"""
HERMES REVIEW SENTINEL: Security Pair Programmer (SPP)
Módulo de análise contextual, aprendizado de padrões e auto-correção com preservação total de sintaxe.
"""

import ast
import os
import re
import textwrap
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

MAX_FILE_SIZE = 1_024 * 1_024  # 1 MB

EXCLUDED_DIRS: Set[str] = {
    "venv", ".venv", "node_modules", ".next", "__pycache__", ".git",
    "dist", "build", ".tox", ".mypy_cache", ".pytest_cache", "coverage",
}

EXCLUDED_EXTENSIONS: Set[str] = {
    ".pyc", ".pyo", ".pyd", ".so", ".dll", ".exe", ".bin", ".dat",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".map", ".min.js", ".min.css",
}

NEXTJS_SERVER_DIRS: Set[str] = {
    "app/api", "pages/api", "actions", "server-actions", "lib/actions",
}

# Patterns mais robustos - aceitam secrets mais curtos para testes
STRIPE_LIVE_PREFIX = "sk_live_"
STRIPE_TEST_PREFIX = "sk_test_"

SECRET_PATTERNS = [
    # Python: GENERIC_SECRET_PY - secret_key = os.getenv("SECRET_KEY", "CHANGE_ME_IN_PRODUCTION") / secret_key = os.getenv("SECRET_KEY", "CHANGE_ME_IN_PRODUCTION")
    (re.compile(r'(?i)(?<![\'"#])(secret_key|jwt_secret|api_key|password|token)\s*=\s*["\']([^"\']{1,})["\']'), "GENERIC_SECRET_PY"),
    # JS/TS: GENERIC_SECRET_JS - const/let/var secretKey = "..."
        (re.compile(r'(?i)(?<![\'"#])(?:const|let|var)\s+(secretKey|jwtSecret|apiKey|stripeKey|password|token)\s*=\s*["\']([^"\']{1,})["\']'), "GENERIC_SECRET_JS"),
    # Stripe live/test keys - usando concatenação para evitar false positives no secret scanning
    (re.compile(STRIPE_LIVE_PREFIX + r'[0-9a-zA-Z\.]{10,}'), "STRIPE_LIVE_KEY"),
    (re.compile(STRIPE_TEST_PREFIX + r'[0-9a-zA-Z\.]{10,}'), "STRIPE_TEST_KEY"),
    # GitHub tokens
    (re.compile(r'ghp_[0-9a-zA-Z]{36}'), "GITHUB_PERSONAL_TOKEN"),
    (re.compile(r'gho_[0-9a-zA-Z]{36}'), "GITHUB_OAUTH_TOKEN"),
    (re.compile(r'ghu_[0-9a-zA-Z]{36}'), "GITHUB_USER_TOKEN"),
    (re.compile(r'ghs_[0-9a-zA-Z]{36}'), "GITHUB_SERVER_TOKEN"),
    (re.compile(r'ghr_[0-9a-zA-Z]{36}'), "GITHUB_REFRESH_TOKEN"),
    # OpenAI
    (re.compile(r'ai_[0-9a-zA-Z]{32,}'), "OPENAI_API_KEY"),
    # Slack
    (re.compile(r'xoxb-[0-9a-zA-Z-]{50,}'), "SLACK_BOT_TOKEN"),
    (re.compile(r'xoxp-[0-9a-zA-Z-]{50,}'), "SLACK_USER_TOKEN"),
    (re.compile(r'xoxa-[0-9a-zA-Z-]{50,}'), "SLACK_APP_TOKEN"),
]

# Tipos que se aplicam a Python (STRIPE deve vir ANTES de GENERIC_SECRET_PY para capturar primeiro)
PYTHON_PATTERN_TYPES = [
    "STRIPE_LIVE_KEY", "STRIPE_TEST_KEY",
    "GITHUB_PERSONAL_TOKEN", "GITHUB_OAUTH_TOKEN", "GITHUB_USER_TOKEN",
    "GITHUB_SERVER_TOKEN", "GITHUB_REFRESH_TOKEN", "OPENAI_API_KEY",
    "SLACK_BOT_TOKEN", "SLACK_USER_TOKEN", "SLACK_APP_TOKEN",
    "GENERIC_SECRET_PY"
]

# Tipos que se aplicam a JS/TS
JS_PATTERN_TYPES = [
    "STRIPE_LIVE_KEY", "STRIPE_TEST_KEY",
    "GITHUB_PERSONAL_TOKEN", "GITHUB_OAUTH_TOKEN", "GITHUB_USER_TOKEN",
    "GITHUB_SERVER_TOKEN", "GITHUB_REFRESH_TOKEN", "OPENAI_API_KEY",
    "SLACK_BOT_TOKEN", "SLACK_USER_TOKEN", "SLACK_APP_TOKEN",
    "GENERIC_SECRET_JS"
]


class SecurityPairProgrammer:
    """Analisa o contexto do projeto e aplica correções preservando indentação e sintaxe."""

    EXCLUDED_DIRS = EXCLUDED_DIRS

    def __init__(self, project_root: Path):
        self.project_root = project_root.resolve()
        self.seen_patterns = self._learn_project_patterns()

    def _should_skip_path(self, path: Path) -> bool:
        try:
            rel_parts = path.relative_to(self.project_root).parts
        except ValueError:
            return True
        if any(part in EXCLUDED_DIRS for part in rel_parts):
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

    def _learn_project_patterns(self) -> Dict[str, List[str]]:
        patterns: Dict[str, List[str]] = {
            "fastapi_auth_decorator": [],
            "nextjs_token_handler": [],
            "env_var_style": [],
        }

        for py_file in self.project_root.rglob("*.py"):
            if self._should_skip_path(py_file):
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
                continue

        for js_file in self.project_root.rglob("*.[jt]s*"):
            if self._should_skip_path(js_file):
                continue
            if not self._is_nextjs_server_file(js_file):
                continue
            try:
                content = js_file.read_text(encoding="utf-8")
                if "use server" in content and "csrf" in content.lower():
                    patterns["nextjs_token_handler"].append("csrf_validation")
                if "cookie" in content.lower() and ("token" in content.lower() or "session" in content.lower()):
                    patterns["nextjs_token_handler"].append("cookie_based")
            except Exception:
                continue

        env_example = self.project_root / ".env.example"
        if env_example.exists() and not self._should_skip_path(env_example):
            try:
                content = env_example.read_text(encoding="utf-8")
                patterns["env_var_style"] = [
                    line.split("=")[0].strip()
                    for line in content.splitlines()
                    if "=" in line and not line.lstrip().startswith("#") and line.strip()
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
            handlers = self.seen_patterns.get("nextjs_token_handler", [])
            hint = f" Padrão detectado: {handlers[0]}." if handlers else ""
            return (
                f"💡 [SPP] Manipulação de token/session sem validação CSRF.{hint} "
                f"Recomendado adicionar middleware de validação CSRF."
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

    def _detect_issues_in_file(self, file_path: Path) -> List[Tuple[int, str]]:
        issues: List[Tuple[int, str]] = []
        if self._should_skip_path(file_path):
            return issues

        try:
            content = file_path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            return issues

        lines = content.splitlines()

        if file_path.suffix == ".py":
                    try:
                        # Dedent content for AST parsing (handles indented code blocks)
                        content_for_ast = content
                        if content.startswith(" ") or content.startswith("\t"):
                            content_for_ast = textwrap.dedent(content)
                
                        tree = ast.parse(content_for_ast)
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
                                    # Check previous lines for @app. or @router. decorators
                                    for i in range(func_line_idx - 1, max(-1, func_line_idx - 5), -1):
                                        if i < 0:
                                            break
                                        prev_line = lines[i].strip()
                                        if "@app." in prev_line or "@router." in prev_line:
                                            has_route_decorator = True
                                            deco_line_idx = i
                                            break
                                        if prev_line and not prev_line.startswith("@") and not prev_line.startswith("#"):
                                            break

                                if has_route_decorator and not has_depends and not has_auth:
                                    # Report the line of the @app.get/@router.get decorator (1-indexed)
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
                                if var_name != preferred:
                                    issues.append((i, "ENV_VAR_STYLE"))

        return issues

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
            # line_num is 1-indexed line of the @app.get decorator
            idx = line_num - 1  # Convert to 0-indexed
            
            if idx < 0 or idx >= len(lines):
                continue

            target_line = lines[idx]
            indentation = target_line[: len(target_line) - len(target_line.lstrip())] if target_line else ""

            if issue_type == "MISSING_AUTH" and file_path.suffix == ".py":
                decorators = self.seen_patterns.get("fastapi_auth_decorator", [])
                deco_to_add = self._get_most_common(decorators, "Depends(get_current_user)")
                if not deco_to_add.startswith("@"):
                    deco_to_add = f"@{deco_to_add}"
                
                # Find the end of the decorator chain: scan forward from the reported @ line
                # Include all consecutive decorators and their multiline continuations
                # Stop when we hit a function definition (def/async def) or class definition
                insert_idx = idx
                while insert_idx < len(lines):
                    stripped = lines[insert_idx].strip()
                    # If this line starts with @, it's a decorator - continue
                    if stripped.startswith("@"):
                        insert_idx += 1
                        continue
                    # If it's a function or class definition, STOP - this is the end of decorators
                    if stripped.startswith("def ") or stripped.startswith("async def ") or stripped.startswith("class "):
                        break
                    # If it's an indented continuation of a multiline decorator, continue
                    # (indented line that doesn't start with def/async def/class)
                    if lines[insert_idx].startswith(" ") or lines[insert_idx].startswith("\t"):
                        insert_idx += 1
                        continue
                    # Non-indented, non-decorator, non-def/class line - stop
                    break
                
                lines.insert(insert_idx, f"{indentation}{deco_to_add}\n")
                modified = True

            elif issue_type == "ENV_VAR_STYLE" and file_path.name == ".env.example":
                old_var = target_line.split("=")[0].strip()
                new_var = old_var.upper()
                new_line = target_line.replace(old_var, new_var, 1)
                lines[idx] = new_line
                modified = True

        if modified:
            try:
                file_path.write_text("".join(lines), encoding="utf-8")
                return True
            except Exception:
                return False
        return False

    def scan_and_report(self, target_path: Path) -> Dict[str, List[Tuple[int, str]]]:
        results: Dict[str, List[Tuple[int, str]]] = {}
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
            env_example_path.write_text(f"# Variáveis de ambiente auto-geradas\n{var_name}=\n", encoding="utf-8")
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
            for ptype in PYTHON_PATTERN_TYPES:
                pattern = next((p for p, t in SECRET_PATTERNS if t == ptype), None)
                if not pattern:
                    continue
                for match in re.finditer(pattern, content):
                    full = match.group(0)
                    # Check if the VALUE is already an actual os.getenv() call (not just a string containing the text)
                    value_part = ""
                    if match.lastindex is not None and match.lastindex >= 2:
                        value_part = match.group(2)
                    elif match.lastindex is not None and match.lastindex >= 1:
                        value_part = match.group(1)
                    value_part = value_part.strip()
                    # Only skip if value looks like an actual function call: os.getenv(...) or os.environ[...]
                    if (value_part.startswith("os.getenv(") or value_part.startswith("os.environ[") or 
                        value_part.startswith("os.environ.get(")):
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
        for ptype in JS_PATTERN_TYPES:
            pattern = next((p for p, t in SECRET_PATTERNS if t == ptype), None)
            if not pattern:
                continue
            for match in re.finditer(pattern, content):
                full = match.group(0)
                if "process.env" in full:
                    continue
                if ptype == "GENERIC_SECRET_JS":
                    var_name = match.group(2).upper() if match.lastindex >= 2 else match.group(1).upper()
                    var_name_js = match.group(2) if match.lastindex >= 2 else match.group(1)
                    replacement = f'const {var_name_js} = process.env.{var_name} || "CHANGE_ME_IN_PRODUCTION";'
                else:
                    var_name = f"API_KEY_{fixes_count + 1}"
                    replacement = f'process.env.{var_name} || "CHANGE_ME_IN_PRODUCTION"'
                content = content.replace(full, replacement, 1)
                fixes_count += 1
                extracted_vars.append(var_name)
                update_env_example(var_name)
        if fixes_count > 0 and not has_process_env:
            content = "// IMPORTANTE: Variáveis de ambiente geradas automaticamente pelo Hermes Sentinel\n" + content

    if content != original_content:
        try:
            file_path.write_text(content, encoding="utf-8")
            return True, fixes_count, extracted_vars
        except Exception:
            return False, 0, []

    return False, 0, []