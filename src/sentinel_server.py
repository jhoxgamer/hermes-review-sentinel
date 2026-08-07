#!/usr/bin/env python3
"""
HERMES REVIEW SENTINEL: CLI Server
Scanner de segurança com auto-fix de secrets e Security Pair Programmer (SPP).
"""

import sys
import argparse
import asyncio
import os
from pathlib import Path
from typing import List, Tuple, Optional, List, Dict, Any
from dataclasses import dataclass

from security_pair_programmer import (
    SecurityPairProgrammer,
    auto_fix_secrets,
    EXCLUDED_DIRS,
    MAX_FILE_SIZE,
)


@dataclass
class Finding:
    """Represents a security finding or code issue."""
    type: str
    severity: str
    message: str
    file: str
    line: int
    rule_id: str
    context: Optional[str] = None


async def run_semgrep_analysis(diff: str, rules: str) -> List[dict]:
    """Run semgrep analysis on a diff."""
    return []


def _evaluate_intent_alignment(diff: str, description: Optional[str]) -> List[dict]:
    """Evaluate if PR intent is well documented."""
    findings = []
    if not description or len(description) < 10:
        findings.append({
            "type": "documentation",
            "severity": "low",
            "message": "PR description is too short or missing"
        })
    return findings


def _calculate_risk_contextual(findings: List[dict], lines_changed: int, config: dict) -> float:
    """Calculate contextual risk score for a PR."""
    risk = 0.1  # base risk
    for finding in findings:
        if finding.get("severity") == "high":
            risk += 0.3
        elif finding.get("severity") == "medium":
            risk += 0.15
    if lines_changed > config.get("max_lines_changed", 500):
        risk += 0.2
    if any("auth" in str(f.get("file", "")).lower() for f in findings):
        risk *= 1.3
    return min(risk, 1.0)


def _generate_actionable_fixes(findings: List[dict]) -> List[dict]:
    """Generate actionable fixes for findings."""
    fix_map = {
        "secret": {"action": "extract_to_env_var"},
        "sql-injection": {"action": "use_parameterized_query"},
        "n-plus-one": {"action": "use_joinedload_or_bulk_fetch"}
    }
    fixes = []
    seen_actions = set()
    for finding in findings:
        fix = fix_map.get(finding.get("type"), {})
        action = fix.get("action")
        if action and action not in seen_actions:
            fixes.append(fix)
            seen_actions.add(action)
    return fixes


def _extract_files_from_diff(diff: str) -> List[str]:
    """Extract file paths from a unified diff."""
    files = []
    for line in diff.split("\n"):
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                files.append(parts[3][2:])  # Remove 'b/' prefix
    return files


def print_banner():
    print("🔍 [Hermes Sentinel] Security Pair Programmer ativo")
    print("   Detecção contextual + Auto-fix + Aprendizado de padrões do projeto")


def run_scan(
    target_path: str,
    auto_fix: bool = False,
    auto_improve: bool = False,
) -> int:
    target = Path(target_path).resolve()
    if not target.exists():
        print(f"❌ Caminho não encontrado: {target_path}")
        return 1

    root_dir = target if target.is_dir() else target.parent
    spp = SecurityPairProgrammer(root_dir)

    files_to_scan: List[Path] = [target] if target.is_file() else list(target.rglob("*"))

    total_fixes = 0
    total_improvements = 0
    files_with_issues = 0

    print(f"🔍 [Hermes Sentinel] Escaneando {len(files_to_scan)} arquivo(s) em {root_dir}...")

    for file_p in files_to_scan:
        if file_p.is_dir():
            continue
        try:
            rel_parts = file_p.relative_to(root_dir).parts
        except ValueError:
            continue
        if any(p in EXCLUDED_DIRS for p in rel_parts):
            continue
        if file_p.stat().st_size > MAX_FILE_SIZE:
            continue

        try:
            content = file_p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        # --- 1. AUTO-FIX DE SECRETS (original) ---
        if auto_fix:
            env_example = root_dir / ".env.example"
            modified, fixes, vars_added = auto_fix_secrets(file_p, env_example)
            if modified:
                total_fixes += fixes
                files_with_issues += 1
                print(f"✅ [AUTO-FIX] {file_p.relative_to(root_dir)}: {fixes} segredo(s) removido(s) → os.getenv()/process.env aplicado.")
                if vars_added:
                    print(f"   └─ Variáveis adicionadas ao .env.example: {', '.join(vars_added)}")

        # --- 2. SPP ANALYSIS & AUTO-IMPROVE ---
        issues = spp._detect_issues_in_file(file_p)
        if issues:
            files_with_issues += 1

            for line_num, issue_type in issues:
                suggestion = spp.suggest_improvement(file_p, line_num, issue_type)
                if suggestion:
                    print(f"💡 [SPP] {file_p.relative_to(root_dir)}:{line_num}")
                    print(f"   {suggestion}")

            if auto_improve:
                applied = spp.apply_improvements_to_file(file_p, issues)
                if applied:
                    total_improvements += len(issues)
                    print(f"✨ [SPP] Melhorias aplicadas com sucesso em {file_p.name}")

    print("\n📊 [Resumo]")
    print(f"   Arquivos com issues: {files_with_issues}")
    if auto_fix:
        print(f"   Secrets corrigidos: {total_fixes}")
    if auto_improve:
        print(f"   Melhorias SPP aplicadas: {total_improvements}")

    if files_with_issues == 0:
        print("\n✨ Nenhuma vulnerabilidade ou melhoria pendente detectada.")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Hermes Review Sentinel - Security Pair Programmer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  python -m sentinel_server .                    # Scan apenas (relatório)
  python -m sentinel_server . --auto-fix         # Corrige secrets hardcoded
  python -m sentinel_server . --auto-improve     # Aplica melhorias de segurança contextuais
  python -m sentinel_server . --auto-fix --auto-improve  # Tudo junto
  python -m sentinel_server backend/main.py      # Scan em arquivo específico
        """
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Arquivo ou diretório alvo (padrão: diretório atual)"
    )
    parser.add_argument(
        "--auto-fix",
        action="store_true",
        help="Corrige automaticamente secrets hardcoded (substitui por os.getenv/process.env e atualiza .env.example)"
    )
    parser.add_argument(
        "--auto-improve",
        action="store_true",
        help="Aplica melhorias de segurança contextuais aprendidas do projeto (indentação preservada, line drift evitado)"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="Hermes Review Sentinel 2.0.0"
    )

    args = parser.parse_args()

    if not args.auto_fix and not args.auto_improve:
        print_banner()
        print("\n💡 Dica: Use --auto-fix para corrigir secrets ou --auto-improve para melhorias contextuais.\n")

    sys.exit(run_scan(args.target, args.auto_fix, args.auto_improve))


if __name__ == "__main__":
    main()