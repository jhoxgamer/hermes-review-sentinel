#!/usr/bin/env python3
"""
HERMES REVIEW SENTINEL: CLI Server
Scanner de segurança com auto-fix de secrets e Security Pair Programmer (SPP).
"""

import sys
import argparse
from pathlib import Path
from typing import List, Tuple

from security_pair_programmer import (
    SecurityPairProgrammer,
    auto_fix_secrets,
    EXCLUDED_DIRS,
    MAX_FILE_SIZE,
)


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