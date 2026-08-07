#!/usr/bin/env python3
"""
HERMES REVIEW SENTINEL: CLI Server
Enterprise-grade Security Pair Programmer CLI and GitHub Action.
"""

import sys
import argparse
import asyncio
import os
from pathlib import Path
from typing import List, Tuple, Optional

from security_pair_programmer import (
    SecurityPairProgrammer,
    auto_fix_secrets,
    EXCLUDED_DIRS,
    MAX_FILE_SIZE,
)

from hermes.formatters import (
    OutputFormatter,
    FindingFormatter,
    OutputFormat,
    OutputConfig,
)

from hermes.config import load_config, HermesConfig


def print_banner():
    print("🔍 [Hermes Sentinel] Security Pair Programmer")
    print("   Enterprise-grade AST-based security scanner with auto-fix")


def run_scan(
    target_path: str,
    auto_fix: bool = False,
    auto_improve: bool = False,
    output_format: str = "markdown",
    output: Optional[str] = None,
    strict: bool = False,
    config_path: Optional[str] = None,
) -> int:
    target = Path(target_path).resolve()
    if not target.exists():
        print(f"❌ Caminho não encontrado: {target_path}")
        return 2

    root_dir = target if target.is_dir() else target.parent

    # Load configuration
    if config_path:
        config = load_config(Path(config_path))
    else:
        config = HermesConfig()

    spp = SecurityPairProgrammer(root_dir)

    files_to_scan: List[Path] = [target] if target.is_file() else list(target.rglob("*"))

    total_fixes = 0
    total_improvements = 0
    files_with_issues = 0
    all_findings: List[Dict[str, Any]] = []
    error_occurred = False

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

        error_occurred = False

        # --- 1. AUTO-FIX DE SECRETS (original) ---
        if auto_fix:
            env_example = root_dir / ".env.example"
            try:
                modified, fixes, vars_added = auto_fix_secrets(file_p, env_example)
                if modified:
                    total_fixes += fixes
                    files_with_issues += 1
                    print(f"✅ [AUTO-FIX] {file_p.relative_to(root_dir)}: {fixes} segredo(s) removido(s) → os.getenv()/process.env aplicado.")
                    if vars_added:
                        print(f"   └─ Variáveis adicionadas ao .env.example: {', '.join(vars_added)}")
            except Exception as e:
                if auto_fix and strict:
                    print(f"❌ [AUTO-FIX] Erro ao processar {file_p}: {e}")
                    return 2
                error_occurred = True

        # --- 2. SPP ANALYSIS & AUTO-IMPROVE ---
        try:
            issues = spp._detect_issues_in_file(file_p)
            if issues:
                files_with_issues += 1

                for line_num, issue_type in issues:
                    suggestion = spp.suggest_improvement(file_p, line_num, issue_type)
                    if suggestion:
                        print(f"💡 [SPP] {file_p.relative_to(root_dir)}:{line_num}")
                        print(f"   {suggestion}")

                        # Add finding to all_findings
                        all_findings.append({
                            "file": str(file_p.relative_to(root_dir)),
                            "line": line_num,
                            "message": suggestion,
                            "severity": "medium",
                            "rule_id": "SPP_IMPROVE",
                        })

                if auto_improve:
                    applied = spp.apply_improvements_to_file(file_p, issues)
                    if applied:
                        total_improvements += len(issues)
                        print(f"✨ [SPP] Melhorias aplicadas com sucesso em {file_p.name}")
        except Exception as e:
            if auto_improve and strict:
                print(f"❌ [SPP] Erro ao processar {file_p}: {e}")
                return 2
            error_occurred = True
        except Exception as e:
            # Handle any unexpected errors during file processing
            if strict:
                print(f"❌ Erro ao processar {file_p}: {e}")
                return 2
            error_occurred = True

    # Output results
    finding_formatter = FindingFormatter(OutputConfig())

    if all_findings:
        output_format_lower = output_format.lower()
        findings_output = FindingFormatter.format_findings(all_findings, output_format)
        print(findings_output)

    # Write to output file if specified
    if output:
        with open(output, 'w') as f:
            f.write(findings_output if all_findings else "")

    print("\n📊 [Resumo]")
    print(f"   Arquivos com issues: {files_with_issues}")
    if auto_fix:
        print(f"   Secrets corrigidos: {total_fixes}")
    if auto_improve:
        print(f"   Melhorias SPP aplicadas: {total_improvements}")

    if files_with_issues == 0:
        print("\n✨ Nenhuma vulnerabilidade ou melhoria pendente detectada.")
        return 0

    # Return exit code 1 for findings (blocking CI/CD)
    return 1


def print_banner():
    print("🔍 [Hermes Sentinel] Security Pair Programmer")
    print("   Enterprise-grade AST-based security scanner with auto-fix")


def main():
    parser = argparse.ArgumentParser(
        description="Hermes Review Sentinel - Security Pair Programmer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m hermes.sentinel_server .                    # Scan only (report)
  python -m hermes.sentinel . --auto-fix                # Auto-fix hardcoded secrets
  python -m hermes.sentinel . --auto-improve           # Apply contextual improvements
  python -m hermes-sentinel . --auto-fix --auto-improve # Everything
  python -m hermes.sentinel backend/main.py --format json  # JSON output
  python -m hermes-sentinel . --format sarif --output results.sarif
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
        "--format",
        choices=["markdown", "json", "sarif"],
        default="markdown",
        help="Output format (default: markdown)"
    )
    parser.add_argument(
        "--output",
        help="Output file path (default: stdout)"
    )
    parser.add_argument(
        "--config",
        help="Path to .hermes.yml configuration file"
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enable strict mode - fail on any error"
    )
    parser.add_argument(
        "--config-output",
        help="Generate default .hermes.yml configuration file"
    )
    parser.add_argument(
        "--version",
        action="version",
        version="Hermes Review Sentinel 2.0.0"
    )

    args = parser.parse_args()

    if args.config_output:
        config = HermesConfig()
        config_path = Path(args.config_output)
        config_path.write_text(config.model_dump_yaml())
        print(f"✅ Configuration saved to {config_path}")
        return 0

    if not args.auto_fix and not args.auto_improve:
        print_banner()
        print("\n💡 Dica: Use --auto-fix para corrigir secrets ou --auto-improve para melhorias contextuais.\n")

    sys.exit(run_scan(
        target_path=args.target,
        auto_fix=args.auto_fix,
        auto_improve=args.auto_improve,
        output_format=args.format,
        output=args.output,
        strict=args.strict,
        config_path=args.config
    ))


if __name__ == "__main__":
    main()