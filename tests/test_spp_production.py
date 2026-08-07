import os
#!/usr/bin/env python3
"""
Testes de produção para o Security Pair Programmer (SPP).
Cobre: preservação de indentação, decoradores multilinhas, line drift, comentários e estilos.
"""

import sys
import textwrap
from pathlib import Path

import pytest

# Adiciona src ao path para importar o módulo
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from security_pair_programmer import SecurityPairProgrammer, auto_fix_secrets


class TestSecurityPairProgrammer:
    """Testes para o SecurityPairProgrammer."""

    def test_indentation_preserved(self, tmp_path: Path):
        """Garante que a indentação exata (4 espaços) é preservada ao inserir decorador."""
        project_root = tmp_path
        (project_root / "backend").mkdir()
        # Cria arquivo com padrão de auth existente
        (project_root / "backend" / "auth.py").write_text(
            "@app.get('/login')\n@depends(get_current_user)\ndef login(): pass\n",
            encoding="utf-8"
        )
        # Cria arquivo de teste com indentação de 4 espaços
        test_file = project_root / "backend" / "test_indent.py"
        test_file.write_text(
            "    @app.get('/admin')\n    def admin_panel():\n        return {'users': []}\n",
            encoding="utf-8"
        )

        spp = SecurityPairProgrammer(project_root)
        issues = [(1, "MISSING_AUTH")]  # Linha 1 (onde está @app.get)
        applied = spp.apply_improvements_to_file(test_file, issues)

        assert applied is True
        result = test_file.read_text(encoding="utf-8")
        # Verifica que a linha inserida tem exatamente 4 espaços de indentação
        lines = result.splitlines()
        assert lines[0] == "    @app.get('/admin')"
        assert lines[1] == "    @depends(get_current_user)"
        assert lines[2] == "    def admin_panel():"
        assert lines[3] == "        return {'users': []}"

    def test_multiline_decorator_handling(self, tmp_path: Path):
        """Garante que decoradores multilinhas não quebram a detecção/inserção."""
        project_root = tmp_path
        (project_root / "backend").mkdir()
        (project_root / "backend" / "auth.py").write_text(
            "@app.get('/login')\n@depends(get_current_user)\ndef login(): pass\n",
            encoding="utf-8"
        )
        # Arquivo com decorador multilinha
        test_file = project_root / "backend" / "test_multiline.py"
        test_file.write_text(
            textwrap.dedent("""
                @app.get(
                    "/dashboard",
                    response_model=DashboardResponse
                )
                def get_dashboard():
                    return dashboard_service.get()
            """).strip() + "\n",
            encoding="utf-8"
        )

        spp = SecurityPairProgrammer(project_root)
        # A detecção via AST pega a linha da função (linha 5 no arquivo acima)
        issues = [(5, "MISSING_AUTH")]
        applied = spp.apply_improvements_to_file(test_file, issues)

        assert applied is True
        result = test_file.read_text(encoding="utf-8")
        lines = result.splitlines()
        # O decorador deve ser inserido ANTES da linha da função (linha 5 original -> índice 4)
        # Como ordenamos reverso, a inserção acontece no índice correto
        assert any("@depends(get_current_user)" in line for line in lines)
        # Verifica que a função original não foi corrompida
        assert "def get_dashboard():" in result

    def test_line_drift_prevention_multiple_insertions(self, tmp_path: Path):
        """Múltiplas inserções no mesmo arquivo não devem causar deslocamento de índices."""
        project_root = tmp_path
        (project_root / "backend").mkdir()
        (project_root / "backend" / "auth.py").write_text(
            "@app.get('/login')\n@depends(get_current_user)\ndef login(): pass\n",
            encoding="utf-8"
        )
        # Arquivo com 3 rotas vulneráveis
        test_file = project_root / "backend" / "test_drift.py"
        test_file.write_text(
            "@app.get('/user')\ndef get_user(): pass\n\n"
            "@app.get('/admin')\ndef get_admin(): pass\n\n"
            "@app.get('/data')\ndef get_data(): pass\n",
            encoding="utf-8"
        )

        spp = SecurityPairProgrammer(project_root)
        # Linhas 1, 4, 7 (1-indexed) - onde estão os @app.get
        issues = [(1, "MISSING_AUTH"), (4, "MISSING_AUTH"), (7, "MISSING_AUTH")]
        applied = spp.apply_improvements_to_file(test_file, issues)

        assert applied is True
        result = test_file.read_text(encoding="utf-8")
        lines = result.splitlines()
        # Deve ter 3 decoradores @depends inseridos
        depends_count = sum(1 for line in lines if "@depends(get_current_user)" in line)
        assert depends_count == 3
        # Verifica ordem: cada @app.get deve ser seguido por @depends
        for i, line in enumerate(lines):
            if "@app.get" in line:
                assert i + 1 < len(lines)
                assert "@depends(get_current_user)" in lines[i + 1]

    def test_comment_and_quote_preservation(self, tmp_path: Path):
        """Comentários inline e estilo de aspas devem ser preservados."""
        project_root = tmp_path
        (project_root / "backend").mkdir()
        (project_root / "backend" / "auth.py").write_text(
            '@app.get("/login")\n@depends(get_current_user)\ndef login(): pass\n',
            encoding="utf-8"
        )
        # Arquivo com comentários e aspas simples
        test_file = project_root / "backend" / "test_quotes.py"
        test_file.write_text(
            "# Rota pública\n@app.get('/public')  # GET endpoint\ndef public(): pass\n",
            encoding="utf-8"
        )

        spp = SecurityPairProgrammer(project_root)
        issues = [(2, "MISSING_AUTH")]  # Linha 2: @app.get('/public')
        applied = spp.apply_improvements_to_file(test_file, issues)

        assert applied is True
        result = test_file.read_text(encoding="utf-8")
        # Comentário original deve permanecer
        assert "# Rota pública" in result
        assert "# GET endpoint" in result
        # Aspas simples preservadas
        assert "@app.get('/public')" in result
        # Decorador inserido com indentação correta (mesma da linha alvo)
        lines = result.splitlines()
        assert lines[0] == "# Rota pública"
        assert lines[1] == "@app.get('/public')  # GET endpoint"
        assert lines[2] == "@depends(get_current_user)"
        assert lines[3] == "def public(): pass"

    def test_env_var_style_standardization(self, tmp_path: Path):
        """Padronização de estilo de estilo de variáveis no .env.example."""
        project_root = tmp_path
        # .env.example com padrão estabelecido (UPPER_SNAKE_CASE)
        (project_root / ".env.example").write_text(
            "SECRET_KEY=\nJWT_SECRET=\nAPI_KEY=\n",
            encoding="utf-8"
        )
        # Arquivo com estilo inconsistente
        test_env = project_root / ".env.example"
        # Sobrescreve com estilo inconsistente
        test_env.write_text(
            "secret_key=\njwt_secret=\nAPI_KEY=\n",
            encoding="utf-8"
        )

        spp = SecurityPairProgrammer(project_root)
        # Detecta issues de estilo nas linhas 1 e 2
        issues = [(1, "ENV_VAR_STYLE"), (2, "ENV_VAR_STYLE")]
        applied = spp.apply_improvements_to_file(test_env, issues)

        assert applied is True
        result = test_env.read_text(encoding="utf-8")
        # Todas devem estar no padrão UPPER_SNAKE_CASE (o mais comum no projeto)
        lines = [line.strip() for line in result.splitlines() if line.strip() and not line.startswith("#")]
        assert all(line.split("=")[0].isupper() for line in lines)

    def test_excluded_dirs_skipped(self, tmp_path: Path):
        """Pastas excluídas (node_modules, venv, .git) não devem ser processadas."""
        project_root = tmp_path
        (project_root / "backend").mkdir()
        # Cria arquivo VULNERÁVEL em backend/ (sem autenticação)
        (project_root / "backend" / "vuln.py").write_text(
            "@app.get('/admin')\ndef admin(): pass\n",
            encoding="utf-8"
        )
        # Cria estrutura com pastas excluídas
        (project_root / "node_modules" / "fake").mkdir(parents=True)
        (project_root / "venv" / "lib").mkdir(parents=True)
        (project_root / ".git").mkdir()

        (project_root / "node_modules" / "fake" / "vuln.py").write_text(
            "@app.get('/hack')\ndef hack(): pass\n",
            encoding="utf-8"
        )
        (project_root / "venv" / "lib" / "vuln.py").write_text(
            "@app.get('/hack')\ndef hack(): pass\n",
            encoding="utf-8"
        )

        spp = SecurityPairProgrammer(project_root)
        results = spp.scan_and_report(project_root)

        # Apenas arquivos fora das pastas excluídas devem aparecer
        scanned_files = list(results.keys())
        assert not any("node_modules" in f for f in scanned_files)
        assert not any("venv" in f for f in scanned_files)
        assert not any(".git" in f for f in scanned_files)
        # Mas o arquivo vulnerável em backend/ deve ser escaneado e aparecer nos resultados
        assert any("backend" in f for f in scanned_files)

    def test_max_file_size_skip(self, tmp_path: Path):
        """Arquivos maiores que 1MB devem ser ignorados."""
        project_root = tmp_path
        (project_root / "backend").mkdir()
        (project_root / "backend" / "auth.py").write_text(
            "@app.get('/login')\n@depends(get_current_user)\ndef login(): pass\n",
            encoding="utf-8"
        )
        # Cria arquivo grande (>1MB)
        large_file = project_root / "backend" / "large.py"
        large_content = "@app.get('/large')\ndef large(): pass\n" + "x" * (1_024 * 1_024)
        large_file.write_text(large_content, encoding="utf-8")

        spp = SecurityPairProgrammer(project_root)
        results = spp.scan_and_report(project_root)

        scanned_files = list(results.keys())
        assert not any("large.py" in f for f in scanned_files)


class TestAutoFixSecrets:
    """Testes para a função auto_fix_secrets (correção de secrets hardcoded)."""

    def test_python_secret_replacement(self, tmp_path: Path):
        """Secrets em Python devem ser substituídos por os.getenv()."""
        test_file = tmp_path / "test_secret.py"
        test_file.write_text(
            'SECRET_KEY = "***"\nAPI_KEY = "os.getenv("API_KEY_1", "CHANGE_ME_IN_PRODUCTION")"\n',
            encoding="utf-8"
        )
        env_example = tmp_path / ".env.example"

        modified, fixes, vars_added = auto_fix_secrets(test_file, env_example)

        assert modified is True
        assert fixes == 2
        result = test_file.read_text(encoding="utf-8")
        assert 'os.getenv("SECRET_KEY"' in result
        assert 'os.getenv("API_KEY_' in result
        assert "import os" in result
        env_content = env_example.read_text(encoding="utf-8")
        assert "SECRET_KEY=" in env_content
        assert any("API_KEY_" in line for line in env_content.splitlines())

    def test_js_secret_replacement(self, tmp_path: Path):
        """Secrets em JS/TS devem ser substituídos por process.env."""
        test_file = tmp_path / "test_secret.js"
        test_file.write_text(
            'const apiKey = "***"\nconst stripeKey = "os.getenv("API_KEY_2", "CHANGE_ME_IN_PRODUCTION")"\n',
            encoding="utf-8"
        )
        env_example = tmp_path / ".env.example"

        modified, fixes, vars_added = auto_fix_secrets(test_file, env_example)

        assert modified is True
        assert fixes == 2
        result = test_file.read_text(encoding="utf-8")
        assert 'process.env.API_KEY_' in result
        assert 'process.env.STRIPE_KEY_' in result or 'process.env.API_KEY_' in result
        env_content = env_example.read_text(encoding="utf-8")
        assert any("API_KEY_" in line for line in env_content.splitlines())

    def test_already_secured_code_unchanged(self, tmp_path: Path):
        """Código que já usa variáveis de ambiente não deve ser alterado."""
        test_file = tmp_path / "test_secure.py"
        test_file.write_text(
            'SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME")\n',
            encoding="utf-8"
        )
        env_example = tmp_path / ".env.example"

        modified, fixes, vars_added = auto_fix_secrets(test_file, env_example)

        assert modified is False
        assert fixes == 0
        result = test_file.read_text(encoding="utf-8")
        assert 'os.getenv("SECRET_KEY"' in result


class TestIntegration:
    """Testes de integração SPP + Auto-fix."""

    def test_spp_and_auto_fix_together(self, tmp_path: Path):
        """SPP e auto-fix devem funcionar juntos sem conflitos."""
        project_root = tmp_path
        (project_root / "backend").mkdir()
        (project_root / "backend" / "auth.py").write_text(
            "@app.get('/login')\n@depends(get_current_user)\ndef login(): pass\n",
            encoding="utf-8"
        )
        # Arquivo com ambos: secret hardcoded E rota sem auth
        test_file = project_root / "backend" / "mixed.py"
        test_file.write_text(
            'SECRET_KEY = "***"\n@app.get("/admin")\ndef admin(): pass\n',
            encoding="utf-8"
        )
        env_example = project_root / ".env.example"

        spp = SecurityPairProgrammer(project_root)

        # 1. Auto-fix
        modified, fixes, vars_added = auto_fix_secrets(test_file, env_example)
        assert modified is True
        assert fixes == 1

        # 2. SPP detecta e corrige
        issues = spp._detect_issues_in_file(test_file)
        assert len(issues) == 1
        assert issues[0][1] == "MISSING_AUTH"

        applied = spp.apply_improvements_to_file(test_file, issues)
        assert applied is True

        result = test_file.read_text(encoding="utf-8")
        # Ambos devem estar presentes
        assert 'os.getenv("SECRET_KEY"' in result
        assert "@depends(get_current_user)" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])