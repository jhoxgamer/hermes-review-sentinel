import sys
sys.path.insert(0, 'src')
from security_pair_programmer import SecurityPairProgrammer, auto_fix_secrets
from pathlib import Path
import tempfile

print('=== SMOKE TEST ===')

# Test 1: CLI import
from src.sentinel_server import run_scan
print('CLI import OK')

# Test 2: SPP basic
with tempfile.TemporaryDirectory() as tmp:
    project = Path(tmp)
    (project / 'backend').mkdir()
    (project / 'backend' / 'auth.py').write_text('@app.get("/login")\n@depends(get_current_user)\ndef login(): pass\n')
    test = project / 'backend' / 'test.py'
    test.write_text('@app.get("/admin")\ndef admin(): pass\n')
    spp = SecurityPairProgrammer(project)
    issues = spp._detect_issues_in_file(test)
    assert issues == [(1, 'MISSING_AUTH')]
    spp.apply_improvements_to_file(test, issues)
    content = test.read_text()
    assert '@depends(get_current_user)' in content
    print('SPP MISSING_AUTH detection + fix OK')

# Test 4: Auto-fix secrets
with tempfile.TemporaryDirectory() as tmp:
    test_file = Path(tmp) / 'test.py'
    test_file.write_text('SECRET_KEY = "FAKE_SECRET_1"\nAPI_KEY = "FAKE_SECRET_2"\n')
    env = Path(tmp) / '.env.example'
    m, f, v = auto_fix_secrets(test_file, env)
    assert m == True and f == 2
    content = test_file.read_text()
    assert 'os.getenv' in content
    print('Auto-fix secrets OK')

print('ALL SMOKE TESTS PASSED')
print('Package is ready for PyPI/Docker release')