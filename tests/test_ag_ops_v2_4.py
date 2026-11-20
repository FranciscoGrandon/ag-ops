# Creado por Francisco Grandón Vergara
"""
Comprehensive verification suite for ag_ops.py v2.4.0 (P0-P3).
Covers zero-dependency enforcement, P0 test tampering controls, P1 performance
primitives, P2 semantic git anchoring & oscillation guards, and P3 batch
renegotiation & MUT001 hidden-mutation sensing.
"""

import ast
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
AG_OPS_PATH = REPO_ROOT / "ag_ops.py"

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import ag_ops  # noqa: E402


def _run_cli(
    args: List[str],
    cwd: Optional[pathlib.Path] = None,
    env_extra: Optional[Dict[str, str]] = None,
) -> Tuple[int, Dict[str, Any]]:
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    proc = subprocess.run(
        [sys.executable, str(AG_OPS_PATH), *args],
        cwd=str(cwd or REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    payload = (
        json.loads(proc.stdout)
        if proc.stdout.strip().startswith("{")
        else {"raw_stdout": proc.stdout, "raw_stderr": proc.stderr}
    )
    return proc.returncode, payload


def _git(repo: pathlib.Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=True,
    )
    return proc.stdout.strip()


def _init_git_repo(repo: pathlib.Path) -> str:
    repo.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "-b", "main", str(repo)], check=True, capture_output=True)
    _git(repo, "config", "user.name", "Test Bot")
    _git(repo, "config", "user.email", "testbot@example.com")
    (repo / "README.md").write_text("# Demo\n", encoding="utf-8")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "chore: init")
    return _git(repo, "rev-parse", "HEAD")


def _write_red_project(root: pathlib.Path, *, failing: bool = True) -> pathlib.Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text(
        f"def add(a: int, b: int) -> int:\n    return {'a - b' if failing else 'a + b'}\n",
        encoding="utf-8",
    )
    tests_dir = root / "tests"
    tests_dir.mkdir(exist_ok=True)
    (tests_dir / "test_app.py").write_text(
        "import pathlib\n"
        "import sys\n"
        "ROOT = str(pathlib.Path(__file__).resolve().parents[1])\n"
        "if ROOT not in sys.path:\n"
        "    sys.path.insert(0, ROOT)\n"
        "from app import add\n\n"
        "def test_add():\n    assert add(2, 3) == 5\n",
        encoding="utf-8",
    )
    return tests_dir


def test_zero_external_dependencies_stdlib_only() -> None:
    tree = ast.parse(AG_OPS_PATH.read_text(encoding="utf-8"), filename=str(AG_OPS_PATH))
    stdlib_names = set(sys.stdlib_module_names)
    imported: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported.append(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            imported.append(node.module.split(".")[0])
    non_stdlib = sorted(name for name in set(imported) if name not in stdlib_names and name != "__future__")
    assert non_stdlib == [], f"Forbidden non-stdlib imports detected in ag_ops.py: {non_stdlib}"


# =============================================================================
# P0 Tests: Config sealing, addopts, env sanitization, test execution count
# =============================================================================


@pytest.mark.parametrize(
    "config_name,content",
    [
        ("conftest.py", "def pytest_collection_modifyitems(items):\n    items.clear()\n"),
        ("pytest.ini", "[pytest]\naddopts = -p no:terminal\n"),
        ("pyproject.toml", '[tool.pytest.ini_options]\naddopts = "-q"\n'),
        ("sitecustomize.py", "print('tainted')\n"),
        ("usercustomize.py", "print('tainted')\n"),
    ],
)
def test_p0_root_config_manifest_detects_late_addition(
    tmp_path: pathlib.Path,
    config_name: str,
    content: str,
) -> None:
    tests_dir = _write_red_project(tmp_path, failing=True)
    cmd = f'"{sys.executable}" -m pytest'

    rc, res = _run_cli(["guard", "witness-red", "--test-dir", str(tests_dir), "--cmd", cmd, "--json"], cwd=tmp_path)
    assert rc == 0, res
    assert res["schema_version"] == "2.4"

    (tmp_path / "app.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    (tmp_path / config_name).write_text(content, encoding="utf-8")

    rc2, res2 = _run_cli(["guard", "verify-green", "--test-dir", str(tests_dir), "--cmd", cmd, "--json"], cwd=tmp_path)
    assert rc2 == 2, res2
    assert "ROOT_CONFIG_DRIFT" in res2["error"]
    assert any(config_name in c for c in res2["changes"]), res2


def test_p0_root_config_rejects_symlink_in_root(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    tests_dir = _write_red_project(tmp_path, failing=True)
    outside = tmp_path.parent / f"{tmp_path.name}_outside.py"
    outside.write_text("# external hook\n", encoding="utf-8")
    link_path = tmp_path / "conftest.py"

    symlink_created = False
    try:
        os.symlink(outside, link_path)
        symlink_created = True
    except OSError:
        symlink_created = False

    if symlink_created:
        cmd = f'"{sys.executable}" -m pytest'
        rc, res = _run_cli(["guard", "witness-red", "--test-dir", str(tests_dir), "--cmd", cmd, "--json"], cwd=tmp_path)
        assert rc == 1
        assert "Symlinks and junctions are forbidden" in res["error"]
    else:
        link_path.write_text("# fallback simulated symlink config\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(ag_ops, "_is_symlink_or_junction", lambda p: p.name == "conftest.py")
        with pytest.raises(ValueError, match="Symlinks and junctions are forbidden"):
            ag_ops._collect_root_config_manifest(tests_dir)


def test_p0_addopts_inspection_blocks_evasive_flags_and_allows_cacheprovider(tmp_path: pathlib.Path) -> None:
    tests_dir = _write_red_project(tmp_path, failing=True)
    cmd = f'"{sys.executable}" -m pytest'

    # Allowed benign addopts
    (tmp_path / "pytest.ini").write_text("[pytest]\naddopts = -p no:cacheprovider\n", encoding="utf-8")
    rc, res = _run_cli(["guard", "witness-red", "--test-dir", str(tests_dir), "--cmd", cmd, "--json"], cwd=tmp_path)
    assert rc == 0, res

    # Explicit --forbid-addopts blocks custom forbidden flag
    (tmp_path / "pyproject.toml").write_text('[tool.pytest.ini_options]\naddopts = ["-p", "no:cov"]\n', encoding="utf-8")
    rc_forbid, res_forbid = _run_cli(
        [
            "guard", "witness-red",
            "--test-dir", str(tests_dir),
            "--cmd", cmd,
            "--forbid-addopts", "-p no:cov",
            "--json",
        ],
        cwd=tmp_path,
    )
    assert rc_forbid == 2
    assert "UNSAFE_PYTEST_ADDOPTS" in res_forbid["error"]

    # Always-blocked evasive flags
    (tmp_path / "pyproject.toml").unlink()
    for bad_addopts in ["--collect-only", "--co -q", "-k test_missing", "--ignore=tests", "--ignore-glob=*app*"]:
        (tmp_path / "pytest.ini").write_text(f"[pytest]\naddopts = {bad_addopts}\n", encoding="utf-8")
        rc_bad, res_bad = _run_cli(
            ["guard", "witness-red", "--test-dir", str(tests_dir), "--cmd", cmd, "--json"],
            cwd=tmp_path,
        )
        assert rc_bad == 2, f"Expected failure for addopts={bad_addopts}, got {res_bad}"
        assert "UNSAFE_PYTEST_ADDOPTS" in res_bad["error"]


def test_p0_env_sanitization_and_allow_env_passthrough(tmp_path: pathlib.Path) -> None:
    tests_dir = _write_red_project(tmp_path, failing=True)
    cmd = f'"{sys.executable}" -m pytest'

    for var_name, var_val in [("PYTEST_ADDOPTS", "--collect-only"), ("PYTHONSTARTUP", "evil.py")]:
        rc, res = _run_cli(
            ["guard", "witness-red", "--test-dir", str(tests_dir), "--cmd", cmd, "--json"],
            cwd=tmp_path,
            env_extra={var_name: var_val},
        )
        assert rc == 2
        assert "ENV_TAINT_DETECTED" in res["error"]

    startup = tmp_path / "startup.py"
    startup.write_text("X_PASSTHROUGH_CHECK = 1\n", encoding="utf-8")
    # Seal strict (no passthrough) during witness-red, then reject --allow-env-passthrough escalation during verify-green
    rc_red_strict, res_red_strict = _run_cli(
        ["guard", "witness-red", "--test-dir", str(tests_dir), "--cmd", cmd, "--json"],
        cwd=tmp_path,
    )
    assert rc_red_strict == 0, res_red_strict

    (tmp_path / "app.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    rc_relax, res_relax = _run_cli(
        ["guard", "verify-green", "--test-dir", str(tests_dir), "--cmd", cmd, "--allow-env-passthrough", "--json"],
        cwd=tmp_path,
        env_extra={"PYTHONSTARTUP": str(startup)},
    )
    assert rc_relax == 2, res_relax
    assert "ENV_TAINT_DETECTED" in res_relax["error"]

    # Explicit --allow-env-passthrough at witness-red + verify-green succeeds cleanly
    (tmp_path / "app.py").write_text("def add(a: int, b: int) -> int:\n    return a - b\n", encoding="utf-8")
    rc_pt_red, res_pt_red = _run_cli(
        ["guard", "witness-red", "--test-dir", str(tests_dir), "--cmd", cmd, "--allow-env-passthrough", "--json"],
        cwd=tmp_path,
        env_extra={"PYTHONSTARTUP": str(startup)},
    )
    assert rc_pt_red == 0, res_pt_red
    receipt_pt = json.loads(pathlib.Path(res_pt_red["receipt_file"]).read_text(encoding="utf-8"))
    assert receipt_pt["env_policy"]["passthrough_allowed"] is True


def test_p0_zero_tests_and_test_count_regression_and_v23_legacy_receipt(tmp_path: pathlib.Path) -> None:
    tests_dir = _write_red_project(tmp_path, failing=True)
    cmd = f'"{sys.executable}" -m pytest'

    rc, res = _run_cli(["guard", "witness-red", "--test-dir", str(tests_dir), "--cmd", cmd, "--json"], cwd=tmp_path)
    assert rc == 0, res
    assert res["witnessed_test_count"] == 1

    # Zero tests executed via immediate process exit with exit code 0 in prod code
    (tmp_path / "app.py").write_text("import os\nos._exit(0)\n", encoding="utf-8")
    rc_zero, res_zero = _run_cli(["guard", "verify-green", "--test-dir", str(tests_dir), "--cmd", cmd, "--json"], cwd=tmp_path)
    assert rc_zero == 2, res_zero
    assert "ZERO_TESTS_EXECUTED" in res_zero["error"]

    # End-to-end TEST_COUNT_REGRESSION via parametrized count shrinking from 2 -> 1
    reg_dir = tmp_path / "reg_proj"
    reg_dir.mkdir()
    reg_tests = reg_dir / "tests"
    reg_tests.mkdir()
    (reg_dir / "app.py").write_text("def get_cases():\n    return [1, -1]\n", encoding="utf-8")
    (reg_tests / "test_reg.py").write_text(
        "import pathlib, sys, pytest\n"
        "ROOT = str(pathlib.Path(__file__).resolve().parents[1])\n"
        "if ROOT not in sys.path:\n    sys.path.insert(0, ROOT)\n"
        "from app import get_cases\n\n"
        "@pytest.mark.parametrize('x', get_cases())\n"
        "def test_positive(x):\n    assert x > 0\n",
        encoding="utf-8",
    )
    rc_red2, res_red2 = _run_cli(["guard", "witness-red", "--test-dir", str(reg_tests), "--cmd", cmd, "--json"], cwd=reg_dir)
    assert rc_red2 == 0, res_red2
    assert res_red2["witnessed_test_count"] == 2

    (reg_dir / "app.py").write_text("def get_cases():\n    return [1]\n", encoding="utf-8")
    rc_reg, res_reg = _run_cli(["guard", "verify-green", "--test-dir", str(reg_tests), "--cmd", cmd, "--json"], cwd=reg_dir)
    assert rc_reg == 2, res_reg
    assert "TEST_COUNT_REGRESSION" in res_reg["error"]

    # Legacy v2.3 receipt without schema_version/root_config_manifest/env_policy parses AND verifies green
    (reg_dir / "app.py").write_text("def get_cases():\n    return [1, 2]\n", encoding="utf-8")
    receipt_path = ag_ops._receipt_path_for_target(ag_ops._resolve_state_dir(reg_tests, None), reg_tests)
    receipt_data = json.loads(receipt_path.read_text(encoding="utf-8"))
    for v24_key in ("schema_version", "root_config_manifest", "root_config_base", "env_policy", "recent_tree_hashes"):
        receipt_data.pop(v24_key, None)
    receipt_path.write_text(json.dumps(receipt_data, indent=2), encoding="utf-8")

    parsed, err = ag_ops._parse_guard_receipt(receipt_path)
    assert err is None and parsed is not None
    assert parsed["version"] == 2

    rc_leg, res_leg = _run_cli(["guard", "verify-green", "--test-dir", str(reg_tests), "--cmd", cmd, "--json"], cwd=reg_dir)
    assert rc_leg == 0, res_leg
    assert res_leg["ok"] is True


# =============================================================================
# P1 Tests: CRLF streaming hash, GitBatchReader, Stat cache & anti-racy guards
# =============================================================================


def test_p1_sha256_crlf_boundary_64kb_and_nul_binary(tmp_path: pathlib.Path) -> None:
    payload_crlf = (b"a" * 65535) + b"\r\n" + (b"b" * 100) + b"\r\n"
    payload_lf = (b"a" * 65535) + b"\n" + (b"b" * 100) + b"\n"

    f_crlf = tmp_path / "boundary_crlf.txt"
    f_lf = tmp_path / "boundary_lf.txt"
    f_crlf.write_bytes(payload_crlf)
    f_lf.write_bytes(payload_lf)

    assert ag_ops._sha256_file(f_crlf, normalize_eol=True) == hashlib.sha256(payload_lf).hexdigest()
    assert ag_ops._sha256_file(f_lf, normalize_eol=True) == ag_ops._sha256_file(f_crlf, normalize_eol=True)
    assert ag_ops._sha256_file(f_crlf, normalize_eol=False) == hashlib.sha256(payload_crlf).hexdigest()

    bin_bytes = b"\x00\x01\r\n" * 5
    f_bin = tmp_path / "binary.dat"
    f_bin.write_bytes(bin_bytes)
    assert ag_ops._sha256_file(f_bin, normalize_eol=True) == hashlib.sha256(bin_bytes).hexdigest()


def test_p1_git_batch_reader_utf8_and_missing(tmp_path: pathlib.Path) -> None:
    repo = tmp_path / "repo_batch"
    _init_git_repo(repo)
    utf8_name = "módulo_ñ.py"
    (repo / utf8_name).write_text("# saludo: árboleda\nX = 1\n", encoding="utf-8")
    _git(repo, "add", utf8_name)
    _git(repo, "commit", "-m", "feat: utf8 file")
    head_sha = _git(repo, "rev-parse", "HEAD")

    with ag_ops.GitBatchReader(repo) as reader:
        text = reader.read_text(head_sha, utf8_name)
        assert text is not None
        assert "saludo: árboleda" in text
        assert reader.read_text(head_sha, "does_not_exist.py") is None


def test_p1_stat_cache_hits_and_strict_no_cache_clock_rollback(tmp_path: pathlib.Path) -> None:
    sample = tmp_path / "clean_mod.py"
    sample.write_text("# Creado por Francisco Grandón Vergara\nX = 42\n", encoding="utf-8")
    past_ns = time.time_ns() - 2_000_000_000
    os.utime(sample, ns=(past_ns, past_ns))
    cache_file = tmp_path / ".ag_state" / "stat_cache.json"

    rc1, res1 = _run_cli(["ast-lint", str(sample), "--author", "Francisco Grandón Vergara", "--json"])
    assert rc1 == 0, res1
    assert res1["cache_hits"] == 0
    assert cache_file.is_file()

    rc2, res2 = _run_cli(["ast-lint", str(sample), "--author", "Francisco Grandón Vergara", "--json"])
    assert rc2 == 0, res2
    assert res2["cache_hits"] == 1

    # Disabled under --no-cache and --strict
    rc_nc, res_nc = _run_cli(["ast-lint", str(sample), "--author", "Francisco Grandón Vergara", "--no-cache", "--json"])
    assert rc_nc == 0 and res_nc["cache_hits"] == 0

    rc_strict, res_strict = _run_cli(["ast-lint", str(sample), "--author", "Francisco Grandón Vergara", "--strict", "--json"])
    assert rc_strict == 0 and res_strict["cache_hits"] == 0

    # Clock rollback / future mtime guard invalidates cache entry instead of serving stale hit
    future_ns = time.time_ns() + 60_000_000_000
    os.utime(sample, ns=(future_ns, future_ns))
    rc_fut, res_fut = _run_cli(["ast-lint", str(sample), "--author", "Francisco Grandón Vergara", "--json"])
    assert rc_fut == 0, res_fut
    assert res_fut["cache_hits"] == 0


# =============================================================================
# P2 Tests: --base-ref / merge-base, k-cycle oscillation, check-scope
# =============================================================================


def test_p2_base_ref_forward_commit_vs_diverged_vs_spec_modified(tmp_path: pathlib.Path) -> None:
    repo = tmp_path / "repo_p2"
    _init_git_repo(repo)
    (repo / "SPEC_A.md").write_text("# Spec A v1\n", encoding="utf-8")
    (repo / "SPEC_B.md").write_text("# Spec B v1\n", encoding="utf-8")
    _git(repo, "add", "SPEC_A.md", "SPEC_B.md")
    _git(repo, "commit", "-m", "docs: baseline specs")
    base_sha = _git(repo, "rev-parse", "HEAD")

    tests_dir = _write_red_project(repo, failing=True)
    _git(repo, "add", "app.py", "tests/test_app.py")
    _git(repo, "commit", "-m", "test: add failing red baseline")
    red_sha = _git(repo, "rev-parse", "HEAD")

    cmd = f'"{sys.executable}" -m pytest'
    rc_red, res_red = _run_cli(
        ["guard", "witness-red", "--test-dir", str(tests_dir), "--cmd", cmd, "--base-ref", base_sha, "--json"],
        cwd=repo,
    )
    assert rc_red == 0, res_red
    assert res_red["base_ref"] == base_sha

    # Forward commit fixing prod code -> merge-base is_ancestor allows verification
    (repo / "app.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-m", "fix: implement add")

    rc_green, res_green = _run_cli(["guard", "verify-green", "--test-dir", str(tests_dir), "--cmd", cmd, "--json"], cwd=repo)
    assert rc_green == 0, res_green

    # Modifying cited spec since base_sha blocks guard renegotiate with SPEC_MODIFIED_SINCE_BASE
    (repo / "app.py").write_text("def add(a: int, b: int) -> int:\n    return a - b\n", encoding="utf-8")
    (repo / "SPEC_A.md").write_text("# Spec A weakened after baseline\n", encoding="utf-8")
    _git(repo, "add", "app.py", "SPEC_A.md")
    _git(repo, "commit", "-m", "docs: modify cited spec")

    rc_spec, res_spec = _run_cli(
        [
            "guard", "renegotiate",
            "--test-dir", str(tests_dir),
            "--cmd", cmd,
            "--base-ref", base_sha,
            "--reason", "Resolve conflict",
            "--witness-type", "spec-collision",
            "--conflict-a", "SPEC_A.md:1",
            "--conflict-b", "SPEC_B.md:1",
            "--json",
        ],
        cwd=repo,
    )
    assert rc_spec == 2, res_spec
    assert "SPEC_MODIFIED_SINCE_BASE" in res_spec["error"]

    # Non-ancestor HEAD rewrite without --base-ref fails, and --allow-head-move audits HEAD_MOVE_ALLOWED
    _git(repo, "reset", "--hard", base_sha)
    tests_dir = _write_red_project(repo, failing=True)
    _git(repo, "add", "app.py", "tests/test_app.py")
    _git(repo, "commit", "-m", "test: fresh baseline")
    rc_w2, res_w2 = _run_cli(["guard", "witness-red", "--test-dir", str(tests_dir), "--cmd", cmd, "--json"], cwd=repo)
    assert rc_w2 == 0, res_w2
    (repo / "app.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "--amend", "-m", "feat: amended head break")
    amended_sha = _git(repo, "rev-parse", "HEAD")
    assert amended_sha != red_sha

    rc_div, res_div = _run_cli(["guard", "verify-green", "--test-dir", str(tests_dir), "--cmd", cmd, "--json"], cwd=repo)
    assert rc_div == 2, res_div
    assert "HEAD_MOVED_DURING_RED_PHASE" in res_div["error"]

    rc_allow, res_allow = _run_cli(
        ["guard", "verify-green", "--test-dir", str(tests_dir), "--cmd", cmd, "--allow-head-move", "--json"],
        cwd=repo,
    )
    assert rc_allow == 0, res_allow
    receipt_path = ag_ops._receipt_path_for_target(ag_ops._resolve_state_dir(tests_dir, None), tests_dir)
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    assert any(c.get("event") == "HEAD_MOVE_ALLOWED" for c in receipt["collisions"])


def test_p2_k_cycle_oscillation_detection_in_guard_and_state(tmp_path: pathlib.Path) -> None:
    repo = tmp_path / "repo_cyc"
    _init_git_repo(repo)
    tests_dir = _write_red_project(repo, failing=True)
    cmd = f'"{sys.executable}" -m pytest'

    # 3-cycle A -> B -> C -> A across witness-red + failing verify-green attempts
    (repo / "app.py").write_text("def add(a, b):\n    return 0\n", encoding="utf-8")  # State A
    rc_a, res_a = _run_cli(["guard", "witness-red", "--test-dir", str(tests_dir), "--cmd", cmd, "--json"], cwd=repo)
    assert rc_a == 0, res_a

    (repo / "app.py").write_text("def add(a, b):\n    return 1\n", encoding="utf-8")  # State B
    rc_b, res_b = _run_cli(["guard", "verify-green", "--test-dir", str(tests_dir), "--cmd", cmd, "--json"], cwd=repo)
    assert rc_b == 1 and "TEST_STILL_FAILING" in res_b["error"]

    (repo / "app.py").write_text("def add(a, b):\n    return 2\n", encoding="utf-8")  # State C
    rc_c, res_c = _run_cli(["guard", "verify-green", "--test-dir", str(tests_dir), "--cmd", cmd, "--json"], cwd=repo)
    assert rc_c == 1 and "TEST_STILL_FAILING" in res_c["error"]

    (repo / "app.py").write_text("def add(a, b):\n    return 0\n", encoding="utf-8")  # Reverted to State A
    rc_osc, res_osc = _run_cli(["guard", "verify-green", "--test-dir", str(tests_dir), "--cmd", cmd, "--json"], cwd=repo)
    assert rc_osc == 2, res_osc
    assert "OSCILLATION_CYCLE_DETECTED" in res_osc["error"]
    assert res_osc["cycle_length"] == 3

    # State write oscillation detection & --replace slug rename allowed
    state_dir = tmp_path / "ag_state_cyc"
    art = tmp_path / "artifact.txt"
    art.write_text("state1\n", encoding="utf-8")
    assert _run_cli(
        ["state", "write", "--dir", str(state_dir), "--step", "1", "--name", "a", "--status", "EN_PROGRESO", "--summary", "s1", "--artifacts", str(art), "--json"],
        cwd=tmp_path,
    )[0] == 0

    art.write_text("state2\n", encoding="utf-8")
    assert _run_cli(
        ["state", "write", "--dir", str(state_dir), "--step", "2", "--name", "b", "--status", "EN_PROGRESO", "--summary", "s2", "--artifacts", str(art), "--json"],
        cwd=tmp_path,
    )[0] == 0

    art.write_text("state1\n", encoding="utf-8")
    rc_st_osc, res_st_osc = _run_cli(
        ["state", "write", "--dir", str(state_dir), "--step", "3", "--name", "c", "--status", "EN_PROGRESO", "--summary", "s3", "--artifacts", str(art), "--json"],
        cwd=tmp_path,
    )
    assert rc_st_osc == 2, res_st_osc
    assert "OSCILLATION_CYCLE_DETECTED" in res_st_osc["error"]

    art.write_text("state2\n", encoding="utf-8")
    rc_rep, res_rep = _run_cli(
        ["state", "write", "--dir", str(state_dir), "--step", "2", "--name", "b_renamed", "--status", "COMPLETADO", "--summary", "renamed", "--artifacts", str(art), "--replace", "--json"],
        cwd=tmp_path,
    )
    assert rc_rep == 0, res_rep


def test_p2_guard_check_scope_modes(tmp_path: pathlib.Path) -> None:
    repo = tmp_path / "repo_scope"
    _init_git_repo(repo)
    rules_dir = repo / ".gemini" / "rules"
    rules_dir.mkdir(parents=True)

    # EMPTY
    rc_empty, res_empty = _run_cli(["guard", "check-scope", "--repo", str(repo), "--base", "main", "--rule-paths", ".gemini/rules", "--json"])
    assert rc_empty == 0 and res_empty["scope"] == "EMPTY"

    # RULES_ONLY (dot-directory regression: .gemini/rules and ./.gemini/rules)
    _git(repo, "checkout", "-b", "feat-scope")
    (rules_dir / "policy.md").write_text("# rule\n", encoding="utf-8")
    _git(repo, "add", ".gemini/rules/policy.md")
    _git(repo, "commit", "-m", "docs: add policy")

    rc_rules, res_rules = _run_cli(["guard", "check-scope", "--repo", str(repo), "--base", "main", "--rule-paths", ".gemini/rules", "--json"])
    assert rc_rules == 0 and res_rules["scope"] == "RULES_ONLY", res_rules
    assert res_rules["rule_files"] == [".gemini/rules/policy.md"]

    rc_rules_dot, res_rules_dot = _run_cli(["guard", "check-scope", "--repo", str(repo), "--base", "main", "--rule-paths", "./.gemini/rules/", "--json"])
    assert rc_rules_dot == 0 and res_rules_dot["scope"] == "RULES_ONLY", res_rules_dot

    # MIXED_SCOPE_VIOLATION
    (repo / "service.py").write_text("X = 1\n", encoding="utf-8")
    _git(repo, "add", "service.py")
    _git(repo, "commit", "-m", "feat: add service alongside rule")
    rc_mix, res_mix = _run_cli(["guard", "check-scope", "--repo", str(repo), "--base", "main", "--rule-paths", ".gemini/rules", "--json"])
    assert rc_mix == 2, res_mix
    assert "MIXED_SCOPE_VIOLATION" in res_mix["error"]

    # CODE_ONLY on separate branch
    _git(repo, "checkout", "main")
    _git(repo, "checkout", "-b", "feat-code-only")
    (repo / "code.py").write_text("Y = 2\n", encoding="utf-8")
    _git(repo, "add", "code.py")
    _git(repo, "commit", "-m", "feat: code only")
    rc_code, res_code = _run_cli(["guard", "check-scope", "--repo", str(repo), "--base", "main", "--rule-paths", ".gemini/rules", "--json"])
    assert rc_code == 0 and res_code["scope"] == "CODE_ONLY", res_code


# =============================================================================
# P3 Tests: guard renegotiate --batch & MUT001 hidden mutation sensor
# =============================================================================


def test_p3_guard_renegotiate_batch_atomic_success_and_rollback(tmp_path: pathlib.Path) -> None:
    repo = tmp_path / "repo_batch_ren"
    _init_git_repo(repo)
    p1 = _write_red_project(repo / "svc_a", failing=True)
    p2 = _write_red_project(repo / "svc_b", failing=True)
    (repo / "SPEC_A.md").write_text("Spec A\n", encoding="utf-8")
    (repo / "SPEC_B.md").write_text("Spec B\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-m", "feat: initial services")

    state_dir = repo / ".ag_state"
    cmd_a = f'"{sys.executable}" -m pytest "{p1}"'
    cmd_b = f'"{sys.executable}" -m pytest "{p2}"'
    assert _run_cli(["guard", "witness-red", "--test-dir", str(p1), "--cmd", cmd_a, "--state-dir", str(state_dir), "--json"], cwd=repo / "svc_a")[0] == 0
    assert _run_cli(["guard", "witness-red", "--test-dir", str(p2), "--cmd", cmd_b, "--state-dir", str(state_dir), "--json"], cwd=repo / "svc_b")[0] == 0

    rec_a = ag_ops._receipt_path_for_target(state_dir, p1)
    rec_b = ag_ops._receipt_path_for_target(state_dir, p2)
    orig_a = rec_a.read_text(encoding="utf-8")
    orig_b = rec_b.read_text(encoding="utf-8")

    # Passing target 2 must fail atomically with COOPERATIVE_RENEGOTIATION and leave both receipts untouched
    (repo / "svc_b" / "app.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n", encoding="utf-8")
    manifest_fail = repo / "batch_fail.json"
    manifest_fail.write_text(
        json.dumps([
            {"test_dir": str(p1), "cmd": cmd_a},
            {"test_dir": str(p2), "cmd": cmd_b},
        ]),
        encoding="utf-8",
    )
    rc_bf, res_bf = _run_cli(
        [
            "guard", "renegotiate",
            "--batch", str(manifest_fail),
            "--reason", "Split shared contract",
            "--witness-type", "spec-collision",
            "--conflict-a", "SPEC_A.md:1",
            "--conflict-b", "SPEC_B.md:1",
            "--state-dir", str(state_dir),
            "--json",
        ],
        cwd=repo,
    )
    assert rc_bf == 1, res_bf
    assert "COOPERATIVE_RENEGOTIATION" in res_bf["error"]
    assert rec_a.read_text(encoding="utf-8") == orig_a
    assert rec_b.read_text(encoding="utf-8") == orig_b

    # Missing constructive witness on batch also aborts before touching receipts
    (repo / "svc_b" / "app.py").write_text("def add(a: int, b: int) -> int:\n    return a - b\n", encoding="utf-8")
    rc_nw, res_nw = _run_cli(
        [
            "guard", "renegotiate",
            "--batch", str(manifest_fail),
            "--reason", "No witness provided",
            "--require-witness",
            "--state-dir", str(state_dir),
            "--json",
        ],
        cwd=repo,
    )
    assert rc_nw == 1, res_nw
    assert rec_a.read_text(encoding="utf-8") == orig_a
    assert rec_b.read_text(encoding="utf-8") == orig_b

    # Atomic dict-manifest success sharing one SCAR-PROC-150 witness and batch_id
    manifest_ok = repo / "batch_ok.json"
    manifest_ok.write_text(
        json.dumps({
            "reason": "Re-align both service suites after SPEC collision",
            "witness_type": "spec-collision",
            "conflict_a": "SPEC_A.md:1",
            "conflict_b": "SPEC_B.md:1",
            "targets": [
                {"test_dir": str(p1), "cmd": cmd_a},
                {"test_dir": str(p2), "cmd": cmd_b},
            ],
        }),
        encoding="utf-8",
    )
    rc_bo, res_bo = _run_cli(
        ["guard", "renegotiate", "--batch", str(manifest_ok), "--state-dir", str(state_dir), "--json"],
        cwd=repo,
    )
    assert rc_bo == 0, res_bo
    assert res_bo["status"] == "RENEGOTIATED_RED_BATCH"
    assert res_bo["targets_count"] == 2
    batch_id = res_bo["batch_id"]
    data_a = json.loads(rec_a.read_text(encoding="utf-8"))
    data_b = json.loads(rec_b.read_text(encoding="utf-8"))
    assert data_a["batch_id"] == batch_id
    assert data_b["batch_id"] == batch_id
    assert data_a["status"] == "RENEGOTIATED_RED"


def test_p3_mut001_detects_all_constructs_and_auditable_justifications(tmp_path: pathlib.Path) -> None:
    mut_file = tmp_path / "mut_sample.py"
    mut_file.write_text(
        "# Creado por Francisco Grandón Vergara\n"
        "COUNTER = 0\n\n"
        "class Service:\n"
        "    def __init__(self) -> None:\n"
        "        self.items = []\n"
        "        self.cache = {}\n"
        "        self.count = 0\n\n"
        "    def get_via_assign(self):\n"
        "        self.count = 1\n"
        "        return self.count\n\n"
        "    def is_via_augassign(self):\n"
        "        self.count += 1\n"
        "        return True\n\n"
        "    def has_via_annassign(self):\n"
        "        self.count: int = 2\n"
        "        return True\n\n"
        "    def validate_via_delete(self):\n"
        "        del self.cache['k']\n"
        "        return True\n\n"
        "    def get_via_global(self):\n"
        "        global COUNTER\n"
        "        COUNTER += 1\n"
        "        return COUNTER\n\n"
        "    def get_via_method_calls(self):\n"
        "        self.items.append(1)\n"
        "        self.cache.update({'a': 1})\n"
        "        return list(self.items)\n\n"
        "    def get_justified_valid(self):\n"
        "        self.cache['memo'] = 99  # ag_ops: allow-mutation: lazy memoized lookup\n"
        "        return 99\n\n"
        "    def get_justified_empty_reason_rejected(self):\n"
        "        self.count = 5  # ag_ops: allow-mutation:\n"
        "        return self.count\n\n"
        "    def get_ignores_nested_scope(self):\n"
        "        def _helper():\n"
        "            self.count = 10\n"
        "        class _Inner:\n"
        "            def run(self_inner):\n"
        "                self_inner.x = 1\n"
        "        fn = lambda: self.items.append(2)\n"
        "        return (_helper, _Inner, fn)\n",
        encoding="utf-8",
    )

    rc_warn, res_warn = _run_cli(["ast-lint", str(mut_file), "--author", "Francisco Grandón Vergara", "--json"])
    assert rc_warn == 0, res_warn
    assert res_warn["violations_count"] == 0
    warn_funcs = {w["function"] for w in res_warn["warnings"]}
    assert warn_funcs == {
        "get_via_assign",
        "is_via_augassign",
        "has_via_annassign",
        "validate_via_delete",
        "get_via_global",
        "get_via_method_calls",
        "get_justified_empty_reason_rejected",
    }
    assert len(res_warn["warnings"]) == 8
    assert res_warn["suppressed_mutations_count"] == 1
    assert res_warn["suppressed_mutations"][0]["function"] == "get_justified_valid"
    assert res_warn["suppressed_mutations"][0]["justification"] == "lazy memoized lookup"

    rc_strict, res_strict = _run_cli(["ast-lint", str(mut_file), "--author", "Francisco Grandón Vergara", "--strict", "--json"])
    assert rc_strict == 1, res_strict
    assert res_strict["warnings_count"] == 0
    assert res_strict["violations_count"] == 8
    assert all(v["rule"] == "MUT001" for v in res_strict["violations"])
