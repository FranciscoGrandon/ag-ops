#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Creado por Francisco Grandón Vergara
"""
Suite de auditoría verificable (stdlib unittest) para ag_ops_v2.py.
Cubre los 5 subcomandos (guard, distill, state, ast-lint, regret-mine) y los 12 defectos corregidos.
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from typing import Any, Dict, List, Optional, Tuple

def git_cmd(args: List[str], cwd: Optional[pathlib.Path] = None, **kwargs) -> subprocess.CompletedProcess:
    git_bin = shutil.which("git") or r"D:\GIT\MinGit-2.56.0.4-64-bit\cmd\git.exe"
    cmd = [git_bin if a == "git" else a for a in args]
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, **kwargs)

AG_OPS_PATH = os.environ.get(
    "AG_OPS_TARGET",
    str((pathlib.Path(__file__).parent / "ag_ops_v2.py").resolve()),
)


def run_cli(*args: str, cwd: Optional[pathlib.Path] = None) -> Tuple[int, Dict[str, Any], str]:
    cmd = [sys.executable, AG_OPS_PATH, *args, "--json"]
    proc = subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True)
    payload: Dict[str, Any] = {}
    if proc.stdout.strip():
        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError:
            payload = {"raw_stdout": proc.stdout}
    return proc.returncode, payload, proc.stderr


class TestAgOpsV2Audit(unittest.TestCase):
    def test_01_guard_ancestor_state_dir(self) -> None:
        """Verifica que --state-dir como ancestro de --test-dir no excluya los archivos de prueba."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            tests_dir = tmp_path / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_unit.py").write_text("def test_fail(): assert False\n", encoding="utf-8")

            rc, data, _ = run_cli(
                "guard", "witness-red",
                "--test-dir", str(tests_dir),
                "--state-dir", str(tmp_path),
                "--cmd", "false",
            )
            self.assertEqual(rc, 0, msg=f"Falló witness-red con state-dir ancestro: {data}")
            self.assertTrue(data.get("ok"))
            self.assertEqual(data.get("files_count"), 1)

    def test_02_renegotiate_timestamp_correlated_in_regret_mine(self) -> None:
        """Verifica que el timestamp de guard renegotiate se registre y correlacione en regret-mine."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            git_cmd(["git", "init", str(tmp_path)], check=True, capture_output=True)
            git_cmd(["git", "-C", str(tmp_path), "config", "user.email", "audit@example.com"], check=True)
            git_cmd(["git", "-C", str(tmp_path), "config", "user.name", "Auditor"], check=True)

            tests_dir = tmp_path / "tests"
            tests_dir.mkdir()
            tfile = tests_dir / "test_a.py"
            tfile.write_text("assert False\n", encoding="utf-8")
            app = tmp_path / "app.py"
            app.write_text("def calc():\n    return 1\n", encoding="utf-8")

            rc1, _, _ = run_cli(
                "guard", "witness-red",
                "--test-dir", str(tests_dir),
                "--state-dir", str(tmp_path / ".ag_state"),
                "--cmd", "false",
            )
            self.assertEqual(rc1, 0)
            time.sleep(1.1)

            git_cmd(["git", "-C", str(tmp_path), "add", "app.py"], check=True)
            git_cmd(["git", "-C", str(tmp_path), "commit", "-m", "initial calc"], check=True, capture_output=True)
            time.sleep(1.1)

            tfile.write_text("assert 1 == 2\n", encoding="utf-8")
            rc2, ren_data, _ = run_cli(
                "guard", "renegotiate",
                "--test-dir", str(tests_dir),
                "--state-dir", str(tmp_path / ".ag_state"),
                "--cmd", "false",
                "--reason", "contract updated",
            )
            self.assertEqual(rc2, 0)
            self.assertEqual(ren_data.get("status"), "RENEGOTIATED_RED")
            time.sleep(1.1)

            app.write_text("def calc():\n    return 2\n", encoding="utf-8")
            git_cmd(["git", "-C", str(tmp_path), "add", "app.py"], check=True)
            git_cmd(["git", "-C", str(tmp_path), "commit", "-m", "update calc output"], check=True, capture_output=True)

            rc3, rm_data, _ = run_cli("regret-mine", "--repo", str(tmp_path))
            self.assertEqual(rc3, 0)
            self.assertEqual(rm_data.get("regret_pairs_count"), 1, msg=f"No correlacionó renegotiate: {rm_data}")
            self.assertIn("GUARD_COLLISION_RECEIPT", rm_data["regret_pairs"][0]["asymmetry_signals"])

    def test_03_ast_lint_from_unittest_import_mock_and_ttk_style(self) -> None:
        """Verifica que 'from unittest import mock' dispare PATH002 y 'ttk.Style(bg=...)' no dispare falso positivo TK002."""
        with tempfile.TemporaryDirectory() as tmp:
            prod_file = pathlib.Path(tmp) / "service.py"
            prod_file.write_text(
                "from unittest import mock\n"
                "from tkinter.ttk import Style, Button as TtkBtn\n"
                "s = Style(bg='red')\n"
                "b = TtkBtn(bg='blue')\n",
                encoding="utf-8",
            )
            rc, data, _ = run_cli("ast-lint", str(prod_file))
            self.assertEqual(rc, 1)
            rules = [(v["rule"], v["line"], v["message"]) for v in data.get("violations", [])]
            self.assertTrue(any(r == "PATH002" and line == 1 for r, line, _ in rules), msg=f"Faltó PATH002: {rules}")
            self.assertFalse(any(r == "TK002" and line == 3 for r, line, _ in rules), msg=f"Falso positivo TK002 en Style: {rules}")
            self.assertTrue(any(r == "TK002" and line == 4 and "ttk.Button" in msg for r, line, msg in rules))

    def test_04_distill_preserves_all_lines_when_under_max_lines(self) -> None:
        """Verifica que distill no descarte líneas iniciales ni agregue líneas vacías sintéticas cuando total_lines <= max_lines."""
        with tempfile.TemporaryDirectory() as tmp:
            cmd = f'"{sys.executable}" -c "import sys; [print(f\'line {{i}}\' if i != 5 else \'RuntimeError: boom\') for i in range(8)]; sys.exit(1)"'
            rc, data, _ = run_cli("distill", "--cmd", cmd, "--max-lines", "35", "--log-dir", tmp)
            self.assertEqual(rc, 1)
            self.assertEqual(data.get("total_lines"), 8)
            self.assertEqual(data.get("distilled_lines"), 8)
            self.assertEqual(data["critical_delta"][0], "line 0")
            self.assertEqual(data["critical_delta"][5], "RuntimeError: boom")
            self.assertEqual(data["critical_delta"][7], "line 7")

    def test_05_dot_linter_chained_edges_comments_and_line_numbers(self) -> None:
        """Verifica transiciones encadenadas (A -> B -> C), ignorado de comentarios y números de línea reales en DOT."""
        with tempfile.TemporaryDirectory() as tmp:
            dot_file = pathlib.Path(tmp) / "machine.dot"
            dot_file.write_text(
                "digraph G {\n"
                "  /*\n"
                "  Fetching -> Error [label=\"commented\"];\n"
                "  */\n"
                "  // Fetching -> Cancelled [label=\"commented\"];\n"
                "  Init -> Fetching -> Done;\n"
                "  OrphanState -> Done;\n"
                "}\n",
                encoding="utf-8",
            )
            rc, data, _ = run_cli("ast-lint", str(dot_file))
            self.assertEqual(rc, 1)
            by_rule = {v["rule"]: v for v in data.get("violations", [])}
            self.assertNotIn("DOT001", by_rule)
            self.assertIn("DOT002", by_rule)
            self.assertEqual(by_rule["DOT002"]["line"], 7)
            self.assertIn("SCAR-PROC-152", by_rule)
            self.assertEqual(by_rule["SCAR-PROC-152"]["line"], 6)
            self.assertIn("SCAR-ASYNC-01", by_rule)
            self.assertEqual(by_rule["SCAR-ASYNC-01"]["line"], 6)

    def test_06_and_07_constructive_witness_validation(self) -> None:
        """Verifica rechazo de archivos vacíos (0 líneas) y etiquetas/anclas duplicadas o vacías en arch-fork."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            tdir = tmp_path / "tests"
            tdir.mkdir()
            (tdir / "test_a.py").write_text("assert False\n", encoding="utf-8")
            empty_file = tmp_path / "empty.py"
            empty_file.write_text("", encoding="utf-8")
            valid_file = tmp_path / "valid.py"
            valid_file.write_text("a = 1\nb = 2\n", encoding="utf-8")

            rc_empty, data_empty, _ = run_cli(
                "guard", "renegotiate",
                "--test-dir", str(tdir),
                "--cmd", "false",
                "--reason", "collision",
                "--witness-type", "spec-collision",
                "--conflict-a", f"{empty_file}:1",
                "--conflict-b", f"{valid_file}:1",
            )
            self.assertEqual(rc_empty, 1)
            self.assertIn("empty (0 lines)", data_empty.get("error", ""))

            rc_dup, data_dup, _ = run_cli(
                "guard", "renegotiate",
                "--test-dir", str(tdir),
                "--cmd", "false",
                "--reason", "fork",
                "--witness-type", "arch-fork",
                "--fork-options", f"OptA@{valid_file}:1|OptB@{valid_file}:1",
            )
            self.assertEqual(rc_dup, 1)
            self.assertIn("Duplicate fork option blast-radius anchor", data_dup.get("error", ""))

            rc_empty_lbl, data_empty_lbl, _ = run_cli(
                "guard", "renegotiate",
                "--test-dir", str(tdir),
                "--cmd", "false",
                "--reason", "fork",
                "--witness-type", "arch-fork",
                "--fork-options", f"@{valid_file}:1|OptB@{valid_file}:2",
            )
            self.assertEqual(rc_empty_lbl, 1)
            self.assertIn("non-empty option label", data_empty_lbl.get("error", ""))

    def test_08_symlink_created_during_witness_red_returns_clean_json(self) -> None:
        """Verifica que si el comando de prueba crea un symlink en test_dir, retorne JSON estructurado sin excepción no controlada."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            tdir = tmp_path / "tests"
            tdir.mkdir()
            tfile = tdir / "test_1.py"
            tfile.write_text("assert False\n", encoding="utf-8")
            link_path = tdir / "evil_link.py"
            jdir = tdir / "evil_junc"
            if os.name == "nt":
                cmd = f'"{sys.executable}" -c "import subprocess, sys; subprocess.run([\'cmd\', \'/c\', \'mklink\', \'/J\', r\'{jdir}\', r\'{tdir}\'], capture_output=True); sys.exit(1)"'
            else:
                cmd = f"ln -s {tfile} {link_path} && false"

            rc, data, stderr = run_cli("guard", "witness-red", "--test-dir", str(tdir), "--cmd", cmd)
            self.assertEqual(rc, 1)
            self.assertFalse(data.get("ok", True))
            self.assertIn("SELF_MUTATING_TEST_DIR", data.get("error", ""))
            self.assertNotIn("Traceback", stderr)

    def test_09_binary_file_crlf_tampering_detected(self) -> None:
        """Verifica que archivos binarios con bytes NUL no sufran normalización CRLF->LF que oculte manipulaciones."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            tdir = tmp_path / "tests"
            tdir.mkdir()
            (tdir / "test_1.py").write_text("assert False\n", encoding="utf-8")
            bin_fixture = tdir / "payload.bin"
            bin_fixture.write_bytes(b"\x00\x89PNG\r\n\x1a\n\x00\xff")

            rc1, _, _ = run_cli("guard", "witness-red", "--test-dir", str(tdir), "--cmd", "false")
            self.assertEqual(rc1, 0)

            bin_fixture.write_bytes(b"\x00\x89PNG\n\x1a\n\x00\xff")
            rc2, data2, _ = run_cli("guard", "verify-green", "--test-dir", str(tdir))
            self.assertEqual(rc2, 2)
            self.assertIn("EACCES_TEST_TAMPERING", data2.get("error", ""))
            self.assertIn("MODIFIED:payload.bin", data2.get("changes", []))

    def test_10_state_conflict_across_zero_padding_and_dir_artifact(self) -> None:
        """Verifica detección de conflicto entre 005_*.json y paso 5, y manejo de directorio como artefacto."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            (tmp_path / "005_legacy.json").write_text(
                json.dumps({"step": "005", "name": "legacy", "status": "COMPLETADO", "artifacts": {}}),
                encoding="utf-8",
            )
            rc_conflict, data_conflict, _ = run_cli("state", "write", "--dir", str(tmp_path), "--step", "5", "--name", "new_slug")
            self.assertEqual(rc_conflict, 1)
            self.assertIn("STEP_CONFLICT", data_conflict.get("error", ""))

            rc_replace, _, _ = run_cli("state", "write", "--dir", str(tmp_path), "--step", "5", "--name", "new_slug", "--replace")
            self.assertEqual(rc_replace, 0)
            self.assertFalse((tmp_path / "005_legacy.json").exists())

            art_file = tmp_path / "artifact.txt"
            art_file.write_text("v1", encoding="utf-8")
            rc_w, _, _ = run_cli(
                "state", "write",
                "--dir", str(tmp_path),
                "--step", "10",
                "--name", "build",
                "--artifacts", str(art_file),
            )
            self.assertEqual(rc_w, 0)
            art_file.unlink()
            art_file.mkdir()

            rc_st, data_st, _ = run_cli("state", "status", "--dir", str(tmp_path), "--strict")
            self.assertEqual(rc_st, 2)
            self.assertTrue(data_st.get("has_drift"))
            self.assertEqual(data_st["drift_warnings"][0]["issue"], "FILE_DELETED")

    def test_11_regret_mine_non_monotonic_commit_timestamps(self) -> None:
        """Verifica que commits con timestamps no monotónicos (rebase/clock skew) fuera de ventana no generen delta_minutes negativos ni falsos positivos."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = pathlib.Path(tmp)
            git_cmd(["git", "init", str(tmp_path)], check=True, capture_output=True)
            git_cmd(["git", "-C", str(tmp_path), "config", "user.email", "audit@example.com"], check=True)
            git_cmd(["git", "-C", str(tmp_path), "config", "user.name", "Auditor"], check=True)

            app = tmp_path / "mod.py"
            app.write_text("def run():\n    return 1\n", encoding="utf-8")
            env1 = dict(os.environ, GIT_COMMITTER_DATE="1700000000 +0000", GIT_AUTHOR_DATE="1700000000 +0000")
            git_cmd(["git", "-C", str(tmp_path), "add", "mod.py"], check=True, env=env1)
            git_cmd(["git", "-C", str(tmp_path), "commit", "-m", "initial"], check=True, env=env1, capture_output=True)

            app.write_text("def run():\n    return 2\n", encoding="utf-8")
            env2 = dict(os.environ, GIT_COMMITTER_DATE="1699000000 +0000", GIT_AUTHOR_DATE="1699000000 +0000")
            git_cmd(["git", "-C", str(tmp_path), "add", "mod.py"], check=True, env=env2)
            git_cmd(["git", "-C", str(tmp_path), "commit", "-m", "fix run"], check=True, env=env2, capture_output=True)

            rc, data, _ = run_cli("regret-mine", "--repo", str(tmp_path), "--window-min", "60")
            self.assertEqual(rc, 0)
            self.assertEqual(data.get("regret_pairs_count"), 0)

    def test_12_atomic_write_json_on_fuse_mount_without_fsync_support(self) -> None:
        """Verifica que _atomic_write_json (state write / guard) no falle con Errno 95 (ENOTSUP) en montajes virtuales/FUSE."""
        fuse_state_dir = pathlib.Path(__file__).resolve().parent.parent / "intermediate" / "fuse_state_test"
        fuse_state_dir.mkdir(parents=True, exist_ok=True)
        try:
            rc, data, stderr = run_cli(
                "state", "write",
                "--dir", str(fuse_state_dir),
                "--step", "1",
                "--name", "fuse_check",
                "--status", "COMPLETADO",
            )
            self.assertEqual(rc, 0, msg=f"Falló escritura atómica en montaje FUSE: {stderr}")
            self.assertTrue(data.get("ok"))
        finally:
            for p in fuse_state_dir.glob("*.json"):
                p.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()