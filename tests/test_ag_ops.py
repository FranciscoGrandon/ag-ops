#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Creado por Francisco Grandón Vergara
# Licensed under the MIT License
"""
test_ag_ops_v2_1.py (v2.1) - Suite de verificación integral (6/6 bloques)
para ag_ops_v2.py / ag_ops.py.
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

AG_OPS = pathlib.Path(
    os.environ.get(
        "AG_OPS_PATH",
        pathlib.Path(__file__).resolve().parent.parent / "ag_ops.py",
    )
).resolve()


def run_cli(*args: str, cwd: pathlib.Path | None = None) -> tuple[int, dict]:
    cmd = [sys.executable, str(AG_OPS), *args, "--json"]
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    payload = json.loads(proc.stdout) if proc.stdout.strip() else {}
    return proc.returncode, payload


class TestAgOpsV21(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name).resolve()

    def tearDown(self):
        self.tmp.cleanup()

    def test_01_guard_receipt_isolation_and_empty_dir(self):
        # Punto 3: Directorio vacío se rechaza con EMPTY_TEST_TARGET
        empty_dir = self.root / "empty_tests"
        empty_dir.mkdir()
        fail_cmd = f'"{sys.executable}" -c "import sys; sys.exit(1)"'
        pass_cmd = f'"{sys.executable}" -c "import sys; sys.exit(0)"'

        rc, out = run_cli(
            "guard", "witness-red",
            "--test-dir", str(empty_dir),
            "--cmd", fail_cmd,
        )
        self.assertEqual(rc, 1)
        self.assertIn("EMPTY_TEST_TARGET", out["error"])

        # Punto 1: Dos archivos en la misma carpeta generan recibos independientes
        tdir = self.root / "tests"
        tdir.mkdir()
        fa = tdir / "test_a.py"
        fb = tdir / "test_b.py"
        fa.write_text("assert False\n", encoding="utf-8")
        fb.write_text("assert False\n", encoding="utf-8")

        rc_a, out_a = run_cli("guard", "witness-red", "--test-dir", str(fa), "--cmd", fail_cmd)
        rc_b, out_b = run_cli("guard", "witness-red", "--test-dir", str(fb), "--cmd", fail_cmd)
        self.assertEqual(rc_a, 0)
        self.assertEqual(rc_b, 0)
        self.assertNotEqual(out_a["receipt_file"], out_b["receipt_file"])

        # Punto 4: Comando distinto falla con COMMAND_MISMATCH (exit 2) y registra colisión
        rc_mismatch, out_mismatch = run_cli(
            "guard", "verify-green",
            "--test-dir", str(fa),
            "--cmd", pass_cmd,
        )
        self.assertEqual(rc_mismatch, 2)
        self.assertIn("COMMAND_MISMATCH", out_mismatch["error"])
        receipt_a = json.loads(pathlib.Path(out_a["receipt_file"]).read_text(encoding="utf-8"))
        self.assertEqual(len(receipt_a["collisions"]), 1)
        self.assertEqual(receipt_a["collisions"][0]["event"], "COMMAND_MISMATCH")

    def test_02_guard_strict_exclusions_and_constructive_witness(self):
        # Punto 2: Archivos .tmp en subcarpetas no se ignoran silenciosamente
        tdir = self.root / "tests"
        sub = tdir / "sub"
        sub.mkdir(parents=True)
        (tdir / "test_main.py").write_text("x = 1\n", encoding="utf-8")

        flag = self.root / "pass.flag"
        cmd = (
            f'"{sys.executable}" -c '
            f'"import pathlib, sys; sys.exit(0 if pathlib.Path(r\'{flag}\').exists() else 1)"'
        )

        rc, _ = run_cli("guard", "witness-red", "--test-dir", str(tdir), "--cmd", cmd)
        self.assertEqual(rc, 0)

        (sub / "datos.tmp").write_text("hidden fixture", encoding="utf-8")
        flag.write_text("ok", encoding="utf-8")
        rc_tamper, out_tamper = run_cli("guard", "verify-green", "--test-dir", str(tdir))
        self.assertEqual(rc_tamper, 2)
        self.assertIn("ADDED:sub/datos.tmp", out_tamper["changes"])

        # SCAR-PROC-150: Renegociación con --require-witness rechaza prosa sin prueba
        flag.unlink()
        rc_lazy, out_lazy = run_cli(
            "guard", "renegotiate",
            "--test-dir", str(tdir),
            "--reason", "Too tedious",
            "--require-witness",
        )
        self.assertEqual(rc_lazy, 1)
        self.assertIn("LAZY_RETRACTION_REJECTED", out_lazy["error"])

        spec_a = self.root / "spec_a.py"
        spec_b = self.root / "spec_b.py"
        spec_a.write_text("req = True\n", encoding="utf-8")
        spec_b.write_text("req = False\n", encoding="utf-8")
        rc_valid, out_valid = run_cli(
            "guard", "renegotiate",
            "--test-dir", str(tdir),
            "--reason", "Contradictory specs",
            "--require-witness",
            "--witness-type", "spec-collision",
            "--conflict-a", f"{spec_a}:1",
            "--conflict-b", f"{spec_b}:1",
        )
        self.assertEqual(rc_valid, 0)
        self.assertEqual(out_valid["constructive_witness"]["type"], "spec-collision")

    def test_03_distill_regex_anchor(self):
        # Punto 7: "DONE   " no dispara falso positivo de "E   "
        script = self.root / "runner.py"
        script.write_text(
            'import sys\n'
            'print(" Step 1 DONE    everything fine")\n'
            'for i in range(10): print(f"info line {i}")\n'
            'print("E   AssertionError: expected 42 got 0")\n'
            'sys.exit(2)\n',
            encoding="utf-8",
        )
        rc, out = run_cli(
            "distill",
            "--cmd", f'"{sys.executable}" "{script}"',
            "--log-dir", str(self.root / "logs"),
        )
        self.assertEqual(rc, 2)
        delta_joined = "\n".join(out["critical_delta"])
        self.assertIn("E   AssertionError", delta_joined)
        self.assertNotIn("Step 1 DONE", out["critical_delta"][0])

    def test_04_state_lifecycle_and_strict(self):
        # Punto 8: NOT_FOUND -> sellado -> FILE_DELETED, --status, --replace y --strict
        sdir = self.root / "state"
        art = self.root / "output.bin"

        rc_bad, _ = run_cli(
            "state", "write",
            "--dir", str(sdir),
            "--step", "10",
            "--name", "init",
            "--status", "INVALIDO",
        )
        self.assertEqual(rc_bad, 1)

        rc_w, _ = run_cli(
            "state", "write",
            "--dir", str(sdir),
            "--step", "10",
            "--name", "init",
            "--status", "EN_PROGRESO",
            "--artifacts", str(art),
        )
        self.assertEqual(rc_w, 0)

        # Conflicto de slug sin --replace falla, con --replace actualiza
        rc_conf, out_conf = run_cli(
            "state", "write",
            "--dir", str(sdir),
            "--step", "10",
            "--name", "otro_slug",
            "--status", "COMPLETADO",
        )
        self.assertEqual(rc_conf, 1)
        self.assertIn("STEP_CONFLICT", out_conf["error"])

        rc_rep, _ = run_cli(
            "state", "write",
            "--dir", str(sdir),
            "--step", "10",
            "--name", "otro_slug",
            "--status", "EN_PROGRESO",
            "--artifacts", str(art),
            "--replace",
        )
        self.assertEqual(rc_rep, 0)

        # Artefacto nunca existió -> ARTIFACT_NEVER_EXISTED (exit 2 con --strict)
        rc_st1, out_st1 = run_cli("state", "status", "--dir", str(sdir), "--strict")
        self.assertEqual(rc_st1, 2)
        self.assertEqual(out_st1["drift_warnings"][0]["issue"], "ARTIFACT_NEVER_EXISTED")

        # Aparece por primera vez -> se sella automáticamente
        art.write_text("contenido v1", encoding="utf-8")
        rc_st2, out_st2 = run_cli("state", "status", "--dir", str(sdir), "--strict")
        self.assertEqual(rc_st2, 0)
        self.assertFalse(out_st2["has_drift"])

        # Se elimina posteriormente -> FILE_DELETED
        art.unlink()
        rc_st3, out_st3 = run_cli("state", "status", "--dir", str(sdir), "--strict")
        self.assertEqual(rc_st3, 2)
        self.assertEqual(out_st3["drift_warnings"][0]["issue"], "FILE_DELETED")

    def test_05_ast_lint_tk002_author_paths_context_and_dot(self):
        # Puntos 9 y 10 + PATH001/PATH002 + ContextSignature + DOT sin ';'
        py_file = self.root / "app_prod.py"
        py_file.write_text(
            "import tkinter as tk\n"
            "import tkinter.ttk\n"
            "from unittest.mock import MagicMock\n"
            "def ttk_custom_helper(bg='red'): return bg\n"
            "def build(root):\n"
            "    ttk_custom_helper(bg='blue')\n"
            "    tk.Label(root, bg='green')\n"
            "    tkinter.ttk.Label(root, bg='red')\n"
            "    try:\n"
            "        build(None)\n"
            "    except Exception:\n"
            "        pass\n",
            encoding="utf-8",
        )

        # 1. Sin --author: no exige AUTH001, detecta PATH001, PATH002 y TK002 con reflex
        rc, out = run_cli("ast-lint", str(py_file))
        self.assertEqual(rc, 1)
        rules = [v["rule"] for v in out["violations"]]
        self.assertEqual(sorted(rules), ["PATH001", "PATH002", "TK002"])
        self.assertTrue(all("reflex" in v for v in out["violations"]))

        # 2. Con --author explícito: exige cabecera y agrega AUTH001
        rc_auth, out_auth = run_cli(
            "ast-lint", str(py_file),
            "--author", "Francisco Grandón",
        )
        self.assertEqual(rc_auth, 1)
        auth_rules = {v["rule"] for v in out_auth["violations"]}
        self.assertIn("AUTH001", auth_rules)

        # 3. ContextSignature: si el hash del archivo ancla diverge, pasa a PROBATIONARY
        anchor = self.root / "pyproject.toml"
        anchor.write_text("[project]\nversion = '2.1'\n", encoding="utf-8")
        cmap = self.root / "context_map.json"
        cmap.write_text(
            json.dumps({
                r: {"anchor_file": str(anchor), "sha256": "0" * 64}
                for r in ("PATH001", "PATH002", "TK002")
            }),
            encoding="utf-8",
        )
        rc_prob, out_prob = run_cli("ast-lint", str(py_file), "--context-map", str(cmap))
        self.assertEqual(rc_prob, 0)
        self.assertEqual(out_prob["probationary_count"], 3)
        self.assertTrue(all(w.get("autoimmune_drift") for w in out_prob["probationary_warnings"]))

        # 4. Archivo .dot sin ';' al final de las líneas: detecta SCAR-PROC-152 y SCAR-ASYNC-01
        dot_file = self.root / "state.dot"
        dot_file.write_text(
            'digraph G {\n'
            '  Idle -> Fetching\n'
            '  Fetching -> Done [label="onSuccess"]\n'
            '}\n',
            encoding="utf-8",
        )
        rc_dot, out_dot = run_cli("ast-lint", str(dot_file))
        self.assertEqual(rc_dot, 1)
        dot_rules = {v["rule"] for v in out_dot["violations"]}
        self.assertIn("SCAR-PROC-152", dot_rules)
        self.assertIn("SCAR-ASYNC-01", dot_rules)
        self.assertNotIn("DOT001", dot_rules)

    @unittest.skipUnless(shutil.which("git") is not None, "Git no disponible en el PATH")
    def test_06_regret_mine(self):
        repo = self.root / "repo"
        repo.mkdir()

        def git(*args: str):
            subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)

        git("init")
        git("config", "user.email", "test@example.com")
        git("config", "user.name", "Tester")

        calc_py = repo / "calc.py"

        # C1: feat: add calc
        calc_py.write_text("def calc(x):\n    res = x + 1\n    return res\n", encoding="utf-8")
        git("add", "calc.py")
        git("commit", "-m", "feat: add calc")

        # C2: refactor: simplify calc (debe filtrarse como refactor sano)
        calc_py.write_text("def calc(x):\n    return x + 1\n", encoding="utf-8")
        git("add", "calc.py")
        git("commit", "-m", "refactor: simplify calc")

        # C3: fix: edge case None in calc (debe reportarse únicamente C2 -> C3)
        calc_py.write_text(
            "def calc(x):\n    if x is None:\n        return 0\n    return x + 1\n",
            encoding="utf-8",
        )
        git("add", "calc.py")
        git("commit", "-m", "fix: edge case None in calc")

        rc, out = run_cli("regret-mine", "--repo", str(repo), "--window-min", "60")
        self.assertEqual(rc, 0)
        self.assertEqual(out["tdd_refactors_filtered"], 1)
        self.assertEqual(out["regret_pairs_count"], 1)
        pair = out["regret_pairs"][0]
        self.assertEqual(pair["file"], "calc.py")
        self.assertEqual(pair["overlapping_functions"], ["calc"])
        self.assertEqual(pair["asymmetry_signals"], ["FIX_VERB_INTENT"])


if __name__ == "__main__":
    unittest.main(verbosity=2)