#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Creado por Francisco Grandón Vergara
# Licensed under the MIT License
"""
test_ag_ops_v2_2.py (v2.2) - Suite TDD de endurecimiento de fronteras de confianza
para ag_ops_v2.py / ag_ops.py.
Cubre:
1. H1: verify-green bloqueo de --ignore con IGNORE_PATTERN_MISMATCH (exit 2) y registro de colisión.
2. H2: regret-mine aislamiento argv (shell=False) e inmunidad contra inyección de nombres.
3. H3: ast-lint --strict con rechazo STRICT_PROBATIONARY (exit 2) ante ancla modificada/borrada.
4. Symlinks en Merkle: ValueError y rechazo determinista en guard.
5. regret-mine: soporte para rutas con tildes (core.quotepath=false) y calificación ClassName.method.
6. PATH001 ampliado: detección de 'except Exception: continue' y 'except Exception: return {}'.
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
        str(pathlib.Path(__file__).resolve().parent.parent / "ag_ops_v2.py"),
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


class TestAgOpsV22(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name).resolve()

    def tearDown(self):
        self.tmp.cleanup()

    def test_01_guard_ignore_pattern_mismatch_locked(self):
        """H1: verify-green rechaza discrepancia de --ignore y sella patrones solo del recibo rojo."""
        tdir = self.root / "tests"
        tdir.mkdir()
        test_file = tdir / "test_math.py"
        test_file.write_text("assert False\n", encoding="utf-8")

        fail_cmd = f'"{sys.executable}" -c "import sys; sys.exit(1)"'
        pass_cmd = f'"{sys.executable}" -c "import sys; sys.exit(0)"'

        # 1. Rojo sin --ignore
        rc_red, out_red = run_cli("guard", "witness-red", "--test-dir", str(tdir), "--cmd", fail_cmd)
        self.assertEqual(rc_red, 0)
        receipt_path = pathlib.Path(out_red["receipt_file"])

        # 2. Intento de evasión: crear conftest.py malicioso y pasarlo en --ignore
        conftest = tdir / "conftest.py"
        conftest.write_text("# backdoor\n", encoding="utf-8")

        rc_attack, out_attack = run_cli(
            "guard", "verify-green",
            "--test-dir", str(tdir),
            "--cmd", pass_cmd,
            "--ignore", "conftest.py",
        )
        self.assertEqual(rc_attack, 2)
        self.assertIn("IGNORE_PATTERN_MISMATCH", out_attack["error"])

        # Verificar colisión auditada en el recibo
        receipt_data = json.loads(receipt_path.read_text(encoding="utf-8"))
        collisions = receipt_data.get("collisions", [])
        self.assertTrue(any(c.get("event") == "IGNORE_PATTERN_MISMATCH" for c in collisions))

    def test_02_regret_mine_argv_injection_immunity(self):
        """H2: regret-mine ejecuta git con argv directo (shell=False), neutralizando inyecciones en nombres."""
        git_bin = shutil.which("git") or r"D:\GIT\MinGit-2.56.0.4-64-bit\cmd\git.exe"
        if not os.path.exists(git_bin) and shutil.which("git") is None:
            self.skipTest("Git no disponible para test_02")

        repo = self.root / "repo"
        repo.mkdir()

        def git(*args: str):
            subprocess.run([git_bin, *args], cwd=repo, check=True, capture_output=True, text=True)

        git("init")
        git("config", "user.email", "tester@example.com")
        git("config", "user.name", "Tester")

        # Nombre de archivo con payload de inyección command substitution
        injection_fname = "a$(touch PWNED).py"
        target_file = repo / injection_fname
        target_file.write_text("def run():\n    return 1\n", encoding="utf-8")
        git("add", "-A")
        git("commit", "-m", "feat: initial commit with injection attempt")

        target_file.write_text("def run():\n    return 2\n", encoding="utf-8")
        git("add", "-A")
        git("commit", "-m", "fix: modify function in injection file")

        rc, out = run_cli("regret-mine", "--repo", str(repo), "--window-min", "60")
        self.assertEqual(rc, 0)

        # Certeza: el archivo PWNED NO debe existir en el repo ni en el root de ejecución
        pwned_local = repo / "PWNED"
        pwned_cwd = pathlib.Path.cwd() / "PWNED"
        self.assertFalse(pwned_local.exists(), "Exploit PWNED creado en repo local!")
        self.assertFalse(pwned_cwd.exists(), "Exploit PWNED creado en CWD!")

    def test_03_ast_lint_strict_probationary(self):
        """H3: ast-lint --strict sale con STRICT_PROBATIONARY (exit 2) ante ancla modificada o borrada."""
        py_file = self.root / "module.py"
        py_file.write_text(
            "def handle():\n"
            "    try:\n"
            "        pass\n"
            "    except Exception:\n"
            "        pass\n",
            encoding="utf-8",
        )

        anchor = self.root / "pyproject.toml"
        anchor.write_text("[project]\nversion = '2.2'\n", encoding="utf-8")

        cmap = self.root / "context_map.json"
        cmap.write_text(
            json.dumps({
                "PATH001": {"anchor_file": str(anchor), "sha256": "0" * 64}  # Hash divergente forzado
            }),
            encoding="utf-8",
        )

        # Sin --strict: degrada a PROBATIONARY y retorna exit 0
        rc_normal, out_normal = run_cli("ast-lint", str(py_file), "--context-map", str(cmap))
        self.assertEqual(rc_normal, 0)
        self.assertEqual(out_normal.get("probationary_count"), 1)

        # Con --strict: rechaza con exit 2 y STRICT_PROBATIONARY
        rc_strict, out_strict = run_cli("ast-lint", str(py_file), "--context-map", str(cmap), "--strict")
        self.assertEqual(rc_strict, 2)
        self.assertIn("STRICT_PROBATIONARY", out_strict["error"])

    def test_04_merkle_guard_symlink_rejection(self):
        """Merkle Guard levanta ValueError / GUARD_INIT_FAILED ante symlinks o junctions en el directorio de pruebas."""
        tdir = self.root / "tests"
        tdir.mkdir()
        external_dir = self.root / "external_tests"
        external_dir.mkdir()
        (external_dir / "test_ext.py").write_text("assert False\n", encoding="utf-8")

        junction_target = tdir / "junction_sub"
        has_link = False
        if os.name == "nt":
            subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(junction_target), str(external_dir)],
                capture_output=True,
                text=True,
            )
            has_link = junction_target.exists() and (
                (hasattr(junction_target, "is_junction") and junction_target.is_junction())
                or os.path.islink(junction_target)
            )
        else:
            try:
                os.symlink(external_dir, junction_target)
                has_link = junction_target.is_symlink()
            except OSError:
                pass

        fail_cmd = f'"{sys.executable}" -c "import sys; sys.exit(1)"'
        if has_link:
            rc, out = run_cli("guard", "witness-red", "--test-dir", str(tdir), "--cmd", fail_cmd)
            self.assertEqual(rc, 1)
            self.assertIn("Symlinks and junctions are forbidden", out["error"])
        else:
            self.skipTest("No se pudo crear enlace simbólico/junction en este SO sin privilegios.")

    def test_05_regret_mine_accents_and_qualified_class_methods(self):
        """regret-mine analiza nombres con tildes (core.quotepath=false) y califica ClassName.method."""
        git_bin = shutil.which("git") or r"D:\GIT\MinGit-2.56.0.4-64-bit\cmd\git.exe"
        if not os.path.exists(git_bin) and shutil.which("git") is None:
            self.skipTest("Git no disponible para test_05")

        repo = self.root / "repo_unicode"
        repo.mkdir()

        def git(*args: str):
            subprocess.run([git_bin, *args], cwd=repo, check=True, capture_output=True, text=True)

        git("init")
        git("config", "user.email", "tester@example.com")
        git("config", "user.name", "Tester")

        # Archivo con tildes: diseño.py
        diseno_py = repo / "diseño.py"
        diseno_py.write_text(
            "class MathEngine:\n"
            "    def calculate(self, x):\n"
            "        return x * 2\n",
            encoding="utf-8",
        )
        git("add", "diseño.py")
        git("commit", "-m", "feat: initial engine with accents")

        diseno_py.write_text(
            "class MathEngine:\n"
            "    def calculate(self, x):\n"
            "        if x is None:\n"
            "            return 0\n"
            "        return x * 2\n",
            encoding="utf-8",
        )
        git("add", "diseño.py")
        git("commit", "-m", "fix: handle None in MathEngine.calculate")

        rc, out = run_cli("regret-mine", "--repo", str(repo), "--window-min", "60")
        self.assertEqual(rc, 0)
        self.assertEqual(out.get("regret_pairs_count"), 1)
        pair = out["regret_pairs"][0]
        self.assertEqual(pair["file"], "diseño.py")
        # Calificación estricta ClassName.method
        self.assertEqual(pair["overlapping_functions"], ["MathEngine.calculate"])

    def test_06_path001_extended_continue_and_trivial_returns(self):
        """PATH001 detecta 'except Exception: continue', 'return {}' y tuplas amplias como '(Exception,)'."""
        py_file = self.root / "swallowed_types.py"
        py_file.write_text(
            "def loop_swallow(items):\n"
            "    for item in items:\n"
            "        try:\n"
            "            int(item)\n"
            "        except Exception:\n"
            "            continue\n"
            "def dict_swallow(key):\n"
            "    try:\n"
            "        return {key: 1}\n"
            "    except Exception:\n"
            "        return {}\n"
            "def tuple_swallow(x):\n"
            "    try:\n"
            "        int(x)\n"
            "    except (Exception,):\n"
            "        continue\n"
            "def specific_safe(key):\n"
            "    try:\n"
            "        return {key: 1}\n"
            "    except (KeyError, ValueError):\n"
            "        return {}\n",
            encoding="utf-8",
        )

        rc, out = run_cli("ast-lint", str(py_file))
        self.assertEqual(rc, 1)
        violations = out.get("violations", [])
        rules = [v["rule"] for v in violations]
        self.assertEqual(rules.count("PATH001"), 3)

        messages = [v["message"] for v in violations if v["rule"] == "PATH001"]
        self.assertTrue(any("continue" in m for m in messages))
        self.assertTrue(any("return {}" in m for m in messages))


if __name__ == "__main__":
    unittest.main(verbosity=2)
