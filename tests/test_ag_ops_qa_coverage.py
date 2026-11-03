# -*- coding: utf-8 -*-
# Creado por Francisco Grandón Vergara
"""
Suite exhaustiva de pruebas unitarias y de cobertura directa para ag_ops.py v2.3.
Cubre casos felices, casos borde y casos de error con invocación en proceso
para certificación de cobertura >90% con pytest-cov.
"""

import errno
import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import ag_ops


class TestAgOpsQACoverage(unittest.TestCase):
    """Pruebas unitarias directas sobre las funciones internas y CLI de ag_ops.py."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmpdir.name).resolve()
        self.git_bin = ag_ops._resolve_git_binary()

    def tearDown(self) -> None:
        try:
            self.tmpdir.cleanup()
        except OSError:
            pass

    def _init_git_repo(self) -> pathlib.Path:
        subprocess.run([self.git_bin, "init"], cwd=self.root, capture_output=True, check=True)
        subprocess.run([self.git_bin, "config", "user.email", "qa@example.com"], cwd=self.root, check=True)
        subprocess.run([self.git_bin, "config", "user.name", "QATester"], cwd=self.root, check=True)
        return self.root

    # -------------------------------------------------------------------------
    # 1. Transversal Utilities & File Helpers
    # -------------------------------------------------------------------------
    def test_utc_now_iso(self) -> None:
        ts = ag_ops._utc_now_iso()
        self.assertTrue(ts.endswith("Z"))
        self.assertIn("T", ts)

    def test_parse_iso_utc_ts(self) -> None:
        ts_valid = "2026-11-02T12:00:00Z"
        parsed = ag_ops._parse_iso_utc_ts(ts_valid)
        self.assertIsNotNone(parsed)
        self.assertGreater(parsed or 0, 0)
        self.assertIsNone(ag_ops._parse_iso_utc_ts("invalid-date"))
        self.assertIsNone(ag_ops._parse_iso_utc_ts(""))

    def test_atomic_write_json_success(self) -> None:
        target = self.root / "sub" / "data.json"
        ag_ops._atomic_write_json(target, {"hello": "world"})
        self.assertTrue(target.is_file())
        with open(target, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data, {"hello": "world"})

    def test_atomic_write_json_fsync_exceptions(self) -> None:
        target = self.root / "sub" / "fsync.json"
        with patch("os.fsync", side_effect=OSError(errno.EINVAL, "Invalid argument")):
            ag_ops._atomic_write_json(target, {"status": "ok"})
        self.assertTrue(target.is_file())

        with patch("os.fsync", side_effect=OSError(errno.EACCES, "Permission denied")):
            with self.assertRaises(OSError):
                ag_ops._atomic_write_json(self.root / "fail.json", {"fail": True})

    def test_sha256_file_text_and_binary(self) -> None:
        p_crlf = self.root / "crlf.txt"
        p_crlf.write_bytes(b"hello\r\nworld\r\n")
        h_crlf = ag_ops._sha256_file(p_crlf, normalize_eol=True)

        p_lf = self.root / "lf.txt"
        p_lf.write_bytes(b"hello\nworld\n")
        h_lf = ag_ops._sha256_file(p_lf, normalize_eol=True)
        self.assertEqual(h_crlf, h_lf)

        p_bin = self.root / "data.bin"
        p_bin.write_bytes(b"\x00\x01\x02\r\n\x00")
        h_bin = ag_ops._sha256_file(p_bin)
        self.assertIsInstance(h_bin, str)
        self.assertEqual(len(h_bin), 64)

    def test_sha256_file_large_streaming(self) -> None:
        p_large = self.root / "large.bin"
        chunk = b"X" * (1024 * 64)
        with open(p_large, "wb") as f:
            for _ in range(165):  # > 10 MB
                f.write(chunk)
        h_large = ag_ops._sha256_file(p_large)
        self.assertIsInstance(h_large, str)
        self.assertEqual(len(h_large), 64)

    def test_is_symlink_or_junction(self) -> None:
        p_reg = self.root / "reg.txt"
        p_reg.write_text("ok", encoding="utf-8")
        self.assertFalse(ag_ops._is_symlink_or_junction(p_reg))

    def test_resolve_git_binary(self) -> None:
        git_bin = ag_ops._resolve_git_binary()
        self.assertTrue(os.path.isfile(git_bin) or shutil.which(git_bin) is not None)

    def test_get_git_repo_and_head(self) -> None:
        self._init_git_repo()
        test_file = self.root / "a.py"
        test_file.write_text("# Creado por Francisco Grandón Vergara\n", encoding="utf-8")
        subprocess.run([self.git_bin, "add", "."], cwd=self.root, check=True)
        subprocess.run([self.git_bin, "commit", "-m", "initial"], cwd=self.root, check=True)

        repo_root, head_sha = ag_ops._get_git_repo_and_head(self.root)
        self.assertIsNotNone(repo_root)
        self.assertIsNotNone(head_sha)
        self.assertEqual(len(head_sha or ""), 40)

    def test_parse_and_matches_ignore(self) -> None:
        patterns = ag_ops._parse_ignore_patterns("*.tmp, build/* , vendor")
        self.assertEqual(patterns, ["*.tmp", "build/*", "vendor"])
        self.assertEqual(ag_ops._parse_ignore_patterns(None), [])

        self.assertTrue(ag_ops._matches_ignore("foo.tmp", "foo.tmp", patterns))
        self.assertTrue(ag_ops._matches_ignore("build/out.js", "out.js", patterns))
        self.assertFalse(ag_ops._matches_ignore("src/main.py", "main.py", patterns))

    def test_compute_merkle_tree_file_and_dir(self) -> None:
        f = self.root / "single.py"
        f.write_text("print('test')\n", encoding="utf-8")
        tree_hash, files_map = ag_ops._compute_merkle_tree(f, self.root / ".ag_state")
        self.assertEqual(len(files_map), 1)
        self.assertIn("single.py", files_map)

        d = self.root / "pkg"
        d.mkdir()
        (d / "a.py").write_text("a = 1\n", encoding="utf-8")
        (d / "b.txt").write_text("b = 2\n", encoding="utf-8")
        tree_hash2, files_map2 = ag_ops._compute_merkle_tree(d, d / ".ag_state", ignore_patterns=["*.txt"])
        self.assertEqual(len(files_map2), 1)
        self.assertIn("a.py", files_map2)

    def test_validate_file_line_ref(self) -> None:
        self._init_git_repo()
        f = self.root / "code.py"
        f.write_text("line1 = True\n# comment\n\nline4 = False\n", encoding="utf-8")
        subprocess.run([self.git_bin, "add", "."], cwd=self.root, check=True)
        subprocess.run([self.git_bin, "commit", "-m", "init"], cwd=self.root, check=True)
        repo_root, head_sha = ag_ops._get_git_repo_and_head(self.root)

        # Valid non-trivial line
        ok, err, content = ag_ops._validate_file_line_ref(f"{f}:1", repo_root, pinned_sha=head_sha)
        self.assertTrue(ok)
        self.assertEqual(content, "line1 = True")

        # Trivial comment line
        ok_com, err_com, _ = ag_ops._validate_file_line_ref(f"{f}:2", repo_root, pinned_sha=head_sha)
        self.assertFalse(ok_com)
        self.assertIn("TRIVIAL_WITNESS_LINE", err_com)

        # Invalid format
        ok_inv, err_inv, _ = ag_ops._validate_file_line_ref("nofile", repo_root)
        self.assertFalse(ok_inv)
        self.assertIn("must follow 'file:line' format", err_inv)

        # Line out of range
        ok_oor, err_oor, _ = ag_ops._validate_file_line_ref(f"{f}:99", repo_root, pinned_sha=head_sha)
        self.assertFalse(ok_oor)
        self.assertIn("out of range", err_oor)

        # Uncommitted file
        uncom = self.root / "uncom.py"
        uncom.write_text("val = 1\n", encoding="utf-8")
        ok_unc, err_unc, _ = ag_ops._validate_file_line_ref(f"{uncom}:1", repo_root, pinned_sha=head_sha)
        self.assertFalse(ok_unc)
        self.assertIn("UNCOMMITTED_WITNESS_FILE", err_unc)

    def test_verify_constructive_witness(self) -> None:
        self._init_git_repo()
        doc = self.root / "spec.txt"
        doc.write_text("Rule 101: System must halt on error\nRule 102: System must restart\n", encoding="utf-8")
        subprocess.run([self.git_bin, "add", "."], cwd=self.root, check=True)
        subprocess.run([self.git_bin, "commit", "-m", "docs"], cwd=self.root, check=True)
        repo_root, head_sha = ag_ops._get_git_repo_and_head(self.root)

        p = ag_ops.build_parser()
        args = p.parse_args([
            "guard", "renegotiate",
            "--test-dir", str(self.root),
            "--reason", "spec clash",
            "--require-witness",
            "--witness-type", "spec-collision",
            "--conflict-a", f"{doc}:1",
            "--conflict-b", f"{doc}:2",
        ])
        ok, err, proof = ag_ops._verify_constructive_witness(args, "", "", repo_root=repo_root, pinned_sha=head_sha)
        self.assertTrue(ok)
        assert proof is not None
        self.assertEqual(proof.get("type"), "spec-collision")
        self.assertEqual(proof.get("excerpt_a"), "Rule 101: System must halt on error")

        # Conflict a == conflict b
        args_same = p.parse_args([
            "guard", "renegotiate",
            "--test-dir", str(self.root),
            "--reason", "spec clash",
            "--require-witness",
            "--witness-type", "spec-collision",
            "--conflict-a", f"{doc}:1",
            "--conflict-b", f"{doc}:1",
        ])
        ok_same, err_same, _ = ag_ops._verify_constructive_witness(args_same, "", "", repo_root=repo_root, pinned_sha=head_sha)
        self.assertFalse(ok_same)
        self.assertIn("must point to distinct locations", err_same)

        # api-lock type
        args_api = p.parse_args([
            "guard", "renegotiate",
            "--test-dir", str(self.root),
            "--reason", "api changed",
            "--require-witness",
            "--witness-type", "api-lock",
        ])
        ok_api, _, proof_api = ag_ops._verify_constructive_witness(args_api, "E   TypeError: unexpected keyword 'foo'", "", repo_root=repo_root, pinned_sha=head_sha)
        self.assertTrue(ok_api)
        assert proof_api is not None
        self.assertEqual(proof_api.get("type"), "api-lock")

        # arch-fork type
        args_fork = p.parse_args([
            "guard", "renegotiate",
            "--test-dir", str(self.root),
            "--reason", "fork decision",
            "--require-witness",
            "--witness-type", "arch-fork",
            "--conflict-a", f"{doc}:1",
            "--fork-options", f"OptA@{doc}:1|OptB@{doc}:2",
        ])
        ok_fork, _, proof_fork = ag_ops._verify_constructive_witness(args_fork, "", "", repo_root=repo_root, pinned_sha=head_sha)
        self.assertTrue(ok_fork)
        assert proof_fork is not None
        self.assertEqual(proof_fork.get("type"), "arch-fork")

    def test_extract_red_signature(self) -> None:
        stdout = "=== FAILURES ===\n_____ test_one _____\nFAILED tests/test_a.py::test_one - AssertionError\nE   assert 1 == 2\n"
        stderr = "CRITICAL error occurred\n"
        sig = ag_ops._extract_red_signature(stdout, stderr)
        self.assertTrue(any("assert 1 == 2" in s for s in sig))

    def test_run_command_isolated_success_and_timeout(self) -> None:
        rc, out, err, timed_out, elapsed = ag_ops._run_command_isolated("python -c \"print('hello')\"", 5.0)
        self.assertEqual(rc, 0)
        self.assertIn("hello", out)
        self.assertFalse(timed_out)

        rc_t, _, _, timed_out_t, _ = ag_ops._run_command_isolated("python -c \"import time; time.sleep(2)\"", 0.2)
        self.assertTrue(timed_out_t)

    # -------------------------------------------------------------------------
    # 2. Guard Subcommand (witness-red, verify-green, renegotiate)
    # -------------------------------------------------------------------------
    def test_guard_witness_red_and_verify_green_flow(self) -> None:
        self._init_git_repo()
        prod = self.root / "calc.py"
        prod.write_text("def add(a, b): return a - b\n", encoding="utf-8")
        t_dir = self.root / "tests"
        t_dir.mkdir()
        t_file = t_dir / "test_calc.py"
        t_file.write_text(
            f'import sys; sys.path.insert(0, r"{self.root}"); import calc\n'
            'def test_add(): assert calc.add(2, 3) == 5\n',
            encoding="utf-8",
        )
        subprocess.run([self.git_bin, "add", "."], cwd=self.root, check=True)
        subprocess.run([self.git_bin, "commit", "-m", "init red"], cwd=self.root, check=True)

        p = ag_ops.build_parser()
        cmd = f'python -m pytest "{t_dir}"'
        args_red = p.parse_args(["guard", "witness-red", "--test-dir", str(t_dir), "--cmd", cmd, "--json"])
        rc_red = ag_ops._cmd_guard(args_red)
        self.assertEqual(rc_red, 0)

        # Verify receipt written
        state_dir = t_dir / ".ag_state"
        receipt_path = ag_ops._receipt_path_for_target(state_dir, t_dir)
        self.assertTrue(receipt_path.is_file())

        # Attempt verify-green while test is still failing -> TEST_STILL_FAILING
        args_green_fail = p.parse_args(["guard", "verify-green", "--test-dir", str(t_dir), "--json"])
        rc_gf = ag_ops._cmd_guard(args_green_fail)
        self.assertEqual(rc_gf, 1)

        # Tampering detection: modify test file directly without renegotiation
        t_file.write_text("def test_item():\n    assert True\n", encoding="utf-8")
        args_green_tamper = p.parse_args(["guard", "verify-green", "--test-dir", str(t_dir), "--json"])
        rc_gt = ag_ops._cmd_guard(args_green_tamper)
        self.assertEqual(rc_gt, 2)  # EACCES_TEST_TAMPERING

        # Restore test file to witnessed state
        t_file.write_text(
            f'import sys; sys.path.insert(0, r"{self.root}"); import calc\n'
            'def test_add(): assert calc.add(2, 3) == 5\n',
            encoding="utf-8",
        )

        # Fix production code: genuine TDD Green transition
        prod.write_text("def add(a, b): return a + b\n", encoding="utf-8")
        args_green_pass = p.parse_args(["guard", "verify-green", "--test-dir", str(t_dir), "--json"])
        rc_gp = ag_ops._cmd_guard(args_green_pass)
        self.assertEqual(rc_gp, 0)

        # ---------------------------------------------------------------------
        # Part B: Renegotiate with constructive witness on an initial red setup
        # where the witness spec file is committed in HEAD before witness-red.
        # ---------------------------------------------------------------------
        t_dir_b = self.root / "tests_b"
        t_dir_b.mkdir()
        t_file_b = t_dir_b / "test_b.py"
        t_file_b.write_text("def test_foo(): assert False\n", encoding="utf-8")
        doc_b = self.root / "spec_b.txt"
        doc_b.write_text("Spec 1: Foo must fail\nSpec 2: Foo must pass\n", encoding="utf-8")
        subprocess.run([self.git_bin, "add", "."], cwd=self.root, check=True)
        subprocess.run([self.git_bin, "commit", "-m", "setup tests_b"], cwd=self.root, check=True)

        cmd_b = f'python -m pytest "{t_dir_b}"'
        args_red_b = p.parse_args(["guard", "witness-red", "--test-dir", str(t_dir_b), "--cmd", cmd_b, "--json"])
        self.assertEqual(ag_ops._cmd_guard(args_red_b), 0)

        # Make test_b fail differently for renegotiate
        t_file_b.write_text("def test_foo(): assert 1 == 99\n", encoding="utf-8")
        args_reneg = p.parse_args([
            "guard", "renegotiate",
            "--test-dir", str(t_dir_b),
            "--reason", "spec change",
            "--require-witness",
            "--witness-type", "spec-collision",
            "--conflict-a", f"{doc_b}:1",
            "--conflict-b", f"{doc_b}:2",
            "--cmd", cmd_b,
            "--json",
        ])
        rc_rn = ag_ops._cmd_guard(args_reneg)
        self.assertEqual(rc_rn, 0)

        # Head moved detection during red phase: create a git commit
        t_dummy = self.root / "dummy.txt"
        t_dummy.write_text("forged\n", encoding="utf-8")
        subprocess.run([self.git_bin, "add", "."], cwd=self.root, check=True)
        subprocess.run([self.git_bin, "commit", "-m", "forged commit"], cwd=self.root, check=True)

        args_green_hm = p.parse_args(["guard", "verify-green", "--test-dir", str(t_dir_b), "--json"])
        rc_hm = ag_ops._cmd_guard(args_green_hm)
        self.assertEqual(rc_hm, 2)  # HEAD_MOVED_DURING_RED_PHASE

    def test_guard_error_branches(self) -> None:
        p = ag_ops.build_parser()
        # Target not found
        args_missing = p.parse_args(["guard", "witness-red", "--test-dir", str(self.root / "nonexistent"), "--cmd", "python -V", "--json"])
        self.assertEqual(ag_ops._cmd_guard(args_missing), 1)

        # Missing cmd
        d = self.root / "empty_dir"
        d.mkdir()
        (d / "dummy.txt").write_text("hi", encoding="utf-8")
        args_nocmd = p.parse_args(["guard", "witness-red", "--test-dir", str(d), "--cmd", "  ", "--json"])
        self.assertEqual(ag_ops._cmd_guard(args_nocmd), 1)

        # Empty test target
        d_empty = self.root / "really_empty"
        d_empty.mkdir()
        args_empty = p.parse_args(["guard", "witness-red", "--test-dir", str(d_empty), "--cmd", "python -V", "--json"])
        self.assertEqual(ag_ops._cmd_guard(args_empty), 1)

        # Cooperative test (exit 0)
        (d_empty / "a.py").write_text("x = 1", encoding="utf-8")
        args_coop = p.parse_args(["guard", "witness-red", "--test-dir", str(d_empty), "--cmd", "python -c \"import sys; sys.exit(0)\"", "--json"])
        self.assertEqual(ag_ops._cmd_guard(args_coop), 1)

        # Unexpected exit code vs expected-exit
        args_unexp = p.parse_args(["guard", "witness-red", "--test-dir", str(d_empty), "--cmd", "python -c \"import sys; sys.exit(4)\"", "--expected-exit", "1", "--json"])
        self.assertEqual(ag_ops._cmd_guard(args_unexp), 1)

        # Collection / syntax error (exit 2) without expected-exit
        args_syntax = p.parse_args(["guard", "witness-red", "--test-dir", str(d_empty), "--cmd", "python -c \"import sys; sys.exit(2)\"", "--json"])
        self.assertEqual(ag_ops._cmd_guard(args_syntax), 1)

        # verify-green without receipt
        args_vg_norec = p.parse_args(["guard", "verify-green", "--test-dir", str(d_empty), "--json"])
        self.assertEqual(ag_ops._cmd_guard(args_vg_norec), 1)

        # Corrupted receipt
        state_dir = d_empty / ".ag_state"
        state_dir.mkdir(parents=True, exist_ok=True)
        rec_path = ag_ops._receipt_path_for_target(state_dir, d_empty)
        rec_path.write_text("not json", encoding="utf-8")
        self.assertEqual(ag_ops._cmd_guard(args_vg_norec), 2)

        # Corrupted receipt version != 2
        rec_path.write_text(json.dumps({"version": 1}), encoding="utf-8")
        self.assertEqual(ag_ops._cmd_guard(args_vg_norec), 2)

        # Corrupted receipt missing cmd
        rec_path.write_text(json.dumps({"version": 2, "cmd": ""}), encoding="utf-8")
        self.assertEqual(ag_ops._cmd_guard(args_vg_norec), 2)

        # Target mismatch
        rec_path.write_text(json.dumps({"version": 2, "cmd": "pytest", "test_target": str(self.root / "other")}), encoding="utf-8")
        self.assertEqual(ag_ops._cmd_guard(args_vg_norec), 2)

        # Ignore pattern mismatch
        rec_path.write_text(json.dumps({
            "version": 2,
            "cmd": "pytest",
            "test_target": str(d_empty),
            "tree_hash": "abc",
            "files": {"a.py": "123"},
            "ignored_patterns": ["*.log"],
        }), encoding="utf-8")
        args_ign_mismatch = p.parse_args(["guard", "verify-green", "--test-dir", str(d_empty), "--ignore", "*.tmp", "--json"])
        self.assertEqual(ag_ops._cmd_guard(args_ign_mismatch), 2)

        # Command mismatch
        args_cmd_mismatch = p.parse_args(["guard", "verify-green", "--test-dir", str(d_empty), "--cmd", "python other.py", "--json"])
        self.assertEqual(ag_ops._cmd_guard(args_cmd_mismatch), 2)

        # renegotiate missing reason
        args_rn_noreason = p.parse_args(["guard", "renegotiate", "--test-dir", str(d_empty), "--json"])
        self.assertEqual(ag_ops._cmd_guard(args_rn_noreason), 1)

    # -------------------------------------------------------------------------
    # 3. Distill Subcommand
    # -------------------------------------------------------------------------
    def test_cmd_distill(self) -> None:
        p = ag_ops.build_parser()
        args = p.parse_args(["distill", "--cmd", "python -c \"print('line1'); print('line2')\"", "--max-lines", "5", "--json"])
        rc = ag_ops._cmd_distill(args)
        self.assertEqual(rc, 0)

        # Distill with error and empty cmd
        args_empty = p.parse_args(["distill", "--cmd", "   ", "--json"])
        self.assertEqual(ag_ops._cmd_distill(args_empty), 1)

        # Distill command timeout exits with code 124
        args_to = p.parse_args(["distill", "--cmd", "python -c \"import time; time.sleep(2)\"", "--timeout", "0.2", "--json"])
        self.assertEqual(ag_ops._cmd_distill(args_to), 124)

        # Distill failing command
        args_fail = p.parse_args(["distill", "--cmd", "python -c \"import sys; sys.exit(1)\"", "--json"])
        self.assertEqual(ag_ops._cmd_distill(args_fail), 1)

    # -------------------------------------------------------------------------
    # 4. State Subcommand (write, status, drift, late artifacts, strict)
    # -------------------------------------------------------------------------
    def test_cmd_state_write_and_status(self) -> None:
        p = ag_ops.build_parser()
        s_dir = self.root / "state_dir"

        art1 = self.root / "art1.txt"
        art1.write_text("artifact one\n", encoding="utf-8")

        # Invalid step
        args_inv_step = p.parse_args(["state", "write", "--step", "10000", "--name", "plan", "--dir", str(s_dir), "--json"])
        self.assertEqual(ag_ops._cmd_state(args_inv_step), 1)

        # Invalid status
        args_inv_stat = p.parse_args(["state", "write", "--step", "0", "--name", "plan", "--status", "INVALID", "--dir", str(s_dir), "--json"])
        self.assertEqual(ag_ops._cmd_state(args_inv_stat), 1)

        # Valid write
        args_w1 = p.parse_args([
            "state", "write",
            "--step", "0",
            "--name", "plan",
            "--status", "COMPLETADO",
            "--artifacts", f"{art1},{self.root / 'missing.txt'}",
            "--dir", str(s_dir),
            "--json",
        ])
        rc_w1 = ag_ops._cmd_state(args_w1)
        self.assertEqual(rc_w1, 0)

        # Conflicting step without --replace
        args_w_conflict = p.parse_args([
            "state", "write",
            "--step", "0",
            "--name", "other_slug",
            "--status", "COMPLETADO",
            "--dir", str(s_dir),
            "--json",
        ])
        self.assertEqual(ag_ops._cmd_state(args_w_conflict), 1)

        # Overwrite with --replace
        args_w_replace = p.parse_args([
            "state", "write",
            "--step", "0",
            "--name", "other_slug",
            "--status", "COMPLETADO",
            "--artifacts", f"{art1},{self.root / 'missing.txt'}",
            "--replace",
            "--dir", str(s_dir),
            "--json",
        ])
        self.assertEqual(ag_ops._cmd_state(args_w_replace), 0)

        # Status inspection (normal mode) -> missing.txt was never found
        args_stat = p.parse_args(["state", "status", "--dir", str(s_dir), "--json"])
        rc_stat = ag_ops._cmd_state(args_stat)
        self.assertEqual(rc_stat, 0)

        # Status in strict mode with ARTIFACT_NEVER_EXISTED -> exits 2
        args_stat_strict = p.parse_args(["state", "status", "--dir", str(s_dir), "--strict", "--json"])
        rc_strict = ag_ops._cmd_state(args_stat_strict)
        self.assertEqual(rc_strict, 2)

        # Late artifact appearance handling: create missing.txt now
        missing_art = self.root / "missing.txt"
        missing_art.write_text("now exists\n", encoding="utf-8")

        # In strict mode, an artifact unsealed at write triggers LATE_ARTIFACT_UNSEALED_AT_WRITE (exit 2)
        rc_strict_late = ag_ops._cmd_state(args_stat_strict)
        self.assertEqual(rc_strict_late, 2)

        # In normal mode, it auto-seals the late artifact (exit 0)
        rc_stat_auto = ag_ops._cmd_state(args_stat)
        self.assertEqual(rc_stat_auto, 0)

        # Corrupted state file detection
        corrupted_step = s_dir / "05_corrupt.json"
        corrupted_step.write_text("invalid json", encoding="utf-8")
        rc_stat_corrupt = ag_ops._cmd_state(args_stat)
        self.assertEqual(rc_stat_corrupt, 0)  # Has drift recorded in warnings

    def test_state_drift_modified_and_deleted(self) -> None:
        p = ag_ops.build_parser()
        s_dir = self.root / "state_drift_dir"
        art = self.root / "data.txt"
        art.write_text("original content", encoding="utf-8")

        args_w = p.parse_args(["state", "write", "--step", "1", "--name", "task", "--status", "COMPLETADO", "--artifacts", str(art), "--dir", str(s_dir), "--json"])
        self.assertEqual(ag_ops._cmd_state(args_w), 0)

        # Modify artifact to trigger DRIFT_MODIFIED
        art.write_text("tampered content", encoding="utf-8")
        args_st = p.parse_args(["state", "status", "--dir", str(s_dir), "--json"])
        self.assertEqual(ag_ops._cmd_state(args_st), 0)

        # Delete artifact to trigger FILE_DELETED
        art.unlink()
        self.assertEqual(ag_ops._cmd_state(args_st), 0)

    # -------------------------------------------------------------------------
    # 5. AST-Lint Subcommand (Python, Dot, Context Signatures, Strict)
    # -------------------------------------------------------------------------
    def test_cmd_ast_lint_comprehensive(self) -> None:
        p = ag_ops.build_parser()

        # Nonexistent target
        args_none = p.parse_args(["ast-lint", str(self.root / "nonexistent"), "--json"])
        self.assertEqual(ag_ops._cmd_ast_lint(args_none), 1)

        # Invalid extension (.txt)
        txt_target = self.root / "readme.txt"
        txt_target.write_text("hello", encoding="utf-8")
        args_inv = p.parse_args(["ast-lint", str(txt_target), "--json"])
        self.assertEqual(ag_ops._cmd_ast_lint(args_inv), 1)

        # Clean python file with Rule 12 author
        py_clean = self.root / "clean.py"
        py_clean.write_text(
            "# -*- coding: utf-8 -*-\n"
            "# Creado por Francisco Grandón Vergara\n"
            "def add(a: int, b: int) -> int:\n"
            "    return a + b\n",
            encoding="utf-8",
        )
        args_clean = p.parse_args(["ast-lint", str(py_clean), "--author", "Francisco Grandón Vergara", "--json"])
        self.assertEqual(ag_ops._cmd_ast_lint(args_clean), 0)

        # File with TK001, TK002, and PATH001 violations
        py_bad = self.root / "bad.py"
        py_bad.write_text(
            "# Creado por Francisco Grandón Vergara\n"
            "import tkinter.ttk as ttk\n"
            "def worker():\n"
            "    try:\n"
            "        x = 1\n"
            "    except Exception:\n"
            "        pass\n"  # PATH001
            "    btn = ttk.Button(text='Click', bg='red', font=('Arial', 10.5))\n",  # TK002 & TK001
            encoding="utf-8",
        )
        args_bad = p.parse_args(["ast-lint", str(py_bad), "--json"])
        self.assertEqual(ag_ops._cmd_ast_lint(args_bad), 1)

        # Directory recursive linting
        lint_dir = self.root / "lint_dir"
        lint_dir.mkdir()
        (lint_dir / "a.py").write_text("# Creado por Francisco Grandón Vergara\nx = 1\n", encoding="utf-8")
        args_dir = p.parse_args(["ast-lint", str(lint_dir), "--json"])
        self.assertEqual(ag_ops._cmd_ast_lint(args_dir), 0)

        # Context Signatures and strict mode
        ctx_map = self.root / "context_map.json"
        anchor_file = self.root / "anchor.txt"
        anchor_file.write_text("v1.0.0", encoding="utf-8")
        anchor_sha = ag_ops._sha256_file(anchor_file)

        ctx_map.write_text(json.dumps({
            "TK002": {
                "anchor_file": str(anchor_file),
                "sha256": anchor_sha,
                "expires_utc": "2030-01-01T00:00:00Z",
            }
        }), encoding="utf-8")

        # Modifying anchor file to induce drift
        anchor_file.write_text("v2.0.0", encoding="utf-8")

        # In strict mode, probationary findings exit 2
        args_ctx_strict = p.parse_args(["ast-lint", str(py_bad), "--context-map", str(ctx_map), "--strict", "--json"])
        self.assertEqual(ag_ops._cmd_ast_lint(args_ctx_strict), 2)

    def test_lint_file_rules_and_swallowed_exceptions(self) -> None:
        p_swallow = self.root / "swallow.py"
        p_swallow.write_text(
            "# -*- coding: utf-8 -*-\n"
            "# Creado por Francisco Grandón Vergara\n"
            "import unittest.mock\n"
            "from unittest.mock import Mock\n"
            "from tkinter import ttk\n"
            "import tkinter.ttk as t_ttk\n"
            "from tkinter.ttk import Button\n"
            "def run():\n"
            "    try: a = 1\n"
            "    except Exception: continue\n"
            "    try: b = 2\n"
            "    except Exception: return {}\n"
            "    try: c = 3\n"
            "    except Exception: return []\n"
            "    try: d = 4\n"
            "    except Exception: return False\n"
            "    try: e = 5\n"
            "    except Exception: return None\n"
            "    b1 = Button(font=('Arial', -10.5))\n"
            "    b2 = ttk.Label(font=('Helvetica', +12.5), background='white')\n"
            "    b3 = t_ttk.Entry(foreground='blue')\n",
            encoding="utf-8",
        )
        violations = ag_ops._lint_file(p_swallow, "Francisco Grandón Vergara")
        rules = [v["rule"] for v in violations]
        self.assertIn("PATH002", rules)
        self.assertIn("PATH001", rules)
        self.assertIn("TK001", rules)
        self.assertIn("TK002", rules)

    def test_ast_lint_dot_state_machine_details(self) -> None:
        dot_file = self.root / "machine.dot"
        # Deadlock state (Non-terminal with out-degree 0) & Unreachable state (in-degree 0)
        dot_file.write_text(
            'digraph M {\n'
            '  Init -> StepA;\n'
            '  StepA -> DeadlockState;\n'
            '  OrphanState -> Done;\n'
            '  Done [shape=doublecircle];\n'
            '}\n',
            encoding="utf-8",
        )
        violations = ag_ops._lint_dot_state_machine(dot_file)
        rules = [v["rule"] for v in violations]
        self.assertIn("DOT001", rules)
        self.assertIn("DOT002", rules)

        # Async state without teardown and missing guard
        dot_async = self.root / "async.dot"
        dot_async.write_text(
            'digraph M {\n'
            '  Init -> AwaitingFetch;\n'
            '  AwaitingFetch -> ActiveState [label="onSuccess"];\n'
            '  ActiveState -> Done;\n'
            '  Done [shape=doublecircle];\n'
            '}\n',
            encoding="utf-8",
        )
        violations_async = ag_ops._lint_dot_state_machine(dot_async)
        rules_async = [v["rule"] for v in violations_async]
        self.assertIn("SCAR-PROC-152", rules_async)
        self.assertIn("SCAR-ASYNC-01", rules_async)

    # -------------------------------------------------------------------------
    # 6. Regret-Mine Subcommand (Filtering, Caching, Asymmetry Signals)
    # -------------------------------------------------------------------------
    def test_cmd_regret_mine_comprehensive(self) -> None:
        p = ag_ops.build_parser()

        # Not a git repo
        args_non_repo = p.parse_args(["regret-mine", "--repo", str(self.root / "not_repo"), "--json"])
        self.assertEqual(ag_ops._cmd_regret_mine(args_non_repo), 1)

        self._init_git_repo()

        src_file = self.root / "app.py"
        src_file.write_text("def run():\n    return 'v1'\n", encoding="utf-8")
        subprocess.run([self.git_bin, "add", "."], cwd=self.root, check=True)
        subprocess.run([self.git_bin, "commit", "-m", "feat: initial logic"], cwd=self.root, check=True)

        # Commit 2: String only edit -> string_only_edits_filtered
        src_file.write_text("def run():\n    return 'v2 string only'\n", encoding="utf-8")
        subprocess.run([self.git_bin, "add", "."], cwd=self.root, check=True)
        subprocess.run([self.git_bin, "commit", "-m", "refactor: update string"], cwd=self.root, check=True)

        # Commit 3: Logic change with fix verb intent & line inversion -> genuine regret pair
        src_file.write_text("def run():\n    x = 10\n    return x\n", encoding="utf-8")
        subprocess.run([self.git_bin, "add", "."], cwd=self.root, check=True)
        subprocess.run([self.git_bin, "commit", "-m", "fix: logic error in run()"], cwd=self.root, check=True)

        args_mine = p.parse_args(["regret-mine", "--repo", str(self.root), "--window-min", "120", "--json"])
        rc_mine = ag_ops._cmd_regret_mine(args_mine)
        self.assertEqual(rc_mine, 0)

    # -------------------------------------------------------------------------
    # 7. Main Entrypoint & Stream Reconfiguration
    # -------------------------------------------------------------------------
    def test_main_cli_dispatch(self) -> None:
        # Help exit code 0
        with patch("sys.argv", ["ag_ops", "--help"]):
            with self.assertRaises(SystemExit) as cm:
                ag_ops.main(["--help"])
            self.assertEqual(cm.exception.code, 0)

        # Subcommand dispatch via main()
        ret = ag_ops.main(["ast-lint", str(self.root), "--json"])
        self.assertIn(ret, (0, 1))


if __name__ == "__main__":
    unittest.main()
