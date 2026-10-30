#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Creado por Francisco Grandón Vergara
# Licensed under the MIT License
"""
ag_ops.py (v2) - Deterministic CLI Engine for Agent Governance, Merkle Guardrails,
Log Distillation, Lexical Runlevels, AST/DOT Validation, and Rapid-Regret Mining.
"""

import argparse
import ast
import datetime
import fnmatch
import hashlib
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Set, Tuple


# =============================================================================
# TRANSVERSAL UTILITIES
# =============================================================================

def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write_json(path: pathlib.Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError as exc:
                sys.stderr.write(f"[ag_ops] Cleanup warning for {tmp_path}: {exc}\n")
        raise


def _sha256_file(path: pathlib.Path, normalize_eol: bool = False) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        if normalize_eol:
            content = f.read().replace(b"\r\n", b"\n")
            h.update(content)
        else:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    return h.hexdigest()


def _run_command_isolated(cmd: str, timeout_sec: Optional[float] = None) -> Tuple[int, str, str, bool, float]:
    """
    Executes a shell command in an isolated process group, killing the entire
    process tree on timeout so inherited stdout/stderr pipes never hang.
    """
    t0 = time.perf_counter()
    kwargs: Dict[str, Any] = {
        "shell": True,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True

    proc = subprocess.Popen(cmd, **kwargs)
    timed_out = False
    try:
        stdout_txt, stderr_txt = proc.communicate(timeout=timeout_sec)
        returncode = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except ProcessLookupError as exc:
                sys.stderr.write(f"[ag_ops] Process group already terminated: {exc}\n")
        stdout_txt, stderr_txt = proc.communicate()
        returncode = 124

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
    return returncode, stdout_txt or "", stderr_txt or "", timed_out, elapsed_ms


def _receipt_path_for_target(state_dir: pathlib.Path, test_path: pathlib.Path) -> pathlib.Path:
    norm_target = os.path.normcase(str(test_path.resolve()))
    short_hash = hashlib.sha256(norm_target.encode("utf-8")).hexdigest()[:12]
    return state_dir / f"merkle_guard_{short_hash}.json"


def _parse_ignore_patterns(raw_ignore: Optional[str]) -> List[str]:
    if not raw_ignore:
        return []
    return [p.strip() for p in raw_ignore.split(",") if p.strip()]


def _matches_ignore(rel_posix: str, name: str, patterns: List[str]) -> bool:
    for pat in patterns:
        if fnmatch.fnmatch(rel_posix, pat) or fnmatch.fnmatch(name, pat):
            return True
    return False


def _compute_merkle_tree(
    test_dir: pathlib.Path,
    state_dir: Optional[pathlib.Path] = None,
    receipt_path: Optional[pathlib.Path] = None,
    ignore_patterns: Optional[List[str]] = None,
) -> Tuple[str, Dict[str, str]]:
    """
    Computes a deterministic SHA-256 Merkle manifest of files within test_dir.
    Normalizes CRLF/LF on text files to prevent cross-platform Windows/POSIX drift.
    Excludes only the exact state_dir and receipt_path, __pycache__ (.pyc/.pyo/.pyd),
    root-level .pytest_cache, and explicit user-supplied --ignore patterns recorded
    in the receipt.
    """
    test_dir = test_dir.resolve()
    if not test_dir.exists():
        raise FileNotFoundError(f"Test target does not exist: {test_dir}")

    resolved_state = state_dir.resolve() if state_dir else None
    resolved_receipt = receipt_path.resolve() if receipt_path else None
    patterns = ignore_patterns or []

    files_map: Dict[str, str] = {}
    if test_dir.is_file():
        files_map[test_dir.name] = _sha256_file(test_dir, normalize_eol=True)
    else:
        all_files: List[Tuple[str, pathlib.Path]] = []
        for root, dirs, files in os.walk(test_dir):
            root_path = pathlib.Path(root).resolve()
            filtered_dirs: List[str] = []
            for d in sorted(dirs):
                d_path = (root_path / d).resolve()
                if resolved_state and d_path == resolved_state:
                    continue
                if d == "__pycache__":
                    continue
                if root_path == test_dir and d.startswith(".pytest_cache"):
                    continue
                rel_dir = d_path.relative_to(test_dir).as_posix()
                if _matches_ignore(rel_dir, d, patterns):
                    continue
                filtered_dirs.append(d)
            dirs[:] = filtered_dirs

            for fname in files:
                if fname.endswith((".pyc", ".pyo", ".pyd")):
                    continue
                fpath = (root_path / fname).resolve()
                if resolved_receipt and fpath == resolved_receipt:
                    continue
                if resolved_state and resolved_state in fpath.parents:
                    continue
                if fpath.is_file():
                    rel_posix = fpath.relative_to(test_dir).as_posix()
                    if _matches_ignore(rel_posix, fname, patterns):
                        continue
                    all_files.append((rel_posix, fpath))

        all_files.sort(key=lambda item: item[0])
        for rel_posix, fpath in all_files:
            files_map[rel_posix] = _sha256_file(fpath, normalize_eol=True)

    tree_hasher = hashlib.sha256()
    for rel_posix in sorted(files_map.keys()):
        entry = f"{rel_posix}:{files_map[rel_posix]}\n".encode("utf-8")
        tree_hasher.update(entry)

    return tree_hasher.hexdigest(), files_map


def _resolve_state_dir(test_dir: pathlib.Path, explicit_state_dir: Optional[pathlib.Path]) -> pathlib.Path:
    if explicit_state_dir:
        return explicit_state_dir.resolve()
    if test_dir.is_file():
        return (test_dir.parent / ".ag_state").resolve()
    return (test_dir / ".ag_state").resolve()


def _emit(payload: Dict[str, Any], as_json: bool, exit_code: int = 0) -> int:
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        status_str = "OK" if payload.get("ok") else "FAIL"
        print(f"[{status_str}] {json.dumps(payload, ensure_ascii=False)}")
    return exit_code


# =============================================================================
# SUBCOMMAND 1: GUARD (Merkle Lock, Witnessed Red & Constructive Renegotiate)
# =============================================================================

def _validate_file_line_ref(ref: str) -> Tuple[bool, str]:
    """Validates 'path/to/file.py:42' exists on disk and line is within bounds."""
    if ":" not in ref:
        return False, f"Reference '{ref}' must follow 'file:line' format."
    raw_path, raw_line = ref.rsplit(":", 1)
    try:
        line_no = int(raw_line)
    except ValueError:
        return False, f"Invalid line number in '{ref}'."
    fpath = pathlib.Path(raw_path).resolve()
    if not fpath.is_file():
        return False, f"Referenced file does not exist: {fpath}"
    total_lines = len(fpath.read_text(encoding="utf-8", errors="replace").splitlines())
    if line_no < 1 or line_no > max(1, total_lines):
        return False, f"Line {line_no} out of range (1..{total_lines}) in {fpath.name}"
    return True, f"{fpath.as_posix()}:{line_no}"


def _verify_constructive_witness(
    args: argparse.Namespace,
    stdout_txt: str,
    stderr_txt: str,
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Enforces SCAR-PROC-150 Constructive Witness Receipt when --witness-type or
    --require-witness is supplied on guard renegotiate.
    """
    wtype = (getattr(args, "witness_type", None) or "").strip()
    require_witness = bool(getattr(args, "require_witness", False))
    if not wtype:
        if require_witness:
            return (
                False,
                "LAZY_RETRACTION_REJECTED: --require-witness is active; specify --witness-type (spec-collision | api-lock | arch-fork).",
                None,
            )
        return True, "LEGACY_REASON_ONLY", None

    if wtype == "spec-collision":
        ref_a = (getattr(args, "conflict_a", "") or "").strip()
        ref_b = (getattr(args, "conflict_b", "") or "").strip()
        ok_a, msg_a = _validate_file_line_ref(ref_a)
        ok_b, msg_b = _validate_file_line_ref(ref_b)
        if not (ok_a and ok_b):
            return False, f"INVALID_SPEC_COLLISION_PROOF: {msg_a if not ok_a else msg_b}", None
        if msg_a == msg_b:
            return False, "INVALID_SPEC_COLLISION_PROOF: --conflict-a and --conflict-b must point to distinct locations.", None
        return True, "VALID", {"type": "spec-collision", "conflict_a": msg_a, "conflict_b": msg_b}

    if wtype == "api-lock":
        combined = f"{stdout_txt}\n{stderr_txt}"
        diag_re = re.compile(
            r"(TypeError|AttributeError|ImportError|Final|Protocol|sealed|cannot assign|visibility|private|readonly)",
            re.I,
        )
        if not diag_re.search(combined):
            return False, "INVALID_API_LOCK_PROOF: Command output lacks a verifiable type/boundary lock diagnostic.", None
        return True, "VALID", {"type": "api-lock", "diagnostic_excerpt": combined.strip()[-300:]}

    if wtype == "arch-fork":
        raw_options = [opt.strip() for opt in (getattr(args, "fork_options", "") or "").split("|") if opt.strip()]
        if len(raw_options) < 2:
            return (
                False,
                "INVALID_ARCH_FORK_PROOF: --fork-options requires at least 2 '|' separated options formatted as 'Label@file:line'.",
                None,
            )
        verified_options = []
        for opt in raw_options:
            if "@" not in opt:
                return False, f"INVALID_ARCH_FORK_PROOF: Option '{opt}' must include '@file:line' blast-radius anchor.", None
            label, ref = opt.split("@", 1)
            ok_ref, msg_ref = _validate_file_line_ref(ref.strip())
            if not ok_ref:
                return False, f"INVALID_ARCH_FORK_PROOF: {msg_ref}", None
            verified_options.append({"option": label.strip(), "anchor": msg_ref})
        return True, "VALID", {"type": "arch-fork", "options": verified_options}

    return False, f"UNKNOWN_WITNESS_TYPE: {wtype}", None


def _record_guard_collision(receipt_path: pathlib.Path, receipt_data: Dict[str, Any], event_type: str, detail: Dict[str, Any]) -> None:
    """Appends a mid-flight collision event into the receipt so Rapid-Regret Miner can correlate it."""
    collisions = receipt_data.get("collisions")
    if not isinstance(collisions, list):
        collisions = []
    entry = {"timestamp_utc": _utc_now_iso(), "event": event_type}
    entry.update(detail)
    collisions.append(entry)
    receipt_data["collisions"] = collisions
    try:
        _atomic_write_json(receipt_path, receipt_data)
    except OSError as exc:
        sys.stderr.write(f"[ag_ops] Warning: could not persist collision log to {receipt_path}: {exc}\n")


def _cmd_guard(args: argparse.Namespace) -> int:
    action = args.guard_action
    test_path = pathlib.Path(args.test_dir).resolve()
    if not test_path.exists():
        return _emit(
            {"ok": False, "error": f"TARGET_NOT_FOUND: Test target does not exist: {test_path}"},
            args.json,
            exit_code=1,
        )

    state_dir = _resolve_state_dir(test_path, pathlib.Path(args.state_dir) if args.state_dir else None)
    state_dir.mkdir(parents=True, exist_ok=True)
    receipt_path = _receipt_path_for_target(state_dir, test_path)
    timeout_sec = float(getattr(args, "timeout", 120.0))
    cli_ignore = _parse_ignore_patterns(getattr(args, "ignore", None))

    if action == "witness-red":
        cmd_str = args.cmd.strip()
        if not cmd_str:
            return _emit({"ok": False, "error": "MISSING_CMD: --cmd is required for witness-red"}, args.json, exit_code=1)

        pre_hash, pre_files = _compute_merkle_tree(test_path, state_dir, receipt_path, cli_ignore)
        if not pre_files:
            return _emit(
                {"ok": False, "error": f"EMPTY_TEST_TARGET: No files found to seal in {test_path}"},
                args.json,
                exit_code=1,
            )

        returncode, stdout_txt, stderr_txt, timed_out, elapsed_ms = _run_command_isolated(cmd_str, timeout_sec)

        if timed_out:
            return _emit(
                {"ok": False, "error": f"COMMAND_TIMED_OUT: Test command exceeded {timeout_sec}s during witness-red", "cmd": cmd_str},
                args.json,
                exit_code=1,
            )

        if returncode == 0:
            return _emit(
                {
                    "ok": False,
                    "error": "COOPERATIVE_TEST: Test passed before fix (exit 0). Red state was not witnessed.",
                    "cmd": cmd_str,
                    "elapsed_ms": elapsed_ms,
                },
                args.json,
                exit_code=1,
            )

        expected_exit = getattr(args, "expected_exit", None)
        if expected_exit is not None and returncode != expected_exit:
            return _emit(
                {
                    "ok": False,
                    "error": f"UNEXPECTED_EXIT_CODE: Expected exit code {expected_exit}, got {returncode}.",
                    "cmd": cmd_str,
                    "returncode": returncode,
                    "stderr": stderr_txt[-500:],
                },
                args.json,
                exit_code=1,
            )
        elif expected_exit is None and returncode in (2, 3, 4, 5, 126, 127, 9009):
            return _emit(
                {
                    "ok": False,
                    "error": f"INVALID_TEST_INVOCATION: Exit code {returncode} indicates collection, syntax, or command error rather than assertion failure. Pass --expected-exit {returncode} if intentional.",
                    "cmd": cmd_str,
                    "returncode": returncode,
                    "stderr": (stderr_txt or stdout_txt)[-500:],
                },
                args.json,
                exit_code=1,
            )

        tree_hash, files_map = _compute_merkle_tree(test_path, state_dir, receipt_path, cli_ignore)
        if tree_hash != pre_hash:
            return _emit(
                {
                    "ok": False,
                    "error": "SELF_MUTATING_TEST_DIR: Test execution created or modified files inside test_dir.",
                    "pre_hash": pre_hash,
                    "post_hash": tree_hash,
                },
                args.json,
                exit_code=1,
            )

        receipt = {
            "version": 2,
            "status": "WITNESSED_RED",
            "timestamp_utc": _utc_now_iso(),
            "test_target": str(test_path),
            "cmd": cmd_str,
            "tree_hash": tree_hash,
            "red_exit_code": returncode,
            "elapsed_ms": elapsed_ms,
            "ignored_patterns": cli_ignore,
            "files": files_map,
            "renegotiation_history": [],
            "collisions": [],
        }
        _atomic_write_json(receipt_path, receipt)

        return _emit(
            {
                "ok": True,
                "status": "WITNESSED_RED",
                "tree_hash": tree_hash,
                "cmd": cmd_str,
                "red_exit_code": returncode,
                "files_count": len(files_map),
                "ignored_patterns": cli_ignore,
                "receipt_file": str(receipt_path),
            },
            args.json,
            exit_code=0,
        )

    elif action == "verify-green":
        if not receipt_path.is_file():
            return _emit(
                {"ok": False, "error": f"NO_RED_RECEIPT: No previous witnessed red receipt found at {receipt_path}"},
                args.json,
                exit_code=1,
            )

        try:
            saved_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        except Exception as exc:
            return _emit(
                {"ok": False, "error": f"CORRUPTED_RECEIPT: Failed to parse {receipt_path}: {exc}"},
                args.json,
                exit_code=2,
            )

        if not isinstance(saved_receipt, dict) or saved_receipt.get("version") != 2:
            return _emit(
                {
                    "ok": False,
                    "error": f"CORRUPTED_RECEIPT: Unsupported or missing receipt version (expected 2, got {saved_receipt.get('version') if isinstance(saved_receipt, dict) else None!r}).",
                },
                args.json,
                exit_code=2,
            )

        saved_cmd = (saved_receipt.get("cmd") or "").strip()
        if not saved_cmd:
            return _emit(
                {"ok": False, "error": "CORRUPTED_RECEIPT: Receipt is missing a non-empty witnessed 'cmd'."},
                args.json,
                exit_code=2,
            )

        saved_target = saved_receipt.get("test_target")
        if not saved_target or pathlib.Path(saved_target).resolve() != test_path:
            return _emit(
                {
                    "ok": False,
                    "error": "TARGET_MISMATCH: --test-dir does not match witnessed test_target.",
                    "witnessed_target": saved_target,
                    "attempted_target": str(test_path),
                },
                args.json,
                exit_code=2,
            )

        saved_tree_hash = saved_receipt.get("tree_hash")
        saved_files: Dict[str, str] = saved_receipt.get("files", {})
        if not saved_tree_hash or not isinstance(saved_files, dict) or not saved_files:
            return _emit(
                {"ok": False, "error": "CORRUPTED_RECEIPT: Receipt is missing tree_hash or non-empty files manifest."},
                args.json,
                exit_code=2,
            )

        effective_ignore = cli_ignore if cli_ignore else list(saved_receipt.get("ignored_patterns", []))

        cmd_to_run = args.cmd.strip() if args.cmd else saved_cmd
        if cmd_to_run != saved_cmd:
            _record_guard_collision(
                receipt_path,
                saved_receipt,
                "COMMAND_MISMATCH",
                {"witnessed_cmd": saved_cmd, "attempted_cmd": cmd_to_run},
            )
            return _emit(
                {
                    "ok": False,
                    "error": f"COMMAND_MISMATCH: Provided command '{cmd_to_run}' does not match witnessed command '{saved_cmd}'.",
                    "witnessed_cmd": saved_cmd,
                    "attempted_cmd": cmd_to_run,
                },
                args.json,
                exit_code=2,
            )

        current_tree_hash, current_files = _compute_merkle_tree(test_path, state_dir, receipt_path, effective_ignore)
        if not current_files:
            return _emit(
                {"ok": False, "error": f"EMPTY_TEST_TARGET: No files found in {test_path}"},
                args.json,
                exit_code=1,
            )

        if current_tree_hash != saved_tree_hash:
            changes: List[str] = []
            all_keys = sorted(set(saved_files.keys()) | set(current_files.keys()))
            for k in all_keys:
                if k not in saved_files:
                    changes.append(f"ADDED:{k}")
                elif k not in current_files:
                    changes.append(f"DELETED:{k}")
                elif saved_files[k] != current_files[k]:
                    changes.append(f"MODIFIED:{k}")

            _record_guard_collision(
                receipt_path,
                saved_receipt,
                "EACCES_TEST_TAMPERING",
                {"current_tree_hash": current_tree_hash, "changes": changes},
            )
            return _emit(
                {
                    "ok": False,
                    "error": "EACCES_TEST_TAMPERING: Test files modified during fix without renegotiation",
                    "saved_tree_hash": saved_tree_hash,
                    "current_tree_hash": current_tree_hash,
                    "changes": changes,
                },
                args.json,
                exit_code=2,
            )

        returncode, stdout_txt, stderr_txt, timed_out, elapsed_ms = _run_command_isolated(cmd_to_run, timeout_sec)

        if timed_out:
            _record_guard_collision(receipt_path, saved_receipt, "COMMAND_TIMED_OUT", {"timeout_sec": timeout_sec})
            return _emit(
                {"ok": False, "error": f"COMMAND_TIMED_OUT: Test command exceeded {timeout_sec}s", "cmd": cmd_to_run},
                args.json,
                exit_code=1,
            )

        if returncode != 0:
            tail_excerpt = stderr_txt[-600:] if stderr_txt else stdout_txt[-600:]
            _record_guard_collision(
                receipt_path,
                saved_receipt,
                "TEST_STILL_FAILING",
                {"exit_code": returncode, "stderr_tail": tail_excerpt[-250:]},
            )
            return _emit(
                {
                    "ok": False,
                    "error": f"TEST_STILL_FAILING: Test exited with code {returncode}",
                    "exit_code": returncode,
                    "cmd": cmd_to_run,
                    "stderr_tail": tail_excerpt,
                },
                args.json,
                exit_code=1,
            )

        post_tree_hash, _ = _compute_merkle_tree(test_path, state_dir, receipt_path, effective_ignore)
        if post_tree_hash != saved_tree_hash:
            _record_guard_collision(
                receipt_path,
                saved_receipt,
                "EACCES_TEST_TAMPERING_DURING_RUN",
                {"post_tree_hash": post_tree_hash},
            )
            return _emit(
                {
                    "ok": False,
                    "error": "EACCES_TEST_TAMPERING_DURING_RUN: Test execution mutated test files during verify-green.",
                    "saved_tree_hash": saved_tree_hash,
                    "post_tree_hash": post_tree_hash,
                },
                args.json,
                exit_code=2,
            )

        saved_receipt["status"] = "VERIFIED_GREEN_WITH_MERKLE_LOCK"
        saved_receipt["verified_at"] = _utc_now_iso()
        saved_receipt["green_elapsed_ms"] = elapsed_ms
        _atomic_write_json(receipt_path, saved_receipt)

        return _emit(
            {
                "ok": True,
                "status": "VERIFIED_GREEN_WITH_MERKLE_LOCK",
                "tree_hash": current_tree_hash,
                "cmd": cmd_to_run,
                "elapsed_ms": elapsed_ms,
                "collisions_count": len(saved_receipt.get("collisions", [])),
                "receipt_file": str(receipt_path),
            },
            args.json,
            exit_code=0,
        )

    elif action == "renegotiate":
        reason = (args.reason or "").strip()
        if not reason:
            return _emit({"ok": False, "error": "MISSING_REASON: --reason is mandatory for test renegotiation"}, args.json, exit_code=1)

        cmd_str = args.cmd.strip() if args.cmd else ""
        history: List[Dict[str, Any]] = []
        collisions: List[Dict[str, Any]] = []
        old_tree_hash = None
        old_cmd = None
        inherited_ignore: List[str] = []

        if receipt_path.is_file():
            try:
                old_data = json.loads(receipt_path.read_text(encoding="utf-8"))
                if not isinstance(old_data, dict) or old_data.get("version") != 2:
                    raise ValueError("Receipt version must be 2")
                old_cmd = (old_data.get("cmd") or "").strip()
                old_tree_hash = old_data.get("tree_hash")
                if not old_cmd or not old_tree_hash:
                    raise ValueError("Receipt missing required 'cmd' or 'tree_hash'")
                raw_history = old_data.get("renegotiation_history", [])
                if not isinstance(raw_history, list):
                    raise ValueError("renegotiation_history must be a list")
                history = list(raw_history)
                collisions = list(old_data.get("collisions", [])) if isinstance(old_data.get("collisions"), list) else []
                inherited_ignore = list(old_data.get("ignored_patterns", []))
                history.append({
                    "timestamp": old_data.get("timestamp_utc"),
                    "status": old_data.get("status"),
                    "reason": old_data.get("reason"),
                    "tree_hash": old_tree_hash,
                    "cmd": old_cmd,
                })
            except Exception as exc:
                return _emit(
                    {
                        "ok": False,
                        "error": f"CORRUPTED_RECEIPT: Cannot renegotiate over corrupted receipt at {receipt_path}: {exc}",
                    },
                    args.json,
                    exit_code=2,
                )

        effective_ignore = cli_ignore if cli_ignore else inherited_ignore

        if not cmd_str:
            cmd_str = old_cmd or ""
        if not cmd_str:
            return _emit({"ok": False, "error": "MISSING_CMD: Test command is required for renegotiate"}, args.json, exit_code=1)

        pre_hash, pre_files = _compute_merkle_tree(test_path, state_dir, receipt_path, effective_ignore)
        if not pre_files:
            return _emit(
                {"ok": False, "error": f"EMPTY_TEST_TARGET: No files found to seal in {test_path}"},
                args.json,
                exit_code=1,
            )

        returncode, stdout_txt, stderr_txt, timed_out, elapsed_ms = _run_command_isolated(cmd_str, timeout_sec)

        if timed_out:
            return _emit(
                {"ok": False, "error": f"COMMAND_TIMED_OUT: Test command exceeded {timeout_sec}s during renegotiate", "cmd": cmd_str},
                args.json,
                exit_code=1,
            )

        if returncode == 0:
            return _emit(
                {
                    "ok": False,
                    "error": "COOPERATIVE_RENEGOTIATION: Newly renegotiated test passed immediately (exit 0). It must fail against clean code to be witnessed.",
                    "cmd": cmd_str,
                },
                args.json,
                exit_code=1,
            )

        expected_exit = getattr(args, "expected_exit", None)
        if expected_exit is not None and returncode != expected_exit:
            return _emit(
                {
                    "ok": False,
                    "error": f"UNEXPECTED_EXIT_CODE: Expected exit code {expected_exit}, got {returncode}.",
                    "cmd": cmd_str,
                    "returncode": returncode,
                },
                args.json,
                exit_code=1,
            )
        elif expected_exit is None and returncode in (2, 3, 4, 5, 126, 127, 9009):
            return _emit(
                {
                    "ok": False,
                    "error": f"INVALID_TEST_INVOCATION: Exit code {returncode} indicates collection, syntax, or command error rather than assertion failure.",
                    "cmd": cmd_str,
                    "returncode": returncode,
                    "stderr": (stderr_txt or stdout_txt)[-500:],
                },
                args.json,
                exit_code=1,
            )

        witness_ok, witness_err, witness_proof = _verify_constructive_witness(args, stdout_txt, stderr_txt)
        if not witness_ok:
            return _emit(
                {"ok": False, "error": witness_err},
                args.json,
                exit_code=1,
            )

        tree_hash, files_map = _compute_merkle_tree(test_path, state_dir, receipt_path, effective_ignore)
        if tree_hash != pre_hash:
            return _emit(
                {
                    "ok": False,
                    "error": "SELF_MUTATING_TEST_DIR: Test execution modified files inside test_dir during renegotiate.",
                },
                args.json,
                exit_code=1,
            )

        new_receipt: Dict[str, Any] = {
            "version": 2,
            "status": "RENEGOTIATED_RED",
            "timestamp_utc": _utc_now_iso(),
            "test_target": str(test_path),
            "reason": reason,
            "cmd": cmd_str,
            "tree_hash": tree_hash,
            "previous_tree_hash": old_tree_hash,
            "red_exit_code": returncode,
            "elapsed_ms": elapsed_ms,
            "ignored_patterns": effective_ignore,
            "files": files_map,
            "renegotiation_history": history,
            "collisions": collisions,
        }
        if witness_proof is not None:
            new_receipt["constructive_witness"] = witness_proof

        _atomic_write_json(receipt_path, new_receipt)

        return _emit(
            {
                "ok": True,
                "status": "RENEGOTIATED_RED",
                "reason": reason,
                "new_tree_hash": tree_hash,
                "previous_tree_hash": old_tree_hash,
                "cmd": cmd_str,
                "red_exit_code": returncode,
                "history_count": len(history),
                "constructive_witness": witness_proof,
                "receipt_file": str(receipt_path),
            },
            args.json,
            exit_code=0,
        )

    return _emit({"ok": False, "error": f"UNKNOWN_GUARD_ACTION: {action}"}, args.json, exit_code=1)


# =============================================================================
# SUBCOMMAND 2: DISTILL (Deterministic Output Distillation)
# =============================================================================

_ERROR_LINE_RE = re.compile(
    r"(Traceback \(most recent call last\)"
    r"|^\s*E\s{3}"
    r"|\b(?:[A-Za-z_]\w*(?:Error|Exception)|AssertionError|FAILED|FATAL|PANIC):"
    r"|^FAIL[:\s]"
    r"|^ERROR[:\s]"
    r"|^\s*error(?:\[[A-Z0-9]+\])?:"
    r"|File \".*?\", line \d+)"
)


def _cmd_distill(args: argparse.Namespace) -> int:
    cmd = args.cmd.strip()
    if not cmd:
        return _emit({"ok": False, "error": "MISSING_CMD: --cmd is required for distill"}, args.json, exit_code=1)

    max_lines = max(5, int(args.max_lines))
    log_dir = pathlib.Path(args.log_dir).resolve() if args.log_dir else pathlib.Path("./logs").resolve()
    log_dir.mkdir(parents=True, exist_ok=True)
    timeout_sec = float(getattr(args, "timeout", 120.0))

    returncode, stdout_txt, stderr_txt, timed_out, elapsed_ms = _run_command_isolated(cmd, timeout_sec)
    combined = f"=== STDOUT ===\n{stdout_txt}\n=== STDERR ===\n{stderr_txt}"

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    timestamp_slug = now_utc.strftime("%Y%m%d_%H%M%S_%f")
    log_path = log_dir / f"raw_{timestamp_slug}.log"
    log_path.write_text(combined, encoding="utf-8", errors="replace")

    all_lines = (stdout_txt + "\n" + stderr_txt).splitlines()
    total_lines = len(all_lines)

    if timed_out:
        return _emit(
            {
                "ok": False,
                "error": f"COMMAND_TIMED_OUT: Process exceeded {timeout_sec}s timeout",
                "exit_code": 124,
                "duration_ms": elapsed_ms,
                "total_lines": total_lines,
                "raw_log": str(log_path),
                "tail": all_lines[-15:],
            },
            args.json,
            exit_code=124,
        )

    if returncode == 0:
        tail = [l for l in all_lines if l.strip()][-5:]
        return _emit(
            {
                "ok": True,
                "exit_code": 0,
                "duration_ms": elapsed_ms,
                "total_lines": total_lines,
                "suppressed_lines": max(0, total_lines - len(tail)),
                "raw_log": str(log_path),
                "tail": tail,
            },
            args.json,
            exit_code=0,
        )

    critical_indices = [idx for idx, line in enumerate(all_lines) if _ERROR_LINE_RE.search(line)]

    extracted_lines: List[str] = []
    if critical_indices:
        first_err = critical_indices[0]
        head_budget = max(2, (max_lines - 1) // 3)
        tail_budget = max(2, max_lines - head_budget - 1)

        start_head = max(0, first_err - 2)
        end_head = min(total_lines, start_head + head_budget)
        head_block = all_lines[start_head:end_head]

        tail_start = max(end_head, total_lines - tail_budget)
        tail_block = all_lines[tail_start:]

        extracted_lines = (
            head_block
            + (["... [intermediate lines pruned] ..."] if tail_start > end_head else [])
            + tail_block
        )
    else:
        extracted_lines = all_lines[-max_lines:]

    return _emit(
        {
            "ok": False,
            "exit_code": returncode,
            "duration_ms": elapsed_ms,
            "total_lines": total_lines,
            "distilled_lines": len(extracted_lines),
            "raw_log": str(log_path),
            "critical_delta": extracted_lines,
        },
        args.json,
        exit_code=returncode if returncode > 0 else 1,
    )


# =============================================================================
# SUBCOMMAND 3: STATE (Lexical Runlevels with Artifact Drift Detection)
# =============================================================================

_STEP_FILE_RE = re.compile(r"^(\d{2,4})_(.+)\.json$")
_VALID_STATUSES = {"PENDIENTE", "EN_PROGRESO", "COMPLETADO", "FALLIDO"}


def _cmd_state(args: argparse.Namespace) -> int:
    state_dir = pathlib.Path(args.dir).resolve()
    state_dir.mkdir(parents=True, exist_ok=True)
    action = args.state_action

    if action == "write":
        step_num = int(args.step)
        if step_num < 0 or step_num > 9999:
            return _emit(
                {"ok": False, "error": "INVALID_STEP: --step must be between 0 and 9999"},
                args.json,
                exit_code=1,
            )
        step_str = f"{step_num:02d}"
        slug = re.sub(r"[^a-zA-Z0-9_\-]+", "_", args.name.strip()).strip("_") or "step"
        status = args.status.strip().upper()
        if status not in _VALID_STATUSES:
            return _emit(
                {
                    "ok": False,
                    "error": f"INVALID_STATUS: '{status}' is not in {sorted(_VALID_STATUSES)}",
                },
                args.json,
                exit_code=1,
            )

        summary = (args.summary or "").strip()
        target_file = state_dir / f"{step_str}_{slug}.json"
        conflicting = [
            existing for existing in state_dir.glob(f"{step_str}_*.json")
            if existing != target_file
        ]
        if conflicting and not getattr(args, "replace", False):
            return _emit(
                {
                    "ok": False,
                    "error": f"STEP_CONFLICT: Step {step_str} already exists with a different slug ({[c.name for c in conflicting]}). Pass --replace to overwrite.",
                    "conflicting_files": [str(c) for c in conflicting],
                },
                args.json,
                exit_code=1,
            )

        artifacts_map: Dict[str, str] = {}
        if args.artifacts:
            for item in args.artifacts.split(","):
                item_clean = item.strip()
                if not item_clean:
                    continue
                p = pathlib.Path(item_clean).resolve()
                if p.is_file():
                    artifacts_map[p.as_posix()] = _sha256_file(p)
                else:
                    artifacts_map[p.as_posix()] = "NOT_FOUND"

        record = {
            "step": step_str,
            "name": slug,
            "status": status,
            "summary": summary,
            "timestamp_utc": _utc_now_iso(),
            "artifacts": artifacts_map,
        }

        for existing in conflicting:
            try:
                existing.unlink()
            except OSError as exc:
                sys.stderr.write(f"[ag_ops] Warning: failed to unlink {existing}: {exc}\n")

        _atomic_write_json(target_file, record)

        return _emit(
            {
                "ok": True,
                "written": str(target_file),
                "step": step_str,
                "status": status,
                "artifacts_count": len(artifacts_map),
            },
            args.json,
            exit_code=0,
        )

    elif action == "status":
        records: List[Dict[str, Any]] = []
        drift_warnings: List[Dict[str, Any]] = []

        candidates: List[Tuple[int, str, pathlib.Path]] = []
        for fpath in state_dir.iterdir():
            if fpath.is_file():
                m = _STEP_FILE_RE.match(fpath.name)
                if m:
                    candidates.append((int(m.group(1)), fpath.name, fpath))

        candidates.sort(key=lambda item: (item[0], item[1]))

        for _, _, fpath in candidates:
            try:
                data = json.loads(fpath.read_text(encoding="utf-8"))
                artifacts = data.get("artifacts", {})
                dirty_record = False
                for art_path_str, expected_hash in list(artifacts.items()):
                    art_path = pathlib.Path(art_path_str)
                    if expected_hash == "NOT_FOUND":
                        if art_path.is_file():
                            artifacts[art_path_str] = _sha256_file(art_path)
                            dirty_record = True
                        else:
                            drift_warnings.append({
                                "step": data.get("step"),
                                "artifact": art_path_str,
                                "issue": "ARTIFACT_NEVER_EXISTED",
                            })
                    else:
                        if not art_path.exists():
                            drift_warnings.append({
                                "step": data.get("step"),
                                "artifact": art_path_str,
                                "issue": "FILE_DELETED",
                            })
                        else:
                            actual_hash = _sha256_file(art_path)
                            if actual_hash != expected_hash:
                                drift_warnings.append({
                                    "step": data.get("step"),
                                    "artifact": art_path_str,
                                    "issue": "DRIFT_MODIFIED",
                                    "expected": expected_hash[:12],
                                    "actual": actual_hash[:12],
                                })
                if dirty_record:
                    _atomic_write_json(fpath, data)
                records.append(data)
            except Exception as exc:
                drift_warnings.append({
                    "step": fpath.name.split("_", 1)[0],
                    "artifact": str(fpath),
                    "issue": "CORRUPTED_STATE_FILE",
                    "detail": str(exc),
                })

        last_active = records[-1] if records else None
        has_drift = len(drift_warnings) > 0
        strict_fail = bool(getattr(args, "strict", False)) and has_drift

        return _emit(
            {
                "ok": not strict_fail,
                "runlevels_count": len(records),
                "steps": [r.get("step") for r in records],
                "last_active": last_active.get("name") if last_active else None,
                "last_status": last_active.get("status") if last_active else None,
                "has_drift": has_drift,
                "drift_warnings": drift_warnings,
                "runlevels": records,
            },
            args.json,
            exit_code=2 if strict_fail else 0,
        )

    return _emit({"ok": False, "error": f"UNKNOWN_STATE_ACTION: {action}"}, args.json, exit_code=1)


# =============================================================================
# SUBCOMMAND 4: AST-LINT (Sub-15ms Static AST & DOT State-Machine Checking)
# =============================================================================

_TTK_WIDGETS = {
    "Frame", "Label", "Button", "LabelFrame", "Entry",
    "Combobox", "Notebook", "Treeview", "Progressbar",
    "Checkbutton", "Radiobutton", "Scale", "Scrollbar", "Spinbox",
}


def _dotted_name(node: ast.AST) -> Optional[str]:
    parts: List[str] = []
    curr = node
    while isinstance(curr, ast.Attribute):
        parts.append(curr.attr)
        curr = curr.value
    if isinstance(curr, ast.Name):
        parts.append(curr.id)
        return ".".join(reversed(parts))
    return None


def _is_test_filepath(filename: str) -> bool:
    p = pathlib.Path(filename)
    name_low = p.name.lower()
    if name_low.startswith("test_") or name_low.endswith("_test.py") or name_low == "conftest.py":
        return True
    return any(part.lower() in ("test", "tests", "testing") for part in p.parts)


class _AntigravityVisitor:
    def __init__(self, filename: str):
        self.filename = filename
        self.is_test_file = _is_test_filepath(filename)
        self.violations: List[Dict[str, Any]] = []
        self.ttk_module_aliases: Set[str] = {"ttk", "tkinter.ttk"}
        self.ttk_direct_imports: Set[str] = set()

    def check_tree(self, tree: ast.AST) -> None:
        """Fast two-pass ast.walk scan avoiding NodeVisitor.generic_visit getattr overhead."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                self._check_import(node)
            elif isinstance(node, ast.ImportFrom):
                self._check_import_from(node)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._check_call(node)
            elif isinstance(node, ast.ExceptHandler):
                self._check_except_handler(node)

    def _check_import(self, node: ast.Import) -> None:
        for alias in node.names:
            if alias.name == "tkinter.ttk":
                if alias.asname:
                    self.ttk_module_aliases.add(alias.asname)
                else:
                    self.ttk_module_aliases.add("tkinter.ttk")
            elif alias.name == "tkinter":
                tk_alias = alias.asname or "tkinter"
                self.ttk_module_aliases.add(f"{tk_alias}.ttk")
            elif alias.name in ("unittest.mock", "mock") and not self.is_test_file:
                self.violations.append({
                    "file": self.filename,
                    "line": node.lineno,
                    "rule": "PATH002",
                    "message": f"Mocking library '{alias.name}' imported in production module.",
                    "reflex": "Move mock objects strictly into tests/ and inject real interfaces or protocols in production code.",
                })

    def _check_import_from(self, node: ast.ImportFrom) -> None:
        if node.module == "tkinter":
            for alias in node.names:
                if alias.name == "ttk":
                    self.ttk_module_aliases.add(alias.asname or "ttk")
        elif node.module == "tkinter.ttk":
            for alias in node.names:
                if alias.name == "*":
                    self.ttk_direct_imports.update(_TTK_WIDGETS)
                else:
                    self.ttk_direct_imports.add(alias.asname or alias.name)
        elif node.module in ("unittest.mock", "mock") and not self.is_test_file:
            self.violations.append({
                "file": self.filename,
                "line": node.lineno,
                "rule": "PATH002",
                "message": f"Mocking primitives from '{node.module}' imported in production module.",
                "reflex": "Remove unittest.mock imports from production modules; pass dependencies via constructor or callable parameters.",
            })

    def _check_except_handler(self, node: ast.ExceptHandler) -> None:
        """
        Rule PATH001: Catches silent exception swallowing (`except:` or `except Exception:`
        followed solely by `pass` or `...`) which masks broken path invariants.
        """
        is_broad = node.type is None or (
            isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException")
        )
        if is_broad and len(node.body) == 1:
            stmt = node.body[0]
            is_noop = isinstance(stmt, ast.Pass) or (
                isinstance(stmt, ast.Expr)
                and isinstance(stmt.value, ast.Constant)
                and stmt.value.value is Ellipsis
            )
            if is_noop:
                self.violations.append({
                    "file": self.filename,
                    "line": node.lineno,
                    "rule": "PATH001",
                    "message": "Silent broad exception swallowing ('except: pass') hides broken path invariants.",
                    "reflex": "Catch a specific exception type and log/handle the failure context, or re-raise the error.",
                })

    def _check_call(self, node: ast.Call) -> None:
        func_name = ""
        is_ttk = False

        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            prefix = _dotted_name(node.func.value)
            if prefix in self.ttk_module_aliases and func_name in _TTK_WIDGETS:
                is_ttk = True
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.ttk_direct_imports:
                is_ttk = True

        # Rule TK002: forbidden background/foreground on confirmed ttk widgets only
        if is_ttk:
            for kw in node.keywords:
                if kw.arg in ("background", "foreground", "bg", "fg"):
                    self.violations.append({
                        "file": self.filename,
                        "line": node.lineno,
                        "rule": "TK002",
                        "message": f"Direct '{kw.arg}=' argument forbidden on ttk.{func_name}. Use ttk.Style() or tk equivalent.",
                        "reflex": f"Configure '{kw.arg}' via ttk.Style().configure('<Style>.T{func_name}', ...) or switch to tk.{func_name}.",
                    })

        # Rule TK001: float font size check
        for kw in node.keywords:
            if kw.arg == "font":
                self._check_font_node(kw.value, node.lineno)

    def _check_font_node(self, node_val: ast.AST, lineno: int) -> None:
        if isinstance(node_val, (ast.Tuple, ast.List)) and len(node_val.elts) >= 2:
            size_node = node_val.elts[1]
            float_val: Optional[float] = None
            if isinstance(size_node, ast.Constant) and isinstance(size_node.value, float):
                float_val = size_node.value
            elif (
                isinstance(size_node, ast.UnaryOp)
                and isinstance(size_node.op, (ast.USub, ast.UAdd))
                and isinstance(size_node.operand, ast.Constant)
                and isinstance(size_node.operand.value, float)
            ):
                float_val = -size_node.operand.value if isinstance(size_node.op, ast.USub) else size_node.operand.value

            if float_val is not None:
                self.violations.append({
                    "file": self.filename,
                    "line": lineno,
                    "rule": "TK001",
                    "message": f"Float font size {float_val} forbidden in font tuple. Use integer.",
                    "reflex": f"Replace float font size {float_val} with integer {int(round(float_val))} in the font tuple.",
                })


def _lint_dot_state_machine(dot_path: pathlib.Path) -> List[Dict[str, Any]]:
    """
    Validates Graphviz DOT state machine files against SCAR-PROC-152 & SCAR-ASYNC-01:
    - DOT001: Non-terminal states must have out-degree >= 1 (Deadlock freedom).
    - DOT002: Non-initial states must have in-degree >= 1 (Reachability).
    - SCAR-PROC-152: Async states must have out-degree >= 2 including an explicit teardown/error edge.
    - SCAR-ASYNC-01: Async resolution edges to active states must declare a '[guard: ...]' attribute.
    """
    violations: List[Dict[str, Any]] = []
    try:
        source = dot_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return [{"file": str(dot_path), "line": 1, "rule": "IO_ERROR", "message": str(exc)}]

    edge_re = re.compile(r'^[ \t]*"?([A-Za-z0-9_]+)"?[ \t]*->[ \t]*"?([A-Za-z0-9_]+)"?[ \t]*(?:\[(.*?)\])?', re.M)
    node_attr_re = re.compile(r'^[ \t]*"?([A-Za-z0-9_]+)"?[ \t]*\[(.*?)\]', re.M)

    out_edges: Dict[str, List[Tuple[str, str]]] = {}
    in_degree: Dict[str, int] = {}
    nodes: List[str] = []
    async_nodes: Set[str] = set()

    def _register_node(name: str) -> None:
        if name not in nodes:
            nodes.append(name)

    for m in node_attr_re.finditer(source):
        node_name, attrs = m.group(1), m.group(2)
        if node_name.lower() in ("node", "edge", "graph", "digraph", "subgraph"):
            continue
        _register_node(node_name)
        if "parallelogram" in attrs or "async=true" in attrs or node_name.startswith(("Awaiting", "Fetching", "Stream", "Loading")):
            async_nodes.add(node_name)

    for m in edge_re.finditer(source):
        src, dst, attrs = m.group(1), m.group(2), m.group(3) or ""
        _register_node(src)
        _register_node(dst)
        out_edges.setdefault(src, []).append((dst, attrs))
        in_degree[dst] = in_degree.get(dst, 0) + 1
        if src.startswith(("Awaiting", "Fetching", "Stream", "Loading")):
            async_nodes.add(src)

    if not nodes:
        return violations

    initial_nodes = {nodes[0], "Init", "Initial", "Idle", "Start", "Created"}
    terminal_names = {"disposed", "closed", "done", "completed", "terminated", "end", "final", "cancelled", "error", "failed"}
    exit_keywords = ("error", "cancel", "dispose", "fail", "abort", "timeout", "close")

    for n in nodes:
        outs = out_edges.get(n, [])
        ins = in_degree.get(n, 0)
        if n not in initial_nodes and ins == 0:
            violations.append({
                "file": str(dot_path),
                "line": 1,
                "rule": "DOT002",
                "message": f"Unreachable state: '{n}' has in-degree 0 and is not an initial state.",
                "reflex": f"Connect an incoming transition into '{n}' or remove the orphan state node.",
            })
        if n.lower() not in terminal_names and len(outs) == 0:
            violations.append({
                "file": str(dot_path),
                "line": 1,
                "rule": "DOT001",
                "message": f"Deadlock risk: Non-terminal state '{n}' has out-degree 0.",
                "reflex": f"Add at least one outgoing transition from '{n}' or rename it as a terminal sink.",
            })

    for an in sorted(async_nodes):
        outs = out_edges.get(an, [])
        has_teardown = any(
            any(k in dst.lower() or k in attrs.lower() for k in exit_keywords)
            for dst, attrs in outs
        )
        if len(outs) < 2 or not has_teardown:
            violations.append({
                "file": str(dot_path),
                "line": 1,
                "rule": "SCAR-PROC-152",
                "message": f"Async state '{an}' lacks explicit teardown/cancel/error exit edge (out-degree={len(outs)}).",
                "reflex": f"Add an explicit transition from '{an}' to a Disposed, Cancelled, or Error state.",
            })
        for dst, attrs in outs:
            if not any(k in dst.lower() for k in exit_keywords) and "guard:" not in attrs:
                violations.append({
                    "file": str(dot_path),
                    "line": 1,
                    "rule": "SCAR-ASYNC-01",
                    "message": f"Late-arrival zombie race on '{an} -> {dst}': missing '[guard: ...]' predicate on edge label.",
                    "reflex": f'Add a cancellation/epoch guard on the resolution edge, e.g. {an} -> {dst} [label="onResolve [guard: !isClosed && reqId == activeReqId]"].',
                })

    return violations


def _load_context_signatures(context_map_path: Optional[str]) -> Dict[str, Dict[str, Any]]:
    """
    Loads optional Scar Context Signatures mapping rule IDs to anchor file hashes:
    {
      "TK002": {"anchor_file": "pyproject.toml", "sha256": "<expected_hex>"}
    }
    When the anchor file's current hash diverges from expected_hex, the rule transitions
    from ENFORCED to PROBATIONARY_REVERIFY (preventing Scar Ossification / Autoimmune Drift).
    """
    if not context_map_path:
        return {}
    p = pathlib.Path(context_map_path).resolve()
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _apply_context_signatures(
    violations: List[Dict[str, Any]],
    context_sigs: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Splits violations into (enforced_violations, probationary_warnings) based on
    whether the rule's pinned AST/dependency ContextSignature has drifted.
    """
    if not context_sigs:
        return violations, []

    enforced: List[Dict[str, Any]] = []
    probationary: List[Dict[str, Any]] = []
    drift_cache: Dict[str, bool] = {}

    for v in violations:
        rule_id = v.get("rule", "")
        sig_info = context_sigs.get(rule_id)
        if not sig_info or not isinstance(sig_info, dict):
            v["severity"] = "ENFORCED"
            enforced.append(v)
            continue

        if rule_id not in drift_cache:
            anchor_str = sig_info.get("anchor_file", "")
            expected_sha = sig_info.get("sha256", "")
            anchor_path = pathlib.Path(anchor_str).resolve() if anchor_str else None
            if not anchor_path or not anchor_path.is_file() or not expected_sha:
                drift_cache[rule_id] = True
            else:
                drift_cache[rule_id] = _sha256_file(anchor_path) != expected_sha

        if drift_cache[rule_id]:
            v_copy = dict(v)
            v_copy["severity"] = "PROBATIONARY_REVERIFY"
            v_copy["autoimmune_drift"] = True
            probationary.append(v_copy)
        else:
            v["severity"] = "ENFORCED"
            enforced.append(v)

    return enforced, probationary


def _lint_file(py_path: pathlib.Path, author_target: Optional[str] = None) -> List[Dict[str, Any]]:
    violations: List[Dict[str, Any]] = []
    try:
        source = py_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return [{"file": str(py_path), "line": 1, "rule": "IO_ERROR", "message": str(exc)}]

    if author_target:
        lines = source.splitlines()[:25]
        if not any(author_target.lower() in line.lower() for line in lines):
            violations.append({
                "file": str(py_path),
                "line": 1,
                "rule": "AUTH001",
                "message": f"Missing mandatory authorship header for '{author_target}'.",
                "reflex": f"Add '# Creado por {author_target}' within the first 25 lines of the file.",
            })

    try:
        tree = ast.parse(source, filename=str(py_path))
    except SyntaxError as exc:
        violations.append({
            "file": str(py_path),
            "line": exc.lineno or 1,
            "rule": "SYNTAX_ERROR",
            "message": f"SyntaxError: {exc.msg}",
            "reflex": "Fix the Python syntax error before running static or runtime checks.",
        })
        return violations

    visitor = _AntigravityVisitor(str(py_path))
    visitor.check_tree(tree)
    violations.extend(visitor.violations)
    return violations


def _cmd_ast_lint(args: argparse.Namespace) -> int:
    target_path = pathlib.Path(args.target).resolve()
    if not target_path.exists():
        return _emit(
            {"ok": False, "error": f"TARGET_NOT_FOUND: Lint target does not exist: {target_path}"},
            args.json,
            exit_code=1,
        )

    author_param = (getattr(args, "author", None) or "").strip() or None
    context_sigs = _load_context_signatures(getattr(args, "context_map", None))
    t0 = time.perf_counter()

    raw_violations: List[Dict[str, Any]] = []
    files_checked = 0

    ignore_dirs = {".git", ".venv", "venv", "node_modules", "site-packages", "__pycache__", "build", "dist"}

    if target_path.is_file():
        if target_path.suffix == ".py":
            raw_violations.extend(_lint_file(target_path, author_param))
            files_checked = 1
        elif target_path.suffix == ".dot":
            raw_violations.extend(_lint_dot_state_machine(target_path))
            files_checked = 1
        else:
            return _emit(
                {"ok": False, "error": f"INVALID_TARGET: Expected a .py or .dot file, got: {target_path.name}"},
                args.json,
                exit_code=1,
            )
    elif target_path.is_dir():
        include_dot = bool(getattr(args, "include_dot", False))
        for root, dirs, files in os.walk(target_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ignore_dirs]
            for fname in sorted(files):
                fpath = pathlib.Path(root) / fname
                if fname.endswith(".py"):
                    raw_violations.extend(_lint_file(fpath, author_param))
                    files_checked += 1
                elif include_dot and fname.endswith(".dot"):
                    raw_violations.extend(_lint_dot_state_machine(fpath))
                    files_checked += 1

    enforced_violations, probationary_warnings = _apply_context_signatures(raw_violations, context_sigs)
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)

    payload: Dict[str, Any] = {
        "ok": len(enforced_violations) == 0,
        "elapsed_ms": elapsed_ms,
        "files_checked": files_checked,
        "violations_count": len(enforced_violations),
        "violations": enforced_violations,
    }
    if probationary_warnings:
        payload["probationary_count"] = len(probationary_warnings)
        payload["probationary_warnings"] = probationary_warnings

    return _emit(
        payload,
        args.json,
        exit_code=0 if len(enforced_violations) == 0 else 1,
    )


# =============================================================================
# SUBCOMMAND 5: REGRET-MINE (Stage-1 Rapid-Regret AST & Receipt Miner)
# =============================================================================

_FIX_VERB_RE = re.compile(r"\b(fix|fixes|fixed|bug|hotfix|revert|oops|regret|patch|broken|typo)\b", re.I)
_REFACTOR_VERB_RE = re.compile(r"\b(refactor|refactoring|simplify|cleanup|clean\s+up|style|format|rename)\b", re.I)
_CONTROL_GUARD_RE = re.compile(r"^\s*(if|elif|else|raise|assert|except)\b")


def _extract_ast_function_hashes(py_source: str) -> Dict[str, str]:
    """Maps qualified function/method names to normalized AST body SHA-256 hashes."""
    defs: Dict[str, str] = {}
    try:
        tree = ast.parse(py_source)
    except SyntaxError:
        return defs

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            body_dump = ast.dump(node, include_attributes=False)
            defs[node.name] = hashlib.sha256(body_dump.encode("utf-8")).hexdigest()
    return defs


def _git_changed_line_sets(repo_path: pathlib.Path, commit_sha: str, rel_file: str) -> Tuple[Set[str], Set[str]]:
    """Returns (added_lines, deleted_lines) stripped of whitespace for a file in a commit."""
    cmd = f'git -C "{repo_path}" show --format="" --unified=0 {commit_sha} -- "{rel_file}"'
    rc, out, _, _, _ = _run_command_isolated(cmd, timeout_sec=5.0)
    added: Set[str] = set()
    deleted: Set[str] = set()
    if rc != 0:
        return added, deleted
    for line in out.splitlines():
        if line.startswith("+++") or line.startswith("---"):
            continue
        if line.startswith("+"):
            clean = line[1:].strip()
            if clean:
                added.add(clean)
        elif line.startswith("-"):
            clean = line[1:].strip()
            if clean:
                deleted.add(clean)
    return added, deleted


def _load_receipt_collision_timestamps(state_dir: Optional[pathlib.Path]) -> List[int]:
    """Extracts Unix timestamps of guard collisions and renegotiations from .ag_state."""
    if not state_dir or not state_dir.is_dir():
        return []
    timestamps: List[int] = []
    for fpath in state_dir.glob("merkle_guard_*.json"):
        try:
            data = json.loads(fpath.read_text(encoding="utf-8"))
            for col in data.get("collisions", []):
                ts_str = col.get("timestamp_utc", "")
                if ts_str:
                    dt = datetime.datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
                    timestamps.append(int(dt.timestamp()))
            for ren in data.get("renegotiation_history", []):
                ts_str = ren.get("timestamp", "")
                if ts_str:
                    dt = datetime.datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
                    timestamps.append(int(dt.timestamp()))
        except Exception:
            continue
    return sorted(timestamps)


def _cmd_regret_mine(args: argparse.Namespace) -> int:
    """
    Stage-1 Deterministic Rapid-Regret Miner (Target 90):
    Scans consecutive per-file Git commits within --window-min (default 60m) for
    overlapping AST function modifications and separates genuine Trap-to-Reflex regret
    from healthy Green -> Refactor TDD cadence via Commit-Intent / Test-Delta Asymmetry
    and .ag_state receipt correlation.
    """
    repo_path = pathlib.Path(args.repo).resolve()
    if not (repo_path / ".git").exists():
        return _emit(
            {"ok": False, "error": f"NOT_A_GIT_REPO: No .git directory found at {repo_path}"},
            args.json,
            exit_code=1,
        )

    window_sec = int(args.window_min) * 60
    limit = int(args.limit)
    state_dir = pathlib.Path(args.state_dir).resolve() if getattr(args, "state_dir", None) else (repo_path / ".ag_state")
    receipt_events_ts = _load_receipt_collision_timestamps(state_dir)

    git_cmd = f'git -C "{repo_path}" log -n {limit} --format="COMMIT|%H|%ct|%s" --name-only'
    rc, out, err, _, _ = _run_command_isolated(git_cmd, timeout_sec=15.0)
    if rc != 0:
        return _emit({"ok": False, "error": f"GIT_LOG_FAILED: {err.strip()}"}, args.json, exit_code=1)

    commits: List[Dict[str, Any]] = []
    current: Optional[Dict[str, Any]] = None
    for raw_line in out.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("COMMIT|"):
            _, sha, ts_str, subj = line.split("|", 3)
            current = {"sha": sha, "ts": int(ts_str), "subject": subj, "py_files": [], "test_files": []}
            commits.append(current)
        elif current is not None and line.endswith(".py"):
            if _is_test_filepath(line):
                current["test_files"].append(line)
            else:
                current["py_files"].append(line)

    regret_pairs: List[Dict[str, Any]] = []
    tdd_refactors_filtered = 0

    # commits are ordered newest (index i) to oldest (index j).
    # Track paired_files per 'newer' commit so each file is only compared against
    # its immediately preceding commit C_k -> C_{k+1} (no transitive C1 -> C3 duplicates).
    for i in range(len(commits) - 1):
        newer = commits[i]
        paired_files: Set[str] = set()

        for j in range(i + 1, len(commits)):
            older = commits[j]
            delta_sec = newer["ts"] - older["ts"]
            if delta_sec > window_sec:
                break

            shared_py = (set(newer["py_files"]) & set(older["py_files"])) - paired_files
            if not shared_py:
                continue

            for rel_file in sorted(shared_py):
                paired_files.add(rel_file)

                _, src_new, _, _, _ = _run_command_isolated(f'git -C "{repo_path}" show {newer["sha"]}:"{rel_file}"', 5.0)
                _, src_old, _, _, _ = _run_command_isolated(f'git -C "{repo_path}" show {older["sha"]}:"{rel_file}"', 5.0)
                defs_new = _extract_ast_function_hashes(src_new)
                defs_old = _extract_ast_function_hashes(src_old)
                overlapping_funcs = [
                    fn for fn in defs_new
                    if fn in defs_old and defs_new[fn] != defs_old[fn]
                ]
                if not overlapping_funcs:
                    continue

                has_fix_verb = bool(_FIX_VERB_RE.search(newer["subject"]))
                is_pure_refactor = bool(_REFACTOR_VERB_RE.search(newer["subject"])) and not has_fix_verb

                signals: List[str] = []
                if has_fix_verb:
                    signals.append("FIX_VERB_INTENT")
                if len(newer["test_files"]) > 0:
                    signals.append("TEST_ASSERTION_DELTA")
                if any(older["ts"] <= ev_ts <= newer["ts"] for ev_ts in receipt_events_ts):
                    signals.append("GUARD_COLLISION_RECEIPT")

                if not is_pure_refactor:
                    added_k, _ = _git_changed_line_sets(repo_path, older["sha"], rel_file)
                    _, deleted_k1 = _git_changed_line_sets(repo_path, newer["sha"], rel_file)
                    inverted_lines = added_k & deleted_k1
                    has_guard_inversion = any(_CONTROL_GUARD_RE.search(line) for line in inverted_lines)
                    if inverted_lines and (has_guard_inversion or len(signals) > 0):
                        signals.append("LINE_REVERSAL_OVERLAP")

                if not signals:
                    tdd_refactors_filtered += 1
                    continue

                regret_pairs.append({
                    "file": rel_file,
                    "overlapping_functions": overlapping_funcs,
                    "delta_minutes": round(delta_sec / 60.0, 2),
                    "initial_commit": older["sha"][:8],
                    "regret_commit": newer["sha"][:8],
                    "regret_subject": newer["subject"],
                    "asymmetry_signals": signals,
                })

    return _emit(
        {
            "ok": True,
            "window_minutes": int(args.window_min),
            "commits_scanned": len(commits),
            "tdd_refactors_filtered": tdd_refactors_filtered,
            "regret_pairs_count": len(regret_pairs),
            "regret_pairs": regret_pairs,
        },
        args.json,
        exit_code=0,
    )


# =============================================================================
# CLI PARSER BUILDER
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ag_ops.py",
        description="Deterministic CLI Engine for Agent Governance, Merkle Guardrails, Distillation, Runlevels & Regret Mining.",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # 1. guard
    p_guard = subparsers.add_parser("guard", help="Merkle-locked test verification and contract enforcement.")
    p_guard.add_argument("guard_action", choices=["witness-red", "verify-green", "renegotiate"])
    p_guard.add_argument("--test-dir", required=True, help="Test file or directory to seal in Merkle tree.")
    p_guard.add_argument("--cmd", default="", help="Test execution command line.")
    p_guard.add_argument("--state-dir", default=None, help="Directory to store merkle_guard_<hash>.json (default: .ag_state).")
    p_guard.add_argument("--ignore", default="", help="Comma-separated glob/relative paths to exclude and record in receipt.")
    p_guard.add_argument("--reason", default="", help="Mandatory rationale for renegotiate.")
    p_guard.add_argument(
        "--witness-type",
        choices=["spec-collision", "api-lock", "arch-fork"],
        default=None,
        help="SCAR-PROC-150 Constructive Witness proof type for renegotiate.",
    )
    p_guard.add_argument("--require-witness", action="store_true", help="Reject prose-only renegotiate without --witness-type.")
    p_guard.add_argument("--conflict-a", default="", help="First conflicting requirement 'file:line' for spec-collision.")
    p_guard.add_argument("--conflict-b", default="", help="Second conflicting requirement 'file:line' for spec-collision.")
    p_guard.add_argument("--fork-options", default="", help="Pipe-separated 'OptionA@file:line|OptionB@file:line' for arch-fork.")
    p_guard.add_argument("--expected-exit", type=int, default=None, help="Expected exit code for witness-red/renegotiate.")
    p_guard.add_argument("--timeout", type=float, default=120.0, help="Test execution timeout in seconds.")
    p_guard.add_argument("--json", action="store_true", help="Emit deterministic JSON.")

    # 2. distill
    p_distill = subparsers.add_parser("distill", help="Deterministic output distillation with timeout protection.")
    p_distill.add_argument("--cmd", required=True, help="Command to execute.")
    p_distill.add_argument("--max-lines", type=int, default=35, help="Maximum lines of critical delta.")
    p_distill.add_argument("--log-dir", default="./logs", help="Directory to save raw execution logs.")
    p_distill.add_argument("--timeout", type=float, default=120.0, help="Process timeout in seconds.")
    p_distill.add_argument("--json", action="store_true", help="Emit deterministic JSON.")

    # 3. state
    p_state = subparsers.add_parser("state", help="Lexical runlevel state manager with artifact drift verification.")
    p_state.add_argument("state_action", choices=["write", "status"])
    p_state.add_argument("--dir", required=True, help="State directory containing NN_*.json files.")
    p_state.add_argument("--step", type=int, default=0, help="Step number (e.g. 0, 10, 20).")
    p_state.add_argument("--name", default="step", help="Slug name for the runlevel.")
    p_state.add_argument("--status", default="COMPLETADO", help="Status: PENDIENTE | EN_PROGRESO | COMPLETADO | FALLIDO.")
    p_state.add_argument("--summary", default="", help="Summary text of the phase.")
    p_state.add_argument("--artifacts", default="", help="Comma-separated paths to produced artifacts.")
    p_state.add_argument("--replace", action="store_true", help="Overwrite existing step file if slug differs.")
    p_state.add_argument("--strict", action="store_true", help="Exit with code 2 on status if artifact drift is detected.")
    p_state.add_argument("--json", action="store_true", help="Emit deterministic JSON.")

    # 4. ast-lint
    p_lint = subparsers.add_parser("ast-lint", help="Sub-15ms static AST & DOT state-machine linter.")
    p_lint.add_argument("target", help="Python (.py), Graphviz (.dot) file, or folder to lint.")
    p_lint.add_argument("--author", default=None, help="Optional author string to enforce in file headers (AUTH001).")
    p_lint.add_argument("--include-dot", action="store_true", help="Also lint .dot state machine files when target is a directory.")
    p_lint.add_argument("--context-map", default=None, help="Path to JSON mapping rule IDs to anchor file SHA-256 signatures.")
    p_lint.add_argument("--json", action="store_true", help="Emit deterministic JSON.")

    # 5. regret-mine
    p_regret = subparsers.add_parser("regret-mine", help="Stage-1 Rapid-Regret AST & Receipt Miner over Git history.")
    p_regret.add_argument("--repo", default=".", help="Path to Git repository (default: current directory).")
    p_regret.add_argument("--window-min", type=int, default=60, help="Maximum minutes between overlapping commits (default: 60).")
    p_regret.add_argument("--limit", type=int, default=100, help="Maximum recent commits to scan (default: 100).")
    p_regret.add_argument("--state-dir", default=None, help="Optional .ag_state directory to correlate guard collisions.")
    p_regret.add_argument("--json", action="store_true", help="Emit deterministic JSON.")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError, AttributeError):
                pass

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.subcommand == "guard":
        return _cmd_guard(args)
    if args.subcommand == "distill":
        return _cmd_distill(args)
    if args.subcommand == "state":
        return _cmd_state(args)
    if args.subcommand == "ast-lint":
        return _cmd_ast_lint(args)
    if args.subcommand == "regret-mine":
        return _cmd_regret_mine(args)

    return 1


if __name__ == "__main__":
    sys.exit(main())
