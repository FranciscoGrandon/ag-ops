#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Creado por Francisco Grandón Vergara
# Licensed under the MIT License
"""
ag_ops.py (v2.4) - Deterministic CLI Engine for Agent Governance, Merkle Guardrails,
Git-Anchored Constructive Witnesses, Log Distillation, Lexical Runlevels,
AST/DOT Validation, Scope/Cycle Governance, and Rapid-Regret Mining.
"""

import argparse
import ast
import collections
import configparser
import copy
import datetime
import errno
import fnmatch
import hashlib
import json
import os
import pathlib
import re
import shlex
import shutil
import signal
import subprocess  # nosec B404
import sys
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type, Union

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

# =============================================================================
# TRANSVERSAL UTILITIES
# =============================================================================

_MAX_IN_MEMORY_EOL_BYTES = 10 * 1024 * 1024  # 10 MB threshold for CRLF->LF normalization
_BINARY_SNIFF_BYTES = 8192
_FILE_DIGEST = getattr(hashlib, "file_digest", None)


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write_json(path: pathlib.Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            try:
                os.fsync(f.fileno())
            except OSError as exc:
                if exc.errno not in (
                    errno.EINVAL,
                    getattr(errno, "ENOTSUP", 95),
                    getattr(errno, "EOPNOTSUPP", 95),
                ):
                    raise
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError as exc:
                sys.stderr.write(f"[ag_ops] Cleanup warning for {tmp_path}: {exc}\n")
        raise


def _sha256_file(path: Union[pathlib.Path, str], normalize_eol: bool = False) -> str:
    """
    Computes SHA-256 of a file using native C hashlib.file_digest when possible.
    When normalize_eol=True, inspects the first 8 KB for NUL bytes: binary files
    rewind and hash via file_digest; text files stream in 64 KB chunks normalizing
    CRLF -> LF across chunk boundaries only when b"\\r" is present.
    """
    file_digest = _FILE_DIGEST
    with open(path, "rb") as f:
        if not normalize_eol:
            if file_digest is not None:
                return str(file_digest(f, "sha256").hexdigest())
            h_raw = hashlib.sha256()
            for chunk in iter(lambda: f.read(65536), b""):
                h_raw.update(chunk)
            return h_raw.hexdigest()

        first_chunk = f.read(_BINARY_SNIFF_BYTES)
        if b"\x00" in first_chunk:
            f.seek(0)
            if file_digest is not None:
                return str(file_digest(f, "sha256").hexdigest())
            h_bin = hashlib.sha256()
            for chunk in iter(lambda: f.read(65536), b""):
                h_bin.update(chunk)
            return h_bin.hexdigest()

        if len(first_chunk) < _BINARY_SNIFF_BYTES and b"\r" not in first_chunk:
            return hashlib.sha256(first_chunk).hexdigest()

        h = hashlib.sha256()
        carry_cr = False
        chunk = first_chunk
        while chunk:
            if carry_cr:
                if chunk.startswith(b"\n"):
                    h.update(b"\n")
                    chunk = chunk[1:]
                else:
                    h.update(b"\r")
                carry_cr = False
            if chunk.endswith(b"\r"):
                carry_cr = True
                chunk = chunk[:-1]
            if b"\r" in chunk:
                chunk = chunk.replace(b"\r\n", b"\n")
            if chunk:
                h.update(chunk)
            chunk = f.read(65536)
        if carry_cr:
            h.update(b"\r")
        return h.hexdigest()


def _is_symlink_or_junction(p: pathlib.Path) -> bool:
    """Detects symbolic links and NTFS junction points across POSIX and Windows."""
    try:
        if p.is_symlink() or os.path.islink(p):
            return True
        if hasattr(p, "is_junction") and p.is_junction():
            return True
    except (OSError, ValueError):
        pass
    return False


def _resolve_git_binary() -> str:
    found = shutil.which("git")
    if found:
        return found
    candidates = [
        r"D:\GIT\MinGit-2.56.0.4-64-bit\cmd\git.exe",
        r"C:\Program Files\Git\cmd\git.exe",
        r"C:\Program Files (x86)\Git\cmd\git.exe",
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return "git"


def _run_command_isolated(
    cmd: Union[str, List[str]],
    timeout_sec: Optional[float] = None,
    env: Optional[Dict[str, str]] = None,
) -> Tuple[int, str, str, bool, float]:
    """
    Executes a shell command (str) or direct argv command (List[str]) in an isolated
    process group, killing the entire process tree on timeout so inherited stdout/stderr
    pipes never hang.
    """
    t0 = time.perf_counter()
    use_shell = isinstance(cmd, str)
    kwargs: Dict[str, Any] = {
        "shell": use_shell,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }
    if env is not None:
        kwargs["env"] = env
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True

    proc = subprocess.Popen(cmd, **kwargs)  # nosec B603
    timed_out = False
    try:
        stdout_txt, stderr_txt = proc.communicate(timeout=timeout_sec)
        returncode = proc.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        if os.name == "nt":
            subprocess.run(  # nosec B603 B607
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            try:
                killpg = getattr(os, "killpg", None)
                getpgid = getattr(os, "getpgid", None)
                sigkill = getattr(signal, "SIGKILL", 9)
                if killpg and getpgid:
                    killpg(getpgid(proc.pid), sigkill)
                else:
                    proc.kill()
            except ProcessLookupError as exc:
                sys.stderr.write(f"[ag_ops] Process group already terminated: {exc}\n")
        stdout_txt, stderr_txt = proc.communicate()
        returncode = 124

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
    return returncode, stdout_txt or "", stderr_txt or "", timed_out, elapsed_ms


class GitBatchReader:
    """Persistent `git cat-file --batch` reader reducing K git-show spawns to 1 process."""

    def __init__(self, repo_root: pathlib.Path) -> None:
        self.repo_root = repo_root.resolve()
        self._proc: Optional[subprocess.Popen[bytes]] = None
        self._cache: Dict[str, Optional[bytes]] = {}

    def __enter__(self) -> "GitBatchReader":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _ensure_proc(self) -> subprocess.Popen[bytes]:
        if self._proc is None or self._proc.poll() is not None:
            git_bin = _resolve_git_binary()
            kwargs: Dict[str, Any] = {
                "stdin": subprocess.PIPE,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.DEVNULL,
            }
            if os.name == "nt":
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            self._proc = subprocess.Popen(  # nosec B603
                [git_bin, "-C", str(self.repo_root), "-c", "core.quotepath=false", "cat-file", "--batch"],
                **kwargs,
            )
        return self._proc

    @staticmethod
    def _read_exact(stream: Any, size: int) -> bytes:
        chunks: List[bytes] = []
        remaining = size
        while remaining > 0:
            part = stream.read(remaining)
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        return b"".join(chunks)

    def read_object_bytes(self, spec: str) -> Optional[bytes]:
        if spec in self._cache:
            return self._cache[spec]
        if "\n" in spec or "\r" in spec:
            return None
        proc = self._ensure_proc()
        if proc.stdin is None or proc.stdout is None:
            return None
        try:
            proc.stdin.write((spec + "\n").encode("utf-8"))
            proc.stdin.flush()
            header_raw = proc.stdout.readline()
            if not header_raw:
                self.close()
                return None
            header = header_raw.decode("utf-8", errors="replace").rstrip("\r\n")
            if header.endswith(" missing") or header.endswith(" ambiguous"):
                self._cache[spec] = None
                return None
            parts = header.rsplit(" ", 2)
            if len(parts) != 3:
                self._cache[spec] = None
                return None
            _, obj_type, size_str = parts
            size = int(size_str)
            data = self._read_exact(proc.stdout, size)
            proc.stdout.read(1)
            if obj_type != "blob":
                self._cache[spec] = None
                return None
            self._cache[spec] = data
            return data
        except (OSError, ValueError):
            self.close()
            return None

    def read_text(self, sha: str, rel_path: str) -> Optional[str]:
        raw = self.read_object_bytes(f"{sha}:{rel_path}")
        if raw is None:
            return None
        return raw.decode("utf-8", errors="replace")

    def close(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except OSError:
            pass
        try:
            if proc.stdout is not None:
                proc.stdout.close()
        except OSError:
            pass
        try:
            if proc.poll() is None:
                proc.terminate()
                proc.wait(timeout=1.0)
        except (OSError, subprocess.TimeoutExpired):
            try:
                proc.kill()
            except OSError:
                pass


def _find_git_root_pure(start_path: pathlib.Path) -> Optional[pathlib.Path]:
    """Finds enclosing Git root purely via filesystem walk without spawning git."""
    cur = start_path.resolve()
    if cur.is_file():
        cur = cur.parent
    for candidate in (cur, *cur.parents):
        if (candidate / ".git").exists():
            return candidate
    return None


def _get_git_repo_and_head(target_path: pathlib.Path) -> Tuple[Optional[pathlib.Path], Optional[str]]:
    """
    Resolves the enclosing Git repository root and current HEAD commit SHA for target_path.
    Uses a pure filesystem walk first to avoid spawning git outside repositories.
    Returns (None, None) if not inside a Git repository or if HEAD is unborn.
    """
    repo_root = _find_git_root_pure(target_path)
    if repo_root is None:
        return None, None
    git_bin = _resolve_git_binary()
    rc_head, out_head, _, _, _ = _run_command_isolated(
        [git_bin, "-C", str(repo_root), "rev-parse", "--verify", "HEAD"],
        timeout_sec=5.0,
    )
    if rc_head != 0 or not out_head.strip():
        return repo_root, None
    return repo_root, out_head.strip()


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
    Normalizes CRLF/LF on text files to prevent cross-platform Windows/POSIX drift,
    while preserving raw byte hashes for binary files (containing NUL bytes).
    Excludes only the exact state_dir (when nested inside test_dir) and receipt_path,
    __pycache__ (.pyc/.pyo/.pyd), root-level .pytest_cache, and explicit user-supplied
    --ignore patterns recorded in the receipt.
    """
    if _is_symlink_or_junction(test_dir):
        raise ValueError(f"Symlinks and junctions are forbidden in Merkle guard target: {test_dir}")
    test_dir = test_dir.resolve()
    if not test_dir.exists():
        raise FileNotFoundError(f"Test target does not exist: {test_dir}")

    resolved_state = state_dir.resolve() if state_dir else None
    state_is_inside_test = bool(resolved_state and test_dir in resolved_state.parents)
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
                d_raw = root_path / d
                if _is_symlink_or_junction(d_raw):
                    raise ValueError(f"Symlinks and junctions are forbidden in Merkle guard target: {d_raw}")
                d_path = d_raw.resolve()
                if state_is_inside_test and resolved_state and d_path == resolved_state:
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
                fpath_raw = root_path / fname
                if _is_symlink_or_junction(fpath_raw):
                    raise ValueError(f"Symlinks and junctions are forbidden in Merkle guard target: {fpath_raw}")
                fpath = fpath_raw.resolve()
                if resolved_receipt and fpath == resolved_receipt:
                    continue
                if state_is_inside_test and resolved_state and resolved_state in fpath.parents:
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

_SCHEMA_VERSION = "2.4"
_ROOT_CONFIG_FILENAMES: Tuple[str, ...] = (
    "conftest.py",
    "pytest.ini",
    "pyproject.toml",
    "setup.cfg",
    "tox.ini",
    "sitecustomize.py",
    "usercustomize.py",
)
_PYTEST_INI_CONFIG_FILENAMES: Tuple[str, ...] = (
    "pyproject.toml",
    "pytest.ini",
    "tox.ini",
    "setup.cfg",
)
_TAINTED_ENV_KEYS: Tuple[str, ...] = ("PYTEST_ADDOPTS", "PYTHONSTARTUP")
_ALWAYS_FORBIDDEN_ADDOPTS: Set[str] = {
    "--collect-only",
    "--co",
    "--setup-only",
    "--setup-plan",
}
_CMD_DECLARED_ADDOPTS: Tuple[str, ...] = ("--ignore", "--ignore-glob", "-k")

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_PYTEST_SUMMARY_LINE_RE = re.compile(
    r"(?:\b(?:passed|failed|errors?|skipped|xfailed|xpassed|deselected)\b.*\bin\s+\d+(?:\.\d+)?s\b|\bno tests ran\b)",
    re.I,
)
_PYTEST_COUNT_TOKEN_RE = re.compile(
    r"\b(\d+)\s+(passed|failed|errors?|skipped|xfailed|xpassed|deselected)\b",
    re.I,
)
_PYTEST_COLLECTED_ZERO_RE = re.compile(r"\bcollected\s+0\s+items\b|\b\d+\s+tests?\s+collected\b", re.I)
_UNITTEST_RAN_RE = re.compile(r"^Ran\s+(\d+)\s+tests?\s+in\s+\d", re.M)

_ERROR_LINE_RE = re.compile(
    r"(Traceback \(most recent call last\)"
    r"|^\s*E\s{3}"
    r"|\b(?:[A-Za-z_]\w*(?:Error|Exception)|AssertionError|FAILED|FATAL|PANIC):"
    r"|^FAIL[:\s]"
    r"|^ERROR[:\s]"
    r"|^\s*error(?:\[[A-Z0-9]+\])?:"
    r"|File \".*?\", line \d+)"
)


def _extract_red_signature(stdout_txt: str, stderr_txt: str, max_items: int = 8) -> List[str]:
    """
    Extracts deterministic failure lines (pytest 'FAILED ...', 'E   AssertionError...', etc.)
    during witness-red so the receipt records the exact red invariant that failed.
    """
    all_lines = stdout_txt.splitlines() + stderr_txt.splitlines()
    matches = [line.strip() for line in all_lines if _ERROR_LINE_RE.search(line) and line.strip()]
    if matches:
        return matches[:max_items]
    non_empty = [line.strip() for line in all_lines if line.strip()]
    return non_empty[-min(5, len(non_empty)):] if non_empty else []


def _validate_file_line_ref(
    ref: str,
    repo_root: Optional[pathlib.Path] = None,
    pinned_sha: Optional[str] = None,
    git_reader: Optional[GitBatchReader] = None,
) -> Tuple[bool, str, str]:
    """
    Validates 'path/to/file.py:42' exists, is non-empty, line is within bounds,
    and the cited line is non-trivial (not blank or a pure comment).
    When repo_root and pinned_sha are available, reads file contents directly from
    Git object storage (via GitBatchReader or `git show <pinned_sha>:<rel_path>`)
    to prevent working-tree forgery.
    Returns (ok, canonical_ref_or_error, cited_line_excerpt).
    """
    if ":" not in ref:
        return False, f"Reference '{ref}' must follow 'file:line' format.", ""
    raw_path, raw_line = ref.rsplit(":", 1)
    if not raw_path.strip():
        return False, f"Reference '{ref}' is missing a file path.", ""
    try:
        line_no = int(raw_line)
    except ValueError:
        return False, f"Invalid line number in '{ref}'.", ""

    fpath = pathlib.Path(raw_path.strip()).resolve()
    content_text: Optional[str] = None
    canonical_path_str = fpath.as_posix()

    if repo_root is not None and pinned_sha:
        try:
            rel_git_path = fpath.relative_to(repo_root).as_posix()
            if git_reader is not None:
                out_txt = git_reader.read_text(pinned_sha, rel_git_path)
                rc = 0 if out_txt is not None else 1
            else:
                git_bin = _resolve_git_binary()
                rc, out_txt, _, _, _ = _run_command_isolated(
                    [git_bin, "-C", str(repo_root), "-c", "core.quotepath=false", "show", f"{pinned_sha}:{rel_git_path}"],
                    timeout_sec=5.0,
                )
            if rc == 0 and out_txt is not None:
                content_text = out_txt
            elif not fpath.is_file():
                return (
                    False,
                    f"Referenced file '{rel_git_path}' does not exist in pinned commit {pinned_sha[:8]} or on disk.",
                    "",
                )
            else:
                return (
                    False,
                    f"UNCOMMITTED_WITNESS_FILE: '{rel_git_path}' is not committed in pinned HEAD ({pinned_sha[:8]}). Working-tree forgery rejected.",
                    "",
                )
        except ValueError:
            pass

    if content_text is None:
        if not fpath.is_file():
            return False, f"Referenced file does not exist: {fpath}", ""
        content_text = fpath.read_text(encoding="utf-8", errors="replace")

    lines = content_text.splitlines()
    total_lines = len(lines)
    if total_lines == 0:
        return False, f"Referenced file is empty (0 lines): {fpath.name}", ""
    if line_no < 1 or line_no > total_lines:
        return False, f"Line {line_no} out of range (1..{total_lines}) in {fpath.name}", ""

    cited_line = lines[line_no - 1].strip()
    if not cited_line or cited_line.startswith("#") or cited_line.startswith("//"):
        return (
            False,
            f"TRIVIAL_WITNESS_LINE: Line {line_no} in {fpath.name} is blank or a pure comment; cite an active contract or code statement.",
            "",
        )

    return True, f"{canonical_path_str}:{line_no}", cited_line[:200]


def _verify_constructive_witness(
    args: argparse.Namespace,
    stdout_txt: str,
    stderr_txt: str,
    repo_root: Optional[pathlib.Path] = None,
    pinned_sha: Optional[str] = None,
    git_reader: Optional[GitBatchReader] = None,
) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    """
    Enforces SCAR-PROC-150 Constructive Witness Receipt when --witness-type or
    --require-witness is supplied on guard renegotiate.
    Anchors file:line references to pinned_sha in Git when available to defeat
    working-tree forgery, and records cited line excerpts for auditability.
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
        ok_a, msg_a, excerpt_a = _validate_file_line_ref(ref_a, repo_root, pinned_sha, git_reader=git_reader)
        ok_b, msg_b, excerpt_b = _validate_file_line_ref(ref_b, repo_root, pinned_sha, git_reader=git_reader)
        if not (ok_a and ok_b):
            return False, f"INVALID_SPEC_COLLISION_PROOF: {msg_a if not ok_a else msg_b}", None
        if msg_a == msg_b:
            return False, "INVALID_SPEC_COLLISION_PROOF: --conflict-a and --conflict-b must point to distinct locations.", None
        return (
            True,
            "VALID",
            {
                "type": "spec-collision",
                "conflict_a": msg_a,
                "excerpt_a": excerpt_a,
                "conflict_b": msg_b,
                "excerpt_b": excerpt_b,
                "git_anchored_sha": pinned_sha,
            },
        )

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
        seen_labels: Set[str] = set()
        seen_anchors: Set[str] = set()
        for opt in raw_options:
            if "@" not in opt:
                return False, f"INVALID_ARCH_FORK_PROOF: Option '{opt}' must include '@file:line' blast-radius anchor.", None
            label, ref = opt.split("@", 1)
            clean_label = label.strip()
            if not clean_label:
                return False, f"INVALID_ARCH_FORK_PROOF: Option '{opt}' must have a non-empty option label before '@'.", None
            ok_ref, msg_ref, excerpt_ref = _validate_file_line_ref(ref.strip(), repo_root, pinned_sha, git_reader=git_reader)
            if not ok_ref:
                return False, f"INVALID_ARCH_FORK_PROOF: {msg_ref}", None
            if clean_label in seen_labels:
                return False, f"INVALID_ARCH_FORK_PROOF: Duplicate fork option label '{clean_label}'.", None
            if msg_ref in seen_anchors:
                return False, f"INVALID_ARCH_FORK_PROOF: Duplicate fork option blast-radius anchor '{msg_ref}'.", None
            seen_labels.add(clean_label)
            seen_anchors.add(msg_ref)
            verified_options.append({"option": clean_label, "anchor": msg_ref, "excerpt": excerpt_ref})
        return True, "VALID", {"type": "arch-fork", "options": verified_options, "git_anchored_sha": pinned_sha}

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


def _resolve_root_config_stop_dir(test_path: pathlib.Path) -> pathlib.Path:
    """Resolves upper ancestor boundary for root_config_manifest (git root, cwd if ancestor, else test dir)."""
    resolved = test_path.resolve()
    start_dir = resolved if resolved.is_dir() else resolved.parent
    git_root = _find_git_root_pure(start_dir)
    if git_root is not None:
        return git_root
    cwd = pathlib.Path.cwd().resolve()
    if cwd == start_dir or cwd in start_dir.parents:
        return cwd
    return start_dir


def _collect_root_config_manifest(
    test_path: pathlib.Path,
    stop_dir: Optional[pathlib.Path] = None,
) -> Tuple[pathlib.Path, Dict[str, str], List[pathlib.Path]]:
    """
    Seals root pytest/python bootstrap config files (including ABSENT markers)
    from test_path.parent up to stop_dir (git root or workspace boundary).
    Also returns existing pytest config files (including inside test_path) for addopts inspection.
    """
    resolved = test_path.resolve()
    base = (stop_dir or _resolve_root_config_stop_dir(resolved)).resolve()

    ancestors: List[pathlib.Path] = []
    if not (resolved.is_dir() and resolved == base):
        cur = resolved.parent
        while cur == base or base in cur.parents:
            if _is_symlink_or_junction(cur):
                raise ValueError(f"Symlinks and junctions are forbidden in ancestor path: {cur}")
            ancestors.append(cur)
            if cur == base or cur.parent == cur:
                break
            cur = cur.parent

    manifest: Dict[str, str] = {}
    ini_paths: Set[pathlib.Path] = set()
    for anc in ancestors:
        for fname in _ROOT_CONFIG_FILENAMES:
            cand = anc / fname
            if _is_symlink_or_junction(cand):
                raise ValueError(f"Symlinks and junctions are forbidden in root config path: {cand}")
            rel_key = cand.relative_to(base).as_posix()
            if cand.is_file():
                manifest[rel_key] = _sha256_file(cand, normalize_eol=True)
                if fname in _PYTEST_INI_CONFIG_FILENAMES:
                    ini_paths.add(cand)
            else:
                manifest[rel_key] = "ABSENT"

    if resolved.is_dir():
        for fname in _PYTEST_INI_CONFIG_FILENAMES:
            cand = resolved / fname
            if _is_symlink_or_junction(cand):
                raise ValueError(f"Symlinks and junctions are forbidden in config path: {cand}")
            if cand.is_file():
                ini_paths.add(cand)

    ordered_manifest = dict(sorted(manifest.items()))
    ordered_ini = sorted(ini_paths, key=lambda p: p.as_posix())
    return base, ordered_manifest, ordered_ini


def _verify_root_config_manifest(
    saved_receipt: Dict[str, Any],
    test_path: pathlib.Path,
) -> Tuple[bool, List[str], List[pathlib.Path]]:
    """
    Verifies root_config_manifest against disk (if sealed in receipt).
    Returns (ok, drift_changes, existing_ini_paths).
    """
    saved_manifest = saved_receipt.get("root_config_manifest")
    if not isinstance(saved_manifest, dict):
        # Legacy v2.3 receipt without root_config_manifest
        _, _, ini_paths = _collect_root_config_manifest(test_path)
        return True, [], ini_paths

    base_str = saved_receipt.get("root_config_base")
    base = pathlib.Path(base_str).resolve() if isinstance(base_str, str) and base_str else _resolve_root_config_stop_dir(test_path)
    changes: List[str] = []
    ini_set: Set[pathlib.Path] = set()

    cur = test_path.resolve().parent
    while cur == base or base in cur.parents:
        if _is_symlink_or_junction(cur):
            changes.append(f"SYMLINK_ANCESTOR:{cur.relative_to(base).as_posix() or '.'}")
        if cur == base or cur.parent == cur:
            break
        cur = cur.parent

    for rel_key, expected_val in sorted(saved_manifest.items()):
        cand = base / rel_key
        if _is_symlink_or_junction(cand):
            changes.append(f"SYMLINK:{rel_key}")
            continue
        if expected_val == "ABSENT":
            if cand.exists():
                changes.append(f"ADDED:{rel_key}")
        else:
            if not cand.is_file():
                changes.append(f"DELETED:{rel_key}")
            else:
                actual_sha = _sha256_file(cand, normalize_eol=True)
                if actual_sha != expected_val:
                    changes.append(f"MODIFIED:{rel_key}")
                elif cand.name in _PYTEST_INI_CONFIG_FILENAMES:
                    ini_set.add(cand)

    if test_path.is_dir():
        for fname in _PYTEST_INI_CONFIG_FILENAMES:
            cand = test_path / fname
            if cand.is_file() and not _is_symlink_or_junction(cand):
                ini_set.add(cand)

    return len(changes) == 0, changes, sorted(ini_set, key=lambda p: p.as_posix())


def _safe_shlex_split(text: str, posix_mode: bool = True) -> List[str]:
    if not text or not text.strip():
        return []
    try:
        return shlex.split(text, posix=posix_mode)
    except ValueError:
        return text.split()


def _extract_flag_values(tokens: List[str], flag: str) -> Tuple[bool, Set[str]]:
    present = False
    values: Set[str] = set()
    i = 0
    while i < len(tokens):
        tok = tokens[i].strip("\"'")
        if tok == flag:
            present = True
            if i + 1 < len(tokens):
                values.add(tokens[i + 1].strip("\"'"))
                i += 2
                continue
        elif tok.startswith(f"{flag}="):
            present = True
            values.add(tok.split("=", 1)[1].strip("\"'"))
        elif flag == "-k" and tok.startswith("-k") and not tok.startswith("--") and len(tok) > 2:
            present = True
            values.add(tok[2:].strip("\"'"))
        i += 1
    return present, values


def _extract_addopts_tokens(cfg_path: pathlib.Path) -> Tuple[List[str], Optional[str]]:
    """Extracts addopts tokens from pyproject.toml, pytest.ini, tox.ini, or setup.cfg."""
    try:
        raw_text = cfg_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], f"Failed to read {cfg_path.name}: {exc}"

    name_low = cfg_path.name.lower()
    if name_low == "pyproject.toml":
        if tomllib is None:
            return [], "tomllib unavailable (requires Python 3.11+)"
        try:
            data = tomllib.loads(raw_text)
        except Exception as exc:
            return [], f"Invalid TOML in {cfg_path.name}: {exc}"
        ini_opts = data.get("tool", {}).get("pytest", {}).get("ini_options", {})
        if not isinstance(ini_opts, dict):
            return [], None
        raw_addopts = ini_opts.get("addopts")
        if isinstance(raw_addopts, str):
            return _safe_shlex_split(raw_addopts, posix_mode=True), None
        if isinstance(raw_addopts, list):
            tokens: List[str] = []
            for item in raw_addopts:
                tokens.extend(_safe_shlex_split(str(item), posix_mode=True))
            return tokens, None
        return [], None

    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read_string(raw_text)
    except configparser.Error as exc:
        return [], f"Invalid INI in {cfg_path.name}: {exc}"

    sections = ("tool:pytest", "pytest") if name_low == "setup.cfg" else ("pytest",)
    for sec in sections:
        if cp.has_option(sec, "addopts"):
            raw_val = cp.get(sec, "addopts")
            return _safe_shlex_split(raw_val, posix_mode=True), None
    return [], None


def _matches_forbid_addopts(tokens: List[str], forbid_patterns: List[str]) -> Optional[str]:
    clean_tokens = [t.strip("\"'") for t in tokens]
    for pat in forbid_patterns:
        norm_pat = re.sub(r"\s+", " ", pat.strip())
        if not norm_pat:
            continue
        collapsed_pat = norm_pat.replace(" ", "")
        for idx, tok in enumerate(clean_tokens):
            if tok == norm_pat or tok == collapsed_pat or tok.startswith(f"{norm_pat}="):
                return norm_pat
            if idx + 1 < len(clean_tokens):
                pair_spaced = f"{tok} {clean_tokens[idx + 1]}"
                pair_collapsed = f"{tok}{clean_tokens[idx + 1]}"
                if pair_spaced == norm_pat or pair_collapsed == collapsed_pat:
                    return norm_pat
    return None


def _inspect_pytest_addopts(
    config_paths: List[pathlib.Path],
    cmd_str: str,
    forbid_addopts: List[str],
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Inspects addopts across pyproject.toml / pytest.ini / tox.ini / setup.cfg.
    Blocks collection-only flags, undeclared --ignore/--ignore-glob/-k filters,
    and user-declared --forbid-addopts tokens.
    """
    cmd_tokens = _safe_shlex_split(cmd_str, posix_mode=(os.name != "nt"))
    declared_flags = {flag: _extract_flag_values(cmd_tokens, flag) for flag in _CMD_DECLARED_ADDOPTS}

    for cfg_path in config_paths:
        tokens, parse_err = _extract_addopts_tokens(cfg_path)
        if parse_err:
            return False, {
                "error": f"UNSAFE_PYTEST_ADDOPTS: {parse_err}",
                "file": str(cfg_path),
                "token": "<parse_error>",
            }
        if not tokens:
            continue

        for raw_tok in tokens:
            tok = raw_tok.strip("\"'")
            base_opt = tok.split("=", 1)[0]
            if base_opt in _ALWAYS_FORBIDDEN_ADDOPTS:
                return False, {
                    "error": f"UNSAFE_PYTEST_ADDOPTS: Forbidden addopts token '{tok}' in {cfg_path.name}.",
                    "file": str(cfg_path),
                    "token": tok,
                }

        for flag in _CMD_DECLARED_ADDOPTS:
            in_addopts, addopts_vals = _extract_flag_values(tokens, flag)
            if not in_addopts:
                continue
            in_cmd, cmd_vals = declared_flags[flag]
            if not in_cmd or (addopts_vals and not addopts_vals.issubset(cmd_vals)):
                bad_val = next(iter(sorted(addopts_vals - cmd_vals)), flag)
                bad_tok = f"{flag} {bad_val}" if bad_val != flag else flag
                return False, {
                    "error": f"UNSAFE_PYTEST_ADDOPTS: Undeclared '{bad_tok}' in {cfg_path.name} addopts not present in sealed --cmd.",
                    "file": str(cfg_path),
                    "token": bad_tok,
                }

        matched_forbid = _matches_forbid_addopts(tokens, forbid_addopts)
        if matched_forbid:
            return False, {
                "error": f"UNSAFE_PYTEST_ADDOPTS: Explicitly forbidden addopts pattern '{matched_forbid}' in {cfg_path.name}.",
                "file": str(cfg_path),
                "token": matched_forbid,
            }

    return True, None


def _check_and_sanitize_env(
    allow_passthrough: bool,
    saved_env_policy: Optional[Dict[str, Any]] = None,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Dict[str, str]], Dict[str, Any]]:
    """
    Detects PYTEST_ADDOPTS / PYTHONSTARTUP taint in os.environ and returns sanitized env.
    """
    if isinstance(saved_env_policy, dict) and saved_env_policy.get("passthrough_allowed") is False and allow_passthrough:
        return (
            False,
            {
                "error": "ENV_TAINT_DETECTED: --allow-env-passthrough cannot relax sealed env_policy from witness-red.",
                "tainted_vars": list(_TAINTED_ENV_KEYS),
            },
            None,
            {"sanitized_keys": list(_TAINTED_ENV_KEYS), "passthrough_allowed": False},
        )

    tainted = [k for k in _TAINTED_ENV_KEYS if os.environ.get(k, "").strip()]
    policy = {"sanitized_keys": list(_TAINTED_ENV_KEYS), "passthrough_allowed": allow_passthrough}
    if tainted and not allow_passthrough:
        return (
            False,
            {
                "error": f"ENV_TAINT_DETECTED: Forbidden environment variable(s) set: {', '.join(tainted)}.",
                "tainted_vars": tainted,
            },
            None,
            policy,
        )

    clean_env = os.environ.copy()
    if not allow_passthrough:
        for k in _TAINTED_ENV_KEYS:
            clean_env.pop(k, None)
    return True, None, clean_env, policy


def _extract_test_execution_counts(
    cmd_str: str,
    stdout_txt: str,
    stderr_txt: str,
) -> Optional[Dict[str, Any]]:
    """
    Extracts executed test counts from pytest or unittest output.
    Returns None only when the command is a non-pytest/non-unittest custom runner
    without standard test summary output.
    """
    combined = _ANSI_ESCAPE_RE.sub("", f"{stdout_txt}\n{stderr_txt}")
    is_pytest_cmd = bool(re.search(r"\bpytest\b|\bpy\.test\b", cmd_str, re.I))
    is_unittest_cmd = bool(re.search(r"\bunittest\b", cmd_str, re.I))

    for line in reversed(combined.splitlines()):
        if _PYTEST_SUMMARY_LINE_RE.search(line):
            if "no tests ran" in line.lower():
                return {
                    "runner": "pytest",
                    "total": 0,
                    "passed": 0,
                    "failed": 0,
                    "error": 0,
                    "skipped": 0,
                    "xfailed": 0,
                    "xpassed": 0,
                }
            counts: Dict[str, int] = {
                "passed": 0,
                "failed": 0,
                "error": 0,
                "skipped": 0,
                "xfailed": 0,
                "xpassed": 0,
            }
            for num_str, label in _PYTEST_COUNT_TOKEN_RE.findall(line):
                lbl = label.lower()
                key = "error" if lbl.startswith("error") else lbl
                if key in counts:
                    counts[key] += int(num_str)
            total = (
                counts["passed"]
                + counts["failed"]
                + counts["error"]
                + counts["skipped"]
                + counts["xfailed"]
                + counts["xpassed"]
            )
            return {"runner": "pytest", "total": total, **counts}

    m_unit = _UNITTEST_RAN_RE.search(combined)
    if m_unit:
        return {"runner": "unittest", "total": int(m_unit.group(1))}

    if _PYTEST_COLLECTED_ZERO_RE.search(combined):
        return {"runner": "pytest", "total": 0}
    if is_pytest_cmd:
        return {"runner": "pytest", "total": 0}
    if is_unittest_cmd:
        return {"runner": "unittest", "total": 0}
    return None


def _git_merge_base(repo_root: pathlib.Path, ref_a: str, ref_b: str = "HEAD") -> Optional[str]:
    git_bin = _resolve_git_binary()
    rc, out, _, _, _ = _run_command_isolated(
        [git_bin, "-C", str(repo_root), "merge-base", ref_a, ref_b],
        timeout_sec=5.0,
    )
    if rc != 0 or not out.strip():
        return None
    return out.strip()


def _git_is_ancestor(repo_root: pathlib.Path, ancestor_sha: str, descendant_ref: str = "HEAD") -> bool:
    git_bin = _resolve_git_binary()
    rc, _, _, _, _ = _run_command_isolated(
        [git_bin, "-C", str(repo_root), "merge-base", "--is-ancestor", ancestor_sha, descendant_ref],
        timeout_sec=5.0,
    )
    return rc == 0


def _extract_cited_spec_files(args: argparse.Namespace, repo_root: pathlib.Path) -> List[str]:
    raw_refs: List[str] = []
    for attr in ("conflict_a", "conflict_b"):
        val = (getattr(args, attr, "") or "").strip()
        if val and ":" in val:
            raw_refs.append(val.rsplit(":", 1)[0].strip())
    raw_fork = (getattr(args, "fork_options", "") or "").strip()
    if raw_fork:
        for opt in raw_fork.split("|"):
            opt = opt.strip()
            if "@" in opt:
                ref_part = opt.split("@", 1)[1].strip()
                if ":" in ref_part:
                    raw_refs.append(ref_part.rsplit(":", 1)[0].strip())

    rel_files: Set[str] = set()
    for raw_p in raw_refs:
        if not raw_p:
            continue
        p = pathlib.Path(raw_p).resolve()
        try:
            rel_files.add(p.relative_to(repo_root).as_posix())
        except ValueError:
            pass
    return sorted(rel_files)


def _check_specs_modified_since_base(
    repo_root: pathlib.Path,
    merge_base_sha: str,
    cited_rel_files: List[str],
) -> List[str]:
    if not cited_rel_files:
        return []
    git_bin = _resolve_git_binary()
    modified: Set[str] = set()
    for diff_args in (
        [git_bin, "-C", str(repo_root), "-c", "core.quotepath=false", "diff", "--name-only", merge_base_sha, "HEAD", "--", *cited_rel_files],
        [git_bin, "-C", str(repo_root), "-c", "core.quotepath=false", "diff", "--name-only", merge_base_sha, "--", *cited_rel_files],
    ):
        rc, out, _, _, _ = _run_command_isolated(diff_args, timeout_sec=5.0)
        if rc == 0 and out.strip():
            for line in out.splitlines():
                clean = line.strip()
                if clean:
                    modified.add(clean)
    return sorted(modified)


def _compute_working_tree_hash(
    repo_root: Optional[pathlib.Path],
    fallback_map: Dict[str, str],
    current_head_sha: Optional[str] = None,
) -> str:
    """
    Computes a deterministic hash representing the current working tree state
    using `git status --porcelain` + `git write-tree` (only when index has staged
    changes or HEAD is absent) + dirty/untracked file hashes (excluding .ag_state,
    __pycache__, .pytest_cache, logs) with deterministic fallback outside Git.
    """
    if repo_root is not None and (repo_root / ".git").exists():
        git_bin = _resolve_git_binary()
        rc_st, out_st, _, _, _ = _run_command_isolated(
            [git_bin, "-C", str(repo_root), "-c", "core.quotepath=false", "status", "--porcelain=v1", "-uall"],
            timeout_sec=5.0,
        )
        raw_lines = out_st.splitlines() if rc_st == 0 and out_st else []
        has_staged = any(len(ln) >= 2 and ln[0] not in (" ", "?") for ln in raw_lines)

        if has_staged or not current_head_sha:
            rc_wt, out_wt, _, _, _ = _run_command_isolated(
                [git_bin, "-C", str(repo_root), "write-tree"],
                timeout_sec=5.0,
            )
            tree_tag = f"TREE:{out_wt.strip()}" if rc_wt == 0 and out_wt.strip() else "TREE:UNBORN_INDEX"
        else:
            tree_tag = f"HEAD:{current_head_sha}"

        h = hashlib.sha256()
        h.update(f"{tree_tag}\n".encode("utf-8"))
        if raw_lines:
            ignored_parts = {".ag_state", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
            dirty_entries: List[Tuple[str, str]] = []
            for raw_line in raw_lines:
                if len(raw_line) < 4:
                    continue
                status_code = raw_line[:2]
                rel_raw = raw_line[3:]
                if " -> " in rel_raw:
                    rel_raw = rel_raw.split(" -> ", 1)[1]
                if rel_raw.startswith('"') and rel_raw.endswith('"'):
                    rel_raw = rel_raw[1:-1]
                norm_rel = rel_raw.replace("\\", "/").lstrip("./")
                parts = norm_rel.split("/")
                if any(part in ignored_parts for part in parts) or norm_rel.startswith("logs/"):
                    continue
                dirty_entries.append((f"{status_code}:{norm_rel}", norm_rel))
            dirty_entries.sort(key=lambda item: item[1])
            for tag, norm_rel in dirty_entries:
                fpath = repo_root / norm_rel
                if fpath.is_file() and not _is_symlink_or_junction(fpath):
                    fhash = _sha256_file(fpath, normalize_eol=True)
                else:
                    fhash = "DIR_OR_MISSING"
                h.update(f"{tag}:{fhash}\n".encode("utf-8"))
        return h.hexdigest()

    h_fb = hashlib.sha256()
    for k in sorted(fallback_map.keys()):
        h_fb.update(f"{k}:{fallback_map[k]}\n".encode("utf-8"))
    return h_fb.hexdigest()


def _detect_oscillation_cycle(
    recent_hashes: List[str],
    current_hash: str,
    allow_initial_same: bool = False,
) -> Optional[int]:
    """
    Returns cycle length k >= 1 if current_hash repeats a previously seen state
    within the bounded history window, or None if no oscillation cycle occurred.
    """
    if not recent_hashes:
        return None
    if allow_initial_same and len(recent_hashes) == 1 and recent_hashes[0] == current_hash:
        return None
    for dist, prev_hash in enumerate(reversed(recent_hashes), start=1):
        if prev_hash == current_hash:
            return dist
    return None


def _append_bounded_history(recent_hashes: List[str], new_hash: str, maxlen: int = 16) -> List[str]:
    dq = collections.deque(recent_hashes, maxlen=maxlen)
    if not dq or dq[-1] != new_hash:
        dq.append(new_hash)
    return list(dq)


def _parse_guard_receipt(receipt_path: pathlib.Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Loads and validates core receipt fields for both v2.3 and v2.4 receipts."""
    try:
        saved_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"CORRUPTED_RECEIPT: Failed to parse {receipt_path}: {exc}"

    if not isinstance(saved_receipt, dict) or saved_receipt.get("version") != 2:
        got_ver = saved_receipt.get("version") if isinstance(saved_receipt, dict) else None
        return None, f"CORRUPTED_RECEIPT: Unsupported or missing receipt version (expected 2, got {got_ver!r})."

    saved_cmd = (saved_receipt.get("cmd") or "").strip()
    if not saved_cmd:
        return None, "CORRUPTED_RECEIPT: Receipt is missing a non-empty witnessed 'cmd'."

    return saved_receipt, None


def _guard_witness_red(
    args: argparse.Namespace,
    test_path: pathlib.Path,
    state_dir: pathlib.Path,
    receipt_path: pathlib.Path,
    timeout_sec: float,
    cli_ignore: List[str],
    repo_root: Optional[pathlib.Path],
    current_head_sha: Optional[str],
) -> int:
    cmd_str = (args.cmd or "").strip()
    if not cmd_str:
        return _emit({"ok": False, "error": "MISSING_CMD: --cmd is required for witness-red"}, args.json, exit_code=1)

    base_ref = (getattr(args, "base_ref", None) or "").strip() or None
    merge_base_sha: Optional[str] = None
    if base_ref:
        if repo_root is None or current_head_sha is None:
            return _emit(
                {"ok": False, "error": "INVALID_BASE_REF: --base-ref requires an initialized Git repository."},
                args.json,
                exit_code=1,
            )
        merge_base_sha = _git_merge_base(repo_root, base_ref, "HEAD")
        if not merge_base_sha:
            return _emit(
                {"ok": False, "error": f"INVALID_BASE_REF: Unable to resolve merge-base between '{base_ref}' and HEAD."},
                args.json,
                exit_code=1,
            )

    forbid_addopts = _parse_ignore_patterns(getattr(args, "forbid_addopts", None))
    allow_passthrough = bool(getattr(args, "allow_env_passthrough", False))

    env_ok, env_err, clean_env, env_policy = _check_and_sanitize_env(allow_passthrough)
    if not env_ok and env_err:
        return _emit({"ok": False, **env_err}, args.json, exit_code=2)

    try:
        root_base, root_manifest, ini_paths = _collect_root_config_manifest(test_path)
    except (ValueError, OSError) as exc:
        return _emit({"ok": False, "error": f"GUARD_INIT_FAILED: {exc}"}, args.json, exit_code=1)

    addopts_ok, addopts_err = _inspect_pytest_addopts(ini_paths, cmd_str, forbid_addopts)
    if not addopts_ok and addopts_err:
        return _emit({"ok": False, **addopts_err}, args.json, exit_code=2)

    try:
        pre_hash, pre_files = _compute_merkle_tree(test_path, state_dir, receipt_path, cli_ignore)
    except (ValueError, OSError) as exc:
        return _emit({"ok": False, "error": f"GUARD_INIT_FAILED: {exc}"}, args.json, exit_code=1)

    if not pre_files:
        return _emit(
            {"ok": False, "error": f"EMPTY_TEST_TARGET: No files found to seal in {test_path}"},
            args.json,
            exit_code=1,
        )

    returncode, stdout_txt, stderr_txt, timed_out, elapsed_ms = _run_command_isolated(cmd_str, timeout_sec, env=clean_env)

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
    if expected_exit is None and returncode in (2, 3, 4, 5, 126, 127, 9009):
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

    try:
        tree_hash, files_map = _compute_merkle_tree(test_path, state_dir, receipt_path, cli_ignore)
    except (ValueError, OSError) as exc:
        return _emit(
            {
                "ok": False,
                "error": f"SELF_MUTATING_TEST_DIR: Test execution introduced forbidden filesystem state inside test_dir: {exc}",
            },
            args.json,
            exit_code=1,
        )
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

    red_signature = _extract_red_signature(stdout_txt, stderr_txt)
    exec_counts = _extract_test_execution_counts(cmd_str, stdout_txt, stderr_txt)
    witnessed_test_count = exec_counts["total"] if exec_counts is not None else None
    working_tree_hash = _compute_working_tree_hash(repo_root, files_map, current_head_sha=current_head_sha)

    receipt: Dict[str, Any] = {
        "version": 2,
        "schema_version": _SCHEMA_VERSION,
        "status": "WITNESSED_RED",
        "timestamp_utc": _utc_now_iso(),
        "test_target": str(test_path),
        "cmd": cmd_str,
        "tree_hash": tree_hash,
        "witnessed_head_sha": current_head_sha,
        "base_ref": base_ref,
        "merge_base_sha": merge_base_sha,
        "red_exit_code": returncode,
        "red_signature": red_signature,
        "witnessed_test_count": witnessed_test_count,
        "elapsed_ms": elapsed_ms,
        "ignored_patterns": cli_ignore,
        "forbidden_addopts": forbid_addopts,
        "env_policy": env_policy,
        "root_config_base": str(root_base),
        "root_config_manifest": root_manifest,
        "recent_tree_hashes": [working_tree_hash],
        "verify_attempts": 0,
        "files": files_map,
        "renegotiation_history": [],
        "collisions": [],
    }
    _atomic_write_json(receipt_path, receipt)

    return _emit(
        {
            "ok": True,
            "schema_version": _SCHEMA_VERSION,
            "status": "WITNESSED_RED",
            "tree_hash": tree_hash,
            "witnessed_head_sha": current_head_sha,
            "base_ref": base_ref,
            "merge_base_sha": merge_base_sha,
            "cmd": cmd_str,
            "red_exit_code": returncode,
            "red_signature": red_signature,
            "witnessed_test_count": witnessed_test_count,
            "root_config_count": len(root_manifest),
            "files_count": len(files_map),
            "ignored_patterns": cli_ignore,
            "receipt_file": str(receipt_path),
        },
        args.json,
        exit_code=0,
    )


def _guard_verify_green(
    args: argparse.Namespace,
    test_path: pathlib.Path,
    state_dir: pathlib.Path,
    receipt_path: pathlib.Path,
    timeout_sec: float,
    repo_root: Optional[pathlib.Path],
    current_head_sha: Optional[str],
) -> int:
    if not receipt_path.is_file():
        return _emit(
            {"ok": False, "error": f"NO_RED_RECEIPT: No previous witnessed red receipt found at {receipt_path}"},
            args.json,
            exit_code=1,
        )

    saved_receipt, parse_err = _parse_guard_receipt(receipt_path)
    if parse_err or saved_receipt is None:
        return _emit({"ok": False, "error": parse_err or "CORRUPTED_RECEIPT"}, args.json, exit_code=2)

    saved_cmd = (saved_receipt.get("cmd") or "").strip()
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

    saved_head_sha = saved_receipt.get("witnessed_head_sha")
    eff_base_ref = (getattr(args, "base_ref", None) or "").strip() or saved_receipt.get("base_ref")
    if saved_head_sha and current_head_sha and saved_head_sha != current_head_sha:
        if getattr(args, "allow_head_move", False):
            _record_guard_collision(
                receipt_path,
                saved_receipt,
                "HEAD_MOVE_ALLOWED",
                {"witnessed_head_sha": saved_head_sha, "current_head_sha": current_head_sha},
            )
        elif eff_base_ref and repo_root is not None and _git_is_ancestor(repo_root, saved_head_sha, "HEAD"):
            pass
        else:
            _record_guard_collision(
                receipt_path,
                saved_receipt,
                "HEAD_MOVED_DURING_RED_PHASE",
                {"witnessed_head_sha": saved_head_sha, "current_head_sha": current_head_sha},
            )
            return _emit(
                {
                    "ok": False,
                    "error": f"HEAD_MOVED_DURING_RED_PHASE: Git HEAD moved from {saved_head_sha[:8]} to {current_head_sha[:8]} before verify-green. Local commits during Red->Green phase are prohibited unless --allow-head-move is set.",
                    "witnessed_head_sha": saved_head_sha,
                    "current_head_sha": current_head_sha,
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

    saved_ignore = list(saved_receipt.get("ignored_patterns", []))
    raw_cli_ignore = getattr(args, "ignore", "") or ""
    if raw_cli_ignore.strip():
        cli_ignore_list = _parse_ignore_patterns(raw_cli_ignore)
        if sorted(cli_ignore_list) != sorted(saved_ignore):
            _record_guard_collision(
                receipt_path,
                saved_receipt,
                "IGNORE_PATTERN_MISMATCH",
                {"witnessed_ignore": saved_ignore, "attempted_ignore": cli_ignore_list},
            )
            return _emit(
                {
                    "ok": False,
                    "error": f"IGNORE_PATTERN_MISMATCH: Provided --ignore patterns {cli_ignore_list} do not match witnessed patterns {saved_ignore}.",
                    "witnessed_ignore": saved_ignore,
                    "attempted_ignore": cli_ignore_list,
                },
                args.json,
                exit_code=2,
            )

    effective_ignore = saved_ignore

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

    allow_passthrough = bool(getattr(args, "allow_env_passthrough", False))
    env_ok, env_err, clean_env, _ = _check_and_sanitize_env(allow_passthrough, saved_receipt.get("env_policy"))
    if not env_ok and env_err:
        _record_guard_collision(receipt_path, saved_receipt, "ENV_TAINT_DETECTED", env_err)
        return _emit({"ok": False, **env_err}, args.json, exit_code=2)

    root_ok, root_changes, ini_paths = _verify_root_config_manifest(saved_receipt, test_path)
    if not root_ok:
        _record_guard_collision(receipt_path, saved_receipt, "ROOT_CONFIG_DRIFT", {"changes": root_changes})
        return _emit(
            {
                "ok": False,
                "error": "ROOT_CONFIG_DRIFT: Root test configuration changed outside --test-dir without renegotiation.",
                "changes": root_changes,
            },
            args.json,
            exit_code=2,
        )

    saved_forbid = list(saved_receipt.get("forbidden_addopts", []))
    cli_forbid = _parse_ignore_patterns(getattr(args, "forbid_addopts", None))
    effective_forbid = sorted(set(saved_forbid) | set(cli_forbid))
    addopts_ok, addopts_err = _inspect_pytest_addopts(ini_paths, cmd_to_run, effective_forbid)
    if not addopts_ok and addopts_err:
        _record_guard_collision(receipt_path, saved_receipt, "UNSAFE_PYTEST_ADDOPTS", addopts_err)
        return _emit({"ok": False, **addopts_err}, args.json, exit_code=2)

    try:
        current_tree_hash, current_files = _compute_merkle_tree(test_path, state_dir, receipt_path, effective_ignore)
    except (ValueError, OSError) as exc:
        return _emit({"ok": False, "error": f"GUARD_VERIFY_FAILED: {exc}"}, args.json, exit_code=1)
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

    recent_hashes = list(saved_receipt.get("recent_tree_hashes", [])) if isinstance(saved_receipt.get("recent_tree_hashes"), list) else []
    verify_attempts = int(saved_receipt.get("verify_attempts", 0) or 0)
    working_tree_hash = _compute_working_tree_hash(repo_root, current_files, current_head_sha=current_head_sha)
    cycle_len = _detect_oscillation_cycle(
        recent_hashes,
        working_tree_hash,
        allow_initial_same=(verify_attempts == 0 and len(recent_hashes) == 1),
    )
    if cycle_len is not None:
        _record_guard_collision(
            receipt_path,
            saved_receipt,
            "OSCILLATION_CYCLE_DETECTED",
            {"cycle_length": cycle_len, "repeated_hash": working_tree_hash[:16]},
        )
        return _emit(
            {
                "ok": False,
                "error": f"OSCILLATION_CYCLE_DETECTED: Working tree reverted to a previously failed state (cycle_length={cycle_len}).",
                "cycle_length": cycle_len,
                "repeated_hash": working_tree_hash,
            },
            args.json,
            exit_code=2,
        )

    saved_receipt["recent_tree_hashes"] = _append_bounded_history(recent_hashes, working_tree_hash, maxlen=16)
    saved_receipt["verify_attempts"] = verify_attempts + 1

    returncode, stdout_txt, stderr_txt, timed_out, elapsed_ms = _run_command_isolated(cmd_to_run, timeout_sec, env=clean_env)

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

    witnessed_count = saved_receipt.get("witnessed_test_count")
    exec_counts = _extract_test_execution_counts(cmd_to_run, stdout_txt, stderr_txt)
    green_count = exec_counts["total"] if exec_counts is not None else None
    if green_count == 0 or (isinstance(witnessed_count, int) and witnessed_count > 0 and green_count is None):
        _record_guard_collision(
            receipt_path,
            saved_receipt,
            "ZERO_TESTS_EXECUTED",
            {"witnessed_test_count": witnessed_count, "green_test_count": green_count or 0},
        )
        return _emit(
            {
                "ok": False,
                "error": "ZERO_TESTS_EXECUTED: Test command exited 0 but executed 0 tests.",
                "witnessed_test_count": witnessed_count,
                "green_test_count": green_count or 0,
                "cmd": cmd_to_run,
            },
            args.json,
            exit_code=2,
        )
    if isinstance(witnessed_count, int) and green_count is not None and green_count < witnessed_count:
        _record_guard_collision(
            receipt_path,
            saved_receipt,
            "TEST_COUNT_REGRESSION",
            {"witnessed_test_count": witnessed_count, "green_test_count": green_count},
        )
        return _emit(
            {
                "ok": False,
                "error": f"TEST_COUNT_REGRESSION: Executed {green_count} tests during verify-green, fewer than witnessed {witnessed_count}.",
                "witnessed_test_count": witnessed_count,
                "green_test_count": green_count,
                "cmd": cmd_to_run,
            },
            args.json,
            exit_code=2,
        )

    try:
        post_tree_hash, _ = _compute_merkle_tree(test_path, state_dir, receipt_path, effective_ignore)
    except (ValueError, OSError) as exc:
        return _emit({"ok": False, "error": f"GUARD_VERIFY_FAILED: {exc}"}, args.json, exit_code=1)
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

    post_root_ok, post_root_changes, _ = _verify_root_config_manifest(saved_receipt, test_path)
    if not post_root_ok:
        _record_guard_collision(
            receipt_path,
            saved_receipt,
            "ROOT_CONFIG_DRIFT",
            {"changes": post_root_changes, "phase": "post_run"},
        )
        return _emit(
            {
                "ok": False,
                "error": "ROOT_CONFIG_DRIFT: Test execution modified root configuration files during verify-green.",
                "changes": post_root_changes,
            },
            args.json,
            exit_code=2,
        )

    saved_receipt["status"] = "VERIFIED_GREEN_WITH_MERKLE_LOCK"
    saved_receipt["verified_at"] = _utc_now_iso()
    saved_receipt["green_elapsed_ms"] = elapsed_ms
    if green_count is not None:
        saved_receipt["green_test_count"] = green_count
    _atomic_write_json(receipt_path, saved_receipt)

    return _emit(
        {
            "ok": True,
            "schema_version": saved_receipt.get("schema_version", "2.3"),
            "status": "VERIFIED_GREEN_WITH_MERKLE_LOCK",
            "tree_hash": current_tree_hash,
            "witnessed_head_sha": saved_head_sha,
            "resolved_red_signature": saved_receipt.get("red_signature", []),
            "witnessed_test_count": witnessed_count,
            "green_test_count": green_count,
            "cmd": cmd_to_run,
            "elapsed_ms": elapsed_ms,
            "collisions_count": len(saved_receipt.get("collisions", [])),
            "receipt_file": str(receipt_path),
        },
        args.json,
        exit_code=0,
    )


def _guard_renegotiate(
    args: argparse.Namespace,
    test_path: pathlib.Path,
    state_dir: pathlib.Path,
    receipt_path: pathlib.Path,
    timeout_sec: float,
    cli_ignore: List[str],
    repo_root: Optional[pathlib.Path],
    current_head_sha: Optional[str],
) -> int:
    reason = (args.reason or "").strip()
    if not reason:
        return _emit({"ok": False, "error": "MISSING_REASON: --reason is mandatory for test renegotiation"}, args.json, exit_code=1)

    cmd_str = args.cmd.strip() if args.cmd else ""
    history: List[Dict[str, Any]] = []
    collisions: List[Dict[str, Any]] = []
    old_tree_hash = None
    old_cmd = None
    old_head_sha = None
    inherited_ignore: List[str] = []
    inherited_forbid: List[str] = []
    renegotiated_at_iso = _utc_now_iso()

    old_data: Optional[Dict[str, Any]] = None
    recent_hashes: List[str] = []
    if receipt_path.is_file():
        old_data, parse_err = _parse_guard_receipt(receipt_path)
        if parse_err or old_data is None:
            return _emit(
                {
                    "ok": False,
                    "error": f"CORRUPTED_RECEIPT: Cannot renegotiate over corrupted receipt at {receipt_path}: {parse_err}",
                },
                args.json,
                exit_code=2,
            )
        old_cmd = (old_data.get("cmd") or "").strip()
        old_tree_hash = old_data.get("tree_hash")
        old_head_sha = old_data.get("witnessed_head_sha")
        if not old_tree_hash:
            return _emit(
                {
                    "ok": False,
                    "error": f"CORRUPTED_RECEIPT: Cannot renegotiate over corrupted receipt at {receipt_path}: missing tree_hash",
                },
                args.json,
                exit_code=2,
            )
        raw_history = old_data.get("renegotiation_history", [])
        if not isinstance(raw_history, list):
            return _emit(
                {
                    "ok": False,
                    "error": f"CORRUPTED_RECEIPT: Cannot renegotiate over corrupted receipt at {receipt_path}: renegotiation_history must be a list",
                },
                args.json,
                exit_code=2,
            )
        history = list(raw_history)
        collisions = list(old_data.get("collisions", [])) if isinstance(old_data.get("collisions"), list) else []
        inherited_ignore = list(old_data.get("ignored_patterns", []))
        inherited_forbid = list(old_data.get("forbidden_addopts", []))
        recent_hashes = list(old_data.get("recent_tree_hashes", [])) if isinstance(old_data.get("recent_tree_hashes"), list) else []
        hist_entry: Dict[str, Any] = {
            "timestamp": old_data.get("timestamp_utc"),
            "renegotiated_at": renegotiated_at_iso,
            "status": old_data.get("status"),
            "reason": old_data.get("reason"),
            "tree_hash": old_tree_hash,
            "witnessed_head_sha": old_head_sha,
            "red_signature": old_data.get("red_signature", []),
            "witnessed_test_count": old_data.get("witnessed_test_count"),
            "cmd": old_cmd,
        }
        if "constructive_witness" in old_data:
            hist_entry["constructive_witness"] = old_data["constructive_witness"]
        history.append(hist_entry)

        eff_base_ref = (getattr(args, "base_ref", None) or "").strip() or old_data.get("base_ref")
        if old_head_sha and current_head_sha and old_head_sha != current_head_sha:
            if getattr(args, "allow_head_move", False):
                collisions.append({
                    "timestamp_utc": renegotiated_at_iso,
                    "event": "HEAD_MOVE_ALLOWED",
                    "witnessed_head_sha": old_head_sha,
                    "current_head_sha": current_head_sha,
                })
            elif eff_base_ref and repo_root is not None and _git_is_ancestor(repo_root, old_head_sha, "HEAD"):
                pass
            else:
                _record_guard_collision(
                    receipt_path,
                    old_data,
                    "HEAD_MOVED_DURING_RED_PHASE",
                    {"witnessed_head_sha": old_head_sha, "current_head_sha": current_head_sha},
                )
                return _emit(
                    {
                        "ok": False,
                        "error": f"HEAD_MOVED_DURING_RED_PHASE: Git HEAD moved from {old_head_sha[:8]} to {current_head_sha[:8]} before renegotiate. Forging witness commits during Red phase is prohibited.",
                        "witnessed_head_sha": old_head_sha,
                        "current_head_sha": current_head_sha,
                    },
                    args.json,
                    exit_code=2,
                )
    else:
        eff_base_ref = (getattr(args, "base_ref", None) or "").strip() or None

    merge_base_sha: Optional[str] = None
    if eff_base_ref:
        if repo_root is None or current_head_sha is None:
            return _emit(
                {"ok": False, "error": "INVALID_BASE_REF: --base-ref requires an initialized Git repository."},
                args.json,
                exit_code=1,
            )
        merge_base_sha = _git_merge_base(repo_root, eff_base_ref, "HEAD")
        if not merge_base_sha:
            return _emit(
                {"ok": False, "error": f"INVALID_BASE_REF: Unable to resolve merge-base between '{eff_base_ref}' and HEAD."},
                args.json,
                exit_code=1,
            )
        cited_spec_files = _extract_cited_spec_files(args, repo_root)
        if cited_spec_files:
            modified_specs = _check_specs_modified_since_base(repo_root, merge_base_sha, cited_spec_files)
            if modified_specs:
                if old_data is not None:
                    _record_guard_collision(
                        receipt_path,
                        old_data,
                        "SPEC_MODIFIED_SINCE_BASE",
                        {"base_ref": eff_base_ref, "merge_base_sha": merge_base_sha, "modified_files": modified_specs},
                    )
                return _emit(
                    {
                        "ok": False,
                        "error": f"SPEC_MODIFIED_SINCE_BASE: Cited specification file(s) modified since merge-base {merge_base_sha[:8]} ({eff_base_ref}): {', '.join(modified_specs)}",
                        "base_ref": eff_base_ref,
                        "merge_base_sha": merge_base_sha,
                        "modified_files": modified_specs,
                    },
                    args.json,
                    exit_code=2,
                )

    effective_ignore = cli_ignore if cli_ignore else inherited_ignore
    cli_forbid = _parse_ignore_patterns(getattr(args, "forbid_addopts", None))
    effective_forbid = sorted(set(inherited_forbid) | set(cli_forbid))
    pinned_sha_for_witness = old_head_sha or current_head_sha

    if not cmd_str:
        cmd_str = old_cmd or ""
    if not cmd_str:
        return _emit({"ok": False, "error": "MISSING_CMD: Test command is required for renegotiate"}, args.json, exit_code=1)

    allow_passthrough = bool(getattr(args, "allow_env_passthrough", False))
    env_ok, env_err, clean_env, env_policy = _check_and_sanitize_env(allow_passthrough)
    if not env_ok and env_err:
        return _emit({"ok": False, **env_err}, args.json, exit_code=2)

    try:
        root_base, root_manifest, ini_paths = _collect_root_config_manifest(test_path)
    except (ValueError, OSError) as exc:
        return _emit({"ok": False, "error": f"GUARD_RENEGOTIATE_FAILED: {exc}"}, args.json, exit_code=1)

    addopts_ok, addopts_err = _inspect_pytest_addopts(ini_paths, cmd_str, effective_forbid)
    if not addopts_ok and addopts_err:
        return _emit({"ok": False, **addopts_err}, args.json, exit_code=2)

    try:
        pre_hash, pre_files = _compute_merkle_tree(test_path, state_dir, receipt_path, effective_ignore)
    except (ValueError, OSError) as exc:
        return _emit({"ok": False, "error": f"GUARD_RENEGOTIATE_FAILED: {exc}"}, args.json, exit_code=1)
    if not pre_files:
        return _emit(
            {"ok": False, "error": f"EMPTY_TEST_TARGET: No files found to seal in {test_path}"},
            args.json,
            exit_code=1,
        )

    returncode, stdout_txt, stderr_txt, timed_out, elapsed_ms = _run_command_isolated(cmd_str, timeout_sec, env=clean_env)

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
    if expected_exit is None and returncode in (2, 3, 4, 5, 126, 127, 9009):
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

    if repo_root is not None and pinned_sha_for_witness and getattr(args, "witness_type", None) in ("spec-collision", "arch-fork"):
        with GitBatchReader(repo_root) as git_reader:
            witness_ok, witness_err, witness_proof = _verify_constructive_witness(
                args,
                stdout_txt,
                stderr_txt,
                repo_root=repo_root,
                pinned_sha=pinned_sha_for_witness,
                git_reader=git_reader,
            )
    else:
        witness_ok, witness_err, witness_proof = _verify_constructive_witness(
            args,
            stdout_txt,
            stderr_txt,
            repo_root=repo_root,
            pinned_sha=pinned_sha_for_witness,
        )
    if not witness_ok:
        if receipt_path.is_file():
            try:
                existing_rec = json.loads(receipt_path.read_text(encoding="utf-8"))
                if isinstance(existing_rec, dict):
                    _record_guard_collision(
                        receipt_path,
                        existing_rec,
                        "INVALID_CONSTRUCTIVE_WITNESS",
                        {"reason": witness_err},
                    )
            except (OSError, json.JSONDecodeError) as exc:
                sys.stderr.write(f"[ag_ops] Warning: failed to log witness collision: {exc}\n")
        return _emit({"ok": False, "error": witness_err}, args.json, exit_code=1)

    try:
        tree_hash, files_map = _compute_merkle_tree(test_path, state_dir, receipt_path, effective_ignore)
    except (ValueError, OSError) as exc:
        return _emit(
            {
                "ok": False,
                "error": f"SELF_MUTATING_TEST_DIR: Test execution introduced forbidden filesystem state during renegotiate: {exc}",
            },
            args.json,
            exit_code=1,
        )
    if tree_hash != pre_hash:
        return _emit(
            {
                "ok": False,
                "error": "SELF_MUTATING_TEST_DIR: Test execution modified files inside test_dir during renegotiate.",
            },
            args.json,
            exit_code=1,
        )

    red_signature = _extract_red_signature(stdout_txt, stderr_txt)
    exec_counts = _extract_test_execution_counts(cmd_str, stdout_txt, stderr_txt)
    witnessed_test_count = exec_counts["total"] if exec_counts is not None else None
    working_tree_hash = _compute_working_tree_hash(repo_root, files_map, current_head_sha=current_head_sha)
    cycle_len = _detect_oscillation_cycle(recent_hashes, working_tree_hash, allow_initial_same=True)
    if cycle_len is not None and cycle_len >= 2:
        if old_data is not None:
            _record_guard_collision(
                receipt_path,
                old_data,
                "OSCILLATION_CYCLE_DETECTED",
                {"cycle_length": cycle_len, "repeated_hash": working_tree_hash[:16]},
            )
        return _emit(
            {
                "ok": False,
                "error": f"OSCILLATION_CYCLE_DETECTED: Renegotiation reverted working tree to an earlier state (cycle_length={cycle_len}).",
                "cycle_length": cycle_len,
                "repeated_hash": working_tree_hash,
            },
            args.json,
            exit_code=2,
        )
    updated_recent_hashes = _append_bounded_history(recent_hashes, working_tree_hash, maxlen=16)

    new_receipt: Dict[str, Any] = {
        "version": 2,
        "schema_version": _SCHEMA_VERSION,
        "status": "RENEGOTIATED_RED",
        "timestamp_utc": renegotiated_at_iso,
        "test_target": str(test_path),
        "reason": reason,
        "cmd": cmd_str,
        "tree_hash": tree_hash,
        "previous_tree_hash": old_tree_hash,
        "witnessed_head_sha": pinned_sha_for_witness,
        "base_ref": eff_base_ref,
        "merge_base_sha": merge_base_sha,
        "red_exit_code": returncode,
        "red_signature": red_signature,
        "witnessed_test_count": witnessed_test_count,
        "elapsed_ms": elapsed_ms,
        "ignored_patterns": effective_ignore,
        "forbidden_addopts": effective_forbid,
        "env_policy": env_policy,
        "root_config_base": str(root_base),
        "root_config_manifest": root_manifest,
        "recent_tree_hashes": updated_recent_hashes,
        "verify_attempts": 0,
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
            "schema_version": _SCHEMA_VERSION,
            "status": "RENEGOTIATED_RED",
            "reason": reason,
            "new_tree_hash": tree_hash,
            "previous_tree_hash": old_tree_hash,
            "witnessed_head_sha": pinned_sha_for_witness,
            "base_ref": eff_base_ref,
            "merge_base_sha": merge_base_sha,
            "cmd": cmd_str,
            "red_exit_code": returncode,
            "red_signature": red_signature,
            "witnessed_test_count": witnessed_test_count,
            "history_count": len(history),
            "constructive_witness": witness_proof,
            "receipt_file": str(receipt_path),
        },
        args.json,
        exit_code=0,
    )


def _guard_check_scope(args: argparse.Namespace) -> int:
    """
    Mechanical scope separation (SCAR-PROC-13 / Cohort A):
    Runs a single `git diff --name-only <base>...HEAD` and rejects mixed commits/PRs
    that modify both governance/rule paths and production code simultaneously.
    """
    repo_arg = pathlib.Path(getattr(args, "repo", ".") or ".").resolve()
    repo_root = _find_git_root_pure(repo_arg)
    if repo_root is None:
        return _emit(
            {"ok": False, "error": f"NOT_A_GIT_REPO: No .git directory found for {repo_arg}"},
            args.json,
            exit_code=1,
        )

    base_ref = (getattr(args, "base", None) or "origin/main").strip()
    raw_rule_paths = getattr(args, "rule_paths", "") or ""
    rule_patterns = [
        p.strip().replace("\\", "/").strip("/")
        for p in raw_rule_paths.split(",")
        if p.strip()
    ]

    git_bin = _resolve_git_binary()
    rc, out, err, _, _ = _run_command_isolated(
        [git_bin, "-C", str(repo_root), "-c", "core.quotepath=false", "diff", "--name-only", f"{base_ref}...HEAD"],
        timeout_sec=10.0,
    )
    if rc != 0:
        return _emit(
            {
                "ok": False,
                "error": f"GIT_DIFF_FAILED: Failed to diff '{base_ref}...HEAD': {err.strip()}",
                "base": base_ref,
            },
            args.json,
            exit_code=1,
        )

    changed_files = [ln.strip().replace("\\", "/").lstrip("./") for ln in out.splitlines() if ln.strip()]
    rule_files: List[str] = []
    code_files: List[str] = []

    for rel_path in changed_files:
        is_rule = False
        for pat in rule_patterns:
            if rel_path == pat or rel_path.startswith(pat + "/") or fnmatch.fnmatch(rel_path, pat):
                is_rule = True
                break
        if is_rule:
            rule_files.append(rel_path)
        else:
            code_files.append(rel_path)

    if rule_files and code_files:
        return _emit(
            {
                "ok": False,
                "error": "MIXED_SCOPE_VIOLATION: Changes mix governance/rule paths with production code in the same branch/PR.",
                "base": base_ref,
                "rule_paths": rule_patterns,
                "rule_files": rule_files,
                "code_files": code_files,
            },
            args.json,
            exit_code=2,
        )

    if rule_files:
        scope = "RULES_ONLY"
    elif code_files:
        scope = "CODE_ONLY"
    else:
        scope = "EMPTY"

    return _emit(
        {
            "ok": True,
            "scope": scope,
            "base": base_ref,
            "rule_paths": rule_patterns,
            "rule_files": rule_files,
            "code_files": code_files,
            "changed_count": len(changed_files),
        },
        args.json,
        exit_code=0,
    )


def _cmd_guard(args: argparse.Namespace) -> int:
    action = args.guard_action
    if action == "check-scope":
        return _guard_check_scope(args)

    raw_test_dir = getattr(args, "test_dir", None)
    if not raw_test_dir:
        return _emit(
            {"ok": False, "error": f"MISSING_TEST_DIR: --test-dir is required for guard {action}"},
            args.json,
            exit_code=1,
        )

    raw_target = pathlib.Path(raw_test_dir)
    if _is_symlink_or_junction(raw_target):
        return _emit(
            {"ok": False, "error": f"GUARD_INIT_FAILED: Symlinks and junctions are forbidden in Merkle guard target: {raw_target}"},
            args.json,
            exit_code=1,
        )
    test_path = raw_target.resolve()
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
    repo_root, current_head_sha = _get_git_repo_and_head(test_path)

    if action == "witness-red":
        return _guard_witness_red(args, test_path, state_dir, receipt_path, timeout_sec, cli_ignore, repo_root, current_head_sha)
    if action == "verify-green":
        return _guard_verify_green(args, test_path, state_dir, receipt_path, timeout_sec, repo_root, current_head_sha)
    if action == "renegotiate":
        return _guard_renegotiate(args, test_path, state_dir, receipt_path, timeout_sec, cli_ignore, repo_root, current_head_sha)

    return _emit({"ok": False, "error": f"UNKNOWN_GUARD_ACTION: {action}"}, args.json, exit_code=1)


# =============================================================================
# SUBCOMMAND 2: DISTILL (Deterministic Output Distillation)
# =============================================================================

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

    all_lines = stdout_txt.splitlines() + stderr_txt.splitlines()
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
        tail = [line for line in all_lines if line.strip()][-5:]
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
    if total_lines <= max_lines:
        extracted_lines = list(all_lines)
    elif critical_indices:
        first_err = critical_indices[0]
        head_budget = max(2, (max_lines - 1) // 3)
        tail_budget = max(2, max_lines - head_budget - 1)

        start_head = max(0, first_err - 2)
        end_head = min(total_lines, start_head + head_budget)
        tail_start = max(end_head, total_lines - tail_budget)

        if tail_start > end_head:
            head_block = all_lines[start_head:end_head]
            tail_block = all_lines[tail_start:]
            extracted_lines = (
                head_block
                + ["... [intermediate lines pruned] ..."]
                + tail_block
            )
        else:
            window_start = min(start_head, max(0, total_lines - max_lines))
            extracted_lines = all_lines[window_start : window_start + max_lines]
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
    if not state_dir.is_dir():
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
        # Pad 0..99 as 2 digits for classic 00_plan/10_build compatibility; pad >=100 as 4 digits
        step_str = f"{step_num:02d}" if step_num < 100 else f"{step_num:04d}"
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
        conflicting: List[pathlib.Path] = []
        for existing in state_dir.iterdir():
            if existing.is_file() and existing != target_file:
                m = _STEP_FILE_RE.match(existing.name)
                if m and int(m.group(1)) == step_num:
                    conflicting.append(existing)
        conflicting.sort(key=lambda p: p.name)
        if conflicting and not getattr(args, "replace", False):
            return _emit(
                {
                    "ok": False,
                    "error": f"STEP_CONFLICT: Step {step_str} already exists with a different filename ({[c.name for c in conflicting]}). Pass --replace to overwrite.",
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

        sealed_artifacts = {k: v for k, v in artifacts_map.items() if v != "NOT_FOUND"}
        osc_path = state_dir / "oscillation_history.json"
        osc_data: Optional[Dict[str, Any]] = None
        if sealed_artifacts:
            h_art = hashlib.sha256()
            for k in sorted(sealed_artifacts.keys()):
                h_art.update(f"{k}:{sealed_artifacts[k]}\n".encode("utf-8"))
            art_state_hash = h_art.hexdigest()

            prev_osc: Dict[str, Any] = {}
            if osc_path.is_file():
                try:
                    loaded_osc = json.loads(osc_path.read_text(encoding="utf-8"))
                    if isinstance(loaded_osc, dict):
                        prev_osc = loaded_osc
                except (OSError, json.JSONDecodeError):
                    prev_osc = {}
            recent_art_hashes = list(prev_osc.get("recent_tree_hashes", [])) if isinstance(prev_osc.get("recent_tree_hashes"), list) else []
            cycle_len = _detect_oscillation_cycle(recent_art_hashes, art_state_hash, allow_initial_same=False)
            same_meta = (
                prev_osc.get("last_step") == step_str
                and prev_osc.get("last_name") == slug
                and prev_osc.get("last_status") == status
                and prev_osc.get("last_summary") == summary
                and not getattr(args, "replace", False)
            )
            if cycle_len is not None and (cycle_len >= 2 or same_meta):
                return _emit(
                    {
                        "ok": False,
                        "error": f"OSCILLATION_CYCLE_DETECTED: State artifact set reverted to a previously recorded state (cycle_length={cycle_len}).",
                        "cycle_length": cycle_len,
                        "repeated_hash": art_state_hash,
                    },
                    args.json,
                    exit_code=2,
                )
            osc_data = {
                "version": _SCHEMA_VERSION,
                "recent_tree_hashes": _append_bounded_history(recent_art_hashes, art_state_hash, maxlen=16),
                "last_step": step_str,
                "last_name": slug,
                "last_status": status,
                "last_summary": summary,
            }

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
        if osc_data is not None:
            _atomic_write_json(osc_path, osc_data)

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
        late_sealed_notices: List[Dict[str, Any]] = []
        strict_mode = bool(getattr(args, "strict", False))

        candidates: List[Tuple[int, str, str]] = []
        with os.scandir(state_dir) as it:
            for entry in it:
                if entry.is_file():
                    m = _STEP_FILE_RE.match(entry.name)
                    if m:
                        candidates.append((int(m.group(1)), entry.name, entry.path))

        candidates.sort(key=lambda item: (item[0], item[1]))

        for _, fname, fpath_str in candidates:
            try:
                with open(fpath_str, "r", encoding="utf-8") as sf:
                    data = json.load(sf)
                if not isinstance(data, dict):
                    raise ValueError("State record must be a JSON object")
                artifacts = data.get("artifacts", {})
                if not isinstance(artifacts, dict):
                    raise ValueError("'artifacts' field must be a JSON object")
                dirty_record = False
                for art_path_str, expected_hash in list(artifacts.items()):
                    if expected_hash == "NOT_FOUND":
                        if os.path.isfile(art_path_str):
                            if strict_mode:
                                drift_warnings.append({
                                    "step": data.get("step"),
                                    "artifact": art_path_str,
                                    "issue": "LATE_ARTIFACT_UNSEALED_AT_WRITE",
                                })
                            else:
                                new_sha = _sha256_file(art_path_str)
                                artifacts[art_path_str] = new_sha
                                dirty_record = True
                                late_sealed_notices.append({
                                    "step": data.get("step"),
                                    "artifact": art_path_str,
                                    "issue": "LATE_ARTIFACT_SEALED",
                                    "sealed_sha": new_sha[:12],
                                })
                        else:
                            drift_warnings.append({
                                "step": data.get("step"),
                                "artifact": art_path_str,
                                "issue": "ARTIFACT_NEVER_EXISTED",
                            })
                    else:
                        try:
                            actual_hash = _sha256_file(art_path_str)
                        except OSError:
                            drift_warnings.append({
                                "step": data.get("step"),
                                "artifact": art_path_str,
                                "issue": "FILE_DELETED",
                            })
                        else:
                            if actual_hash != expected_hash:
                                drift_warnings.append({
                                    "step": data.get("step"),
                                    "artifact": art_path_str,
                                    "issue": "DRIFT_MODIFIED",
                                    "expected": expected_hash[:12],
                                    "actual": actual_hash[:12],
                                })
                if dirty_record:
                    _atomic_write_json(pathlib.Path(fpath_str), data)
                records.append(data)
            except Exception as exc:
                drift_warnings.append({
                    "step": fname.split("_", 1)[0],
                    "artifact": fpath_str,
                    "issue": "CORRUPTED_STATE_FILE",
                    "detail": str(exc),
                })

        last_active = records[-1] if records else None
        has_drift = len(drift_warnings) > 0
        strict_fail = strict_mode and has_drift

        payload: Dict[str, Any] = {
            "ok": not strict_fail,
            "runlevels_count": len(records),
            "steps": [r.get("step") for r in records],
            "last_active": last_active.get("name") if last_active else None,
            "last_status": last_active.get("status") if last_active else None,
            "has_drift": has_drift,
            "drift_warnings": drift_warnings,
            "runlevels": records,
        }
        if late_sealed_notices:
            payload["late_sealed_notices"] = late_sealed_notices
        osc_path = state_dir / "oscillation_history.json"
        if osc_path.is_file():
            try:
                with open(osc_path, "r", encoding="utf-8") as of:
                    osc_loaded = json.load(of)
                if isinstance(osc_loaded, dict) and isinstance(osc_loaded.get("recent_tree_hashes"), list):
                    payload["recent_tree_hashes"] = osc_loaded["recent_tree_hashes"]
            except (OSError, json.JSONDecodeError):
                pass

        return _emit(
            payload,
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


class _LintFileContext:
    """Mutable per-file linting state shared across SinglePassVisitor rule handlers."""

    def __init__(self, filename: str, source_lines: Optional[List[str]] = None) -> None:
        self.filename = filename
        self.is_test_file = _is_test_filepath(filename)
        self.source_lines: List[str] = source_lines or []
        self.ttk_module_aliases: Set[str] = {"ttk", "tkinter.ttk"}
        self.ttk_direct_imports: Dict[str, str] = {}
        self.violations: List[Dict[str, Any]] = []
        self.warnings: List[Dict[str, Any]] = []
        self.suppressed_mutations: List[Dict[str, Any]] = []


def _register_ttk_import(node: ast.Import, ctx: _LintFileContext) -> None:
    for alias in node.names:
        if alias.name == "tkinter.ttk":
            ctx.ttk_module_aliases.add(alias.asname or "tkinter.ttk")
        elif alias.name == "tkinter":
            tk_alias = alias.asname or "tkinter"
            ctx.ttk_module_aliases.add(f"{tk_alias}.ttk")


def _register_ttk_import_from(node: ast.ImportFrom, ctx: _LintFileContext) -> None:
    if node.module == "tkinter":
        for alias in node.names:
            if alias.name == "ttk":
                ctx.ttk_module_aliases.add(alias.asname or "ttk")
    elif node.module == "tkinter.ttk":
        for alias in node.names:
            if alias.name == "*":
                for w in _TTK_WIDGETS:
                    ctx.ttk_direct_imports[w] = w
            elif alias.name in _TTK_WIDGETS:
                ctx.ttk_direct_imports[alias.asname or alias.name] = alias.name


def _prescan_top_level_ttk_imports(tree: ast.AST, ctx: _LintFileContext) -> None:
    for stmt in getattr(tree, "body", ()):
        if isinstance(stmt, ast.Import):
            _register_ttk_import(stmt, ctx)
        elif isinstance(stmt, ast.ImportFrom):
            _register_ttk_import_from(stmt, ctx)


def _rule_import(node: ast.AST, ctx: _LintFileContext) -> None:
    assert isinstance(node, ast.Import)
    _register_ttk_import(node, ctx)
    if not ctx.is_test_file:
        for alias in node.names:
            if alias.name in ("unittest.mock", "mock"):
                ctx.violations.append({
                    "file": ctx.filename,
                    "line": node.lineno,
                    "rule": "PATH002",
                    "message": f"Mocking library '{alias.name}' imported in production module.",
                    "reflex": "Move mock objects strictly into tests/ and inject real interfaces or protocols in production code.",
                })


def _rule_import_from(node: ast.AST, ctx: _LintFileContext) -> None:
    assert isinstance(node, ast.ImportFrom)
    _register_ttk_import_from(node, ctx)
    if not ctx.is_test_file:
        if node.module in ("unittest.mock", "mock"):
            ctx.violations.append({
                "file": ctx.filename,
                "line": node.lineno,
                "rule": "PATH002",
                "message": f"Mocking primitives from '{node.module}' imported in production module.",
                "reflex": "Remove unittest.mock imports from production modules; pass dependencies via constructor or callable parameters.",
            })
        elif node.module == "unittest":
            for alias in node.names:
                if alias.name == "mock":
                    ctx.violations.append({
                        "file": ctx.filename,
                        "line": node.lineno,
                        "rule": "PATH002",
                        "message": "Mocking module 'unittest.mock' imported in production module.",
                        "reflex": "Remove unittest.mock imports from production modules; pass dependencies via constructor or callable parameters.",
                    })


def _rule_path001_except(node: ast.AST, ctx: _LintFileContext) -> None:
    """
    Rule PATH001: Catches silent broad exception swallowing (`except:` or `except Exception:`
    followed solely by `pass`, `...`, `continue`, or trivial returns like `return {}`,
    `return None`, `return []`) which masks broken path invariants.
    """
    assert isinstance(node, ast.ExceptHandler)
    is_broad = False
    if node.type is None:
        is_broad = True
    elif isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"):
        is_broad = True
    elif isinstance(node.type, ast.Tuple):
        is_broad = any(
            isinstance(elt, ast.Name) and elt.id in ("Exception", "BaseException")
            for elt in node.type.elts
        )
    if is_broad and len(node.body) == 1:
        stmt = node.body[0]
        is_noop = isinstance(stmt, ast.Pass) or (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Constant)
            and stmt.value.value is Ellipsis
        )
        is_continue = isinstance(stmt, ast.Continue)
        is_trivial_return = False
        if isinstance(stmt, ast.Return):
            if stmt.value is None:
                is_trivial_return = True
            elif isinstance(stmt.value, ast.Dict) and len(stmt.value.keys) == 0:
                is_trivial_return = True
            elif isinstance(stmt.value, (ast.List, ast.Tuple, ast.Set)) and len(stmt.value.elts) == 0:
                is_trivial_return = True
            elif isinstance(stmt.value, ast.Constant) and stmt.value.value in (None, False, ""):
                is_trivial_return = True

        if is_noop or is_continue or is_trivial_return:
            if is_continue:
                detail = "continue"
            elif is_trivial_return:
                if isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.Dict):
                    detail = "return {}"
                else:
                    detail = "trivial return"
            else:
                detail = "pass"

            ctx.violations.append({
                "file": ctx.filename,
                "line": node.lineno,
                "rule": "PATH001",
                "message": f"Silent broad exception swallowing ('except: {detail}') hides broken path invariants.",
                "reflex": "Catch a specific exception type and log/handle the failure context, or re-raise the error.",
            })


def _check_font_node(node_val: ast.AST, lineno: int, ctx: _LintFileContext) -> None:
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
            ctx.violations.append({
                "file": ctx.filename,
                "line": lineno,
                "rule": "TK001",
                "message": f"Float font size {float_val} forbidden in font tuple. Use integer.",
                "reflex": f"Replace float font size {float_val} with integer {int(round(float_val))} in the font tuple.",
            })


def _rule_call_tk(node: ast.AST, ctx: _LintFileContext) -> None:
    assert isinstance(node, ast.Call)
    widget_canonical = ""
    is_ttk = False

    if isinstance(node.func, ast.Attribute):
        func_name = node.func.attr
        prefix = _dotted_name(node.func.value)
        if prefix in ctx.ttk_module_aliases and func_name in _TTK_WIDGETS:
            is_ttk = True
            widget_canonical = func_name
    elif isinstance(node.func, ast.Name):
        func_name = node.func.id
        if func_name in ctx.ttk_direct_imports:
            is_ttk = True
            widget_canonical = ctx.ttk_direct_imports[func_name]

    if is_ttk:
        for kw in node.keywords:
            if kw.arg in ("background", "foreground", "bg", "fg"):
                ctx.violations.append({
                    "file": ctx.filename,
                    "line": node.lineno,
                    "rule": "TK002",
                    "message": f"Direct '{kw.arg}=' argument forbidden on ttk.{widget_canonical}. Use ttk.Style() or tk equivalent.",
                    "reflex": f"Configure '{kw.arg}' via ttk.Style().configure('<Style>.T{widget_canonical}', ...) or switch to tk.{widget_canonical}.",
                })

    for kw in node.keywords:
        if kw.arg == "font":
            _check_font_node(kw.value, node.lineno, ctx)


_RuleFn = Callable[[ast.AST, _LintFileContext], None]

_DEFAULT_LINT_DISPATCH: Dict[Type[ast.AST], List[_RuleFn]] = {
    ast.Import: [_rule_import],
    ast.ImportFrom: [_rule_import_from],
    ast.Call: [_rule_call_tk],
    ast.ExceptHandler: [_rule_path001_except],
}


class SinglePassVisitor(ast.NodeVisitor):
    """Single-pass iterative AST NodeVisitor dispatching rules via node-type lookup table."""

    def __init__(
        self,
        ctx: _LintFileContext,
        dispatch: Optional[Dict[Type[ast.AST], List[_RuleFn]]] = None,
    ) -> None:
        self.ctx = ctx
        self.dispatch = dispatch if dispatch is not None else _DEFAULT_LINT_DISPATCH

    def visit(self, node: ast.AST) -> None:
        dispatch = self.dispatch
        ctx = self.ctx
        ast_type = ast.AST
        stack: List[ast.AST] = [node]
        while stack:
            curr = stack.pop()
            handlers = dispatch.get(type(curr))
            if handlers:
                for fn in handlers:
                    fn(curr, ctx)
            for fname in reversed(curr._fields):
                val = getattr(curr, fname, None)
                if isinstance(val, ast_type):
                    stack.append(val)
                elif isinstance(val, list):
                    for item in reversed(val):
                        if isinstance(item, ast_type):
                            stack.append(item)


class _AntigravityVisitor:
    """Compatibility wrapper around SinglePassVisitor + _LintFileContext."""

    def __init__(self, filename: str, source_lines: Optional[List[str]] = None) -> None:
        self.ctx = _LintFileContext(filename, source_lines=source_lines)
        self.filename = filename
        self.is_test_file = self.ctx.is_test_file
        self.violations = self.ctx.violations
        self.ttk_module_aliases = self.ctx.ttk_module_aliases
        self.ttk_direct_imports = self.ctx.ttk_direct_imports

    def check_tree(self, tree: ast.AST) -> None:
        _prescan_top_level_ttk_imports(tree, self.ctx)
        SinglePassVisitor(self.ctx).visit(tree)


def _strip_dot_comments_preserve_lines(source: str) -> str:
    """Strips /* ... */, //..., and #... comments outside quotes while preserving newline counts."""
    out: List[str] = []
    i = 0
    n = len(source)
    in_quotes = False
    while i < n:
        ch = source[i]
        if in_quotes:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(source[i + 1])
                i += 2
                continue
            if ch == '"':
                in_quotes = False
            i += 1
            continue

        if ch == '"':
            in_quotes = True
            out.append(ch)
            i += 1
        elif source.startswith("/*", i):
            end_idx = source.find("*/", i + 2)
            if end_idx == -1:
                segment = source[i:]
                out.append("\n" * segment.count("\n"))
                break
            segment = source[i : end_idx + 2]
            out.append("\n" * segment.count("\n"))
            i = end_idx + 2
        elif source.startswith("//", i) or ch == "#":
            nl_idx = source.find("\n", i)
            if nl_idx == -1:
                break
            i = nl_idx
        else:
            out.append(ch)
            i += 1
    return "".join(out)


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
        raw_source = dot_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return [{"file": str(dot_path), "line": 1, "rule": "IO_ERROR", "message": str(exc)}]

    source = _strip_dot_comments_preserve_lines(raw_source)

    endpoint_pat = r'(?:"?[A-Za-z0-9_]+"?|\{[^{}]*\})'
    edge_chain_re = re.compile(
        rf'^[ \t]*((?:{endpoint_pat}[ \t]*->[ \t]*)+{endpoint_pat})[ \t]*(?:\[([^\]]*)\])?',
        re.M,
    )
    node_token_re = re.compile(r'"?([A-Za-z0-9_]+)"?')
    node_attr_re = re.compile(r'^[ \t]*"?([A-Za-z0-9_]+)"?[ \t]*\[([^\]]*)\]', re.M)
    guard_pred_re = re.compile(r"\bguard\s*:\s*[^\]\s,;\"']+", re.I)

    out_edges: Dict[str, List[Tuple[str, str, int]]] = {}
    in_degree: Dict[str, int] = {}
    nodes: List[str] = []
    node_lines: Dict[str, int] = {}
    async_nodes: Set[str] = set()

    def _line_at(offset: int) -> int:
        return source.count("\n", 0, offset) + 1

    def _register_node(name: str, line_no: int) -> None:
        if name not in nodes:
            nodes.append(name)
            node_lines[name] = line_no

    for m in node_attr_re.finditer(source):
        node_name, attrs = m.group(1), m.group(2)
        if node_name.lower() in ("node", "edge", "graph", "digraph", "subgraph"):
            continue
        line_no = _line_at(m.start())
        _register_node(node_name, line_no)
        if "parallelogram" in attrs or "async=true" in attrs or node_name.startswith(("Awaiting", "Fetching", "Stream", "Loading")):
            async_nodes.add(node_name)

    for m in edge_chain_re.finditer(source):
        chain_str, attrs = m.group(1), m.group(2) or ""
        line_no = _line_at(m.start())
        chain_groups: List[List[str]] = []
        for part in chain_str.split("->"):
            part_str = part.strip()
            if part_str.startswith("{") and part_str.endswith("}"):
                grp = [t.group(1) for t in node_token_re.finditer(part_str[1:-1])]
            else:
                tok = node_token_re.search(part_str)
                grp = [tok.group(1)] if tok else []
            if grp:
                chain_groups.append(grp)
        for grp in chain_groups:
            for n in grp:
                _register_node(n, line_no)
                if n.startswith(("Awaiting", "Fetching", "Stream", "Loading")):
                    async_nodes.add(n)
        for idx in range(len(chain_groups) - 1):
            for src in chain_groups[idx]:
                for dst in chain_groups[idx + 1]:
                    out_edges.setdefault(src, []).append((dst, attrs, line_no))
                    in_degree[dst] = in_degree.get(dst, 0) + 1

    if not nodes:
        return violations

    canonical_initial_names = {"Init", "Initial", "Idle", "Start", "Created"}
    explicit_initials = {n for n in nodes if n in canonical_initial_names}
    # Only fall back to nodes[0] if no canonical initial state name exists in the graph
    initial_nodes = explicit_initials if explicit_initials else {nodes[0]}

    terminal_names = {"disposed", "closed", "done", "completed", "terminated", "end", "final", "cancelled", "error", "failed"}
    exit_keywords = ("error", "cancel", "dispose", "fail", "abort", "timeout", "close")

    for n in nodes:
        outs = out_edges.get(n, [])
        ins = in_degree.get(n, 0)
        n_line = node_lines.get(n, 1)
        if n not in initial_nodes and ins == 0:
            violations.append({
                "file": str(dot_path),
                "line": n_line,
                "rule": "DOT002",
                "message": f"Unreachable state: '{n}' has in-degree 0 and is not an initial state.",
                "reflex": f"Connect an incoming transition into '{n}' or remove the orphan state node.",
            })
        if n.lower() not in terminal_names and len(outs) == 0:
            violations.append({
                "file": str(dot_path),
                "line": n_line,
                "rule": "DOT001",
                "message": f"Deadlock risk: Non-terminal state '{n}' has out-degree 0.",
                "reflex": f"Add at least one outgoing transition from '{n}' or rename it as a terminal sink.",
            })

    for an in sorted(async_nodes):
        outs = out_edges.get(an, [])
        an_line = node_lines.get(an, 1)
        has_teardown = any(
            any(k in dst.lower() or k in attrs.lower() for k in exit_keywords)
            for dst, attrs, _ in outs
        )
        if len(outs) < 2 or not has_teardown:
            violations.append({
                "file": str(dot_path),
                "line": an_line,
                "rule": "SCAR-PROC-152",
                "message": f"Async state '{an}' lacks explicit teardown/cancel/error exit edge (out-degree={len(outs)}).",
                "reflex": f"Add an explicit transition from '{an}' to a Disposed, Cancelled, or Error state.",
            })
        for dst, attrs, edge_line in outs:
            if not any(k in dst.lower() for k in exit_keywords) and not guard_pred_re.search(attrs):
                violations.append({
                    "file": str(dot_path),
                    "line": edge_line,
                    "rule": "SCAR-ASYNC-01",
                    "message": f"Late-arrival zombie race on '{an} -> {dst}': missing '[guard: ...]' predicate on edge label.",
                    "reflex": f'Add a cancellation/epoch guard on the resolution edge, e.g. {an} -> {dst} [label="onResolve [guard: !isClosed && reqId == activeReqId]"].',
                })

    return violations


def _load_context_signatures(context_map_path: Optional[str]) -> Dict[str, Dict[str, Any]]:
    """
    Loads optional Scar Context Signatures mapping rule IDs to anchor file hashes:
    {
      "TK002": {"anchor_file": "pyproject.toml", "sha256": "<expected_hex>", "expires_utc": "2026-12-31T00:00:00Z"}
    }
    When the anchor file's current hash diverges from expected_hex (or expires_utc has passed),
    the rule transitions from ENFORCED to PROBATIONARY_REVERIFY (preventing Scar Ossification).
    """
    if not context_map_path:
        return {}
    p = pathlib.Path(context_map_path).resolve()
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _apply_context_signatures(
    violations: List[Dict[str, Any]],
    context_sigs: Dict[str, Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Splits violations into (enforced_violations, probationary_warnings) based on
    whether the rule's pinned AST/dependency ContextSignature has drifted or expired.
    """
    if not context_sigs:
        return violations, []

    enforced: List[Dict[str, Any]] = []
    probationary: List[Dict[str, Any]] = []
    drift_cache: Dict[str, Tuple[bool, str]] = {}
    now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())

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
            expires_str = sig_info.get("expires_utc", "")
            anchor_path = pathlib.Path(anchor_str).resolve() if anchor_str else None

            exp_ts = _parse_iso_utc_ts(expires_str) if expires_str else None
            if exp_ts is not None and now_ts > exp_ts:
                drift_cache[rule_id] = (True, "TTL_EXPIRED")
            elif not anchor_path or not anchor_path.is_file() or not expected_sha:
                drift_cache[rule_id] = (True, "ANCHOR_MISSING")
            elif _sha256_file(anchor_path) != expected_sha:
                drift_cache[rule_id] = (True, "ANCHOR_SHA_DRIFT")
            else:
                drift_cache[rule_id] = (False, "VALID")

        is_drifted, drift_reason = drift_cache[rule_id]
        if is_drifted:
            v_copy = dict(v)
            v_copy["severity"] = "PROBATIONARY_REVERIFY"
            v_copy["autoimmune_drift"] = True
            v_copy["drift_reason"] = drift_reason
            probationary.append(v_copy)
        else:
            v["severity"] = "ENFORCED"
            enforced.append(v)

    return enforced, probationary


_STAT_CACHE_ANTI_RACY_NS = 50_000_000  # 50 ms NTFS/POSIX mtime granularity guard


def _ast_rules_hash(author_target: Optional[str]) -> str:
    raw = f"{_SCHEMA_VERSION}:TK001,TK002,PATH001,PATH002,AUTH001,MUT001:{author_target or ''}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _resolve_stat_cache_path(target_path: pathlib.Path) -> pathlib.Path:
    git_root = _find_git_root_pure(target_path)
    base_dir = git_root if git_root is not None else (target_path if target_path.is_dir() else target_path.parent)
    return base_dir / ".ag_state" / "stat_cache.json"


def _load_stat_cache(cache_path: pathlib.Path) -> Dict[str, Any]:
    if not cache_path.is_file():
        return {"version": _SCHEMA_VERSION, "entries": {}, "results": {}}
    try:
        data = json.loads(cache_path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("entries"), dict) and isinstance(data.get("results"), dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"version": _SCHEMA_VERSION, "entries": {}, "results": {}}


def _lint_python_source(
    py_path: pathlib.Path,
    source: str,
    author_target: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    violations: List[Dict[str, Any]] = []
    source_lines = source.splitlines()
    if author_target:
        lines = source_lines[:25]
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
        return violations, [], []

    ctx = _LintFileContext(str(py_path), source_lines=source_lines)
    _prescan_top_level_ttk_imports(tree, ctx)
    SinglePassVisitor(ctx).visit(tree)
    violations.extend(ctx.violations)
    return violations, ctx.warnings, ctx.suppressed_mutations


def _lint_file(py_path: pathlib.Path, author_target: Optional[str] = None) -> List[Dict[str, Any]]:
    try:
        source = py_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [{"file": str(py_path), "line": 1, "rule": "IO_ERROR", "message": str(exc)}]
    violations, _, _ = _lint_python_source(py_path, source, author_target)
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
    strict_mode = bool(getattr(args, "strict", False))
    no_cache = bool(getattr(args, "no_cache", False))
    cache_enabled = not strict_mode and not no_cache
    t0 = time.perf_counter()

    cache_path = _resolve_stat_cache_path(target_path) if cache_enabled else None
    cache_data = _load_stat_cache(cache_path) if cache_path is not None else {"entries": {}, "results": {}}
    cache_entries: Dict[str, Any] = cache_data["entries"]
    cache_results: Dict[str, Any] = cache_data["results"]
    rules_hash = _ast_rules_hash(author_param)
    cache_dirty = False
    now_ns = time.time_ns()

    raw_violations: List[Dict[str, Any]] = []
    files_checked = 0
    cache_hits = 0

    ignore_dirs = {".git", ".venv", "venv", "node_modules", "site-packages", "__pycache__", "build", "dist"}

    def _lint_py_cached(fpath: pathlib.Path) -> None:
        nonlocal cache_dirty, cache_hits
        if cache_path is not None:
            try:
                rel_key = fpath.relative_to(cache_path.parent.parent).as_posix()
            except ValueError:
                rel_key = fpath.as_posix()
        else:
            rel_key = fpath.as_posix()
        if cache_enabled:
            try:
                st = fpath.stat()
                if st.st_mtime_ns <= now_ns and (now_ns - st.st_mtime_ns) >= _STAT_CACHE_ANTI_RACY_NS:
                    entry = cache_entries.get(rel_key)
                    if (
                        isinstance(entry, list)
                        and len(entry) == 4
                        and entry[0] == st.st_mtime_ns
                        and entry[1] == st.st_size
                        and entry[3] == rules_hash
                    ):
                        cached_res = cache_results.get(rel_key)
                        if isinstance(cached_res, dict):
                            for item in cached_res.get("violations", []):
                                raw_violations.append(dict(item))
                            cache_hits += 1
                            return
            except OSError:
                st = None
        else:
            st = None

        try:
            raw_bytes = fpath.read_bytes()
        except OSError as exc:
            raw_violations.append({"file": str(fpath), "line": 1, "rule": "IO_ERROR", "message": str(exc)})
            return

        source = raw_bytes.decode("utf-8", errors="replace")
        file_violations, file_warnings, file_suppressed = _lint_python_source(fpath, source, author_param)
        raw_violations.extend(file_violations)

        if cache_enabled:
            try:
                if st is None:
                    st = fpath.stat()
                if st.st_mtime_ns <= now_ns:
                    file_sha = hashlib.sha256(raw_bytes).hexdigest()
                    cache_entries[rel_key] = [st.st_mtime_ns, st.st_size, file_sha, rules_hash]
                    cache_results[rel_key] = {
                        "violations": [dict(v) for v in file_violations],
                        "warnings": [dict(w) for w in file_warnings],
                        "suppressed_mutations": [dict(s) for s in file_suppressed],
                    }
                    cache_dirty = True
            except OSError:
                pass

    if target_path.is_file():
        if target_path.suffix == ".py":
            _lint_py_cached(target_path)
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
                    _lint_py_cached(fpath)
                    files_checked += 1
                elif include_dot and fname.endswith(".dot"):
                    raw_violations.extend(_lint_dot_state_machine(fpath))
                    files_checked += 1

    if cache_enabled and cache_dirty and cache_path is not None:
        try:
            _atomic_write_json(cache_path, cache_data)
        except OSError as exc:
            sys.stderr.write(f"[ag_ops] Warning: could not persist stat cache to {cache_path}: {exc}\n")

    enforced_violations, probationary_warnings = _apply_context_signatures(raw_violations, context_sigs)
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)

    payload: Dict[str, Any] = {
        "ok": len(enforced_violations) == 0,
        "elapsed_ms": elapsed_ms,
        "files_checked": files_checked,
        "cache_hits": cache_hits,
        "violations_count": len(enforced_violations),
        "violations": enforced_violations,
    }
    if probationary_warnings:
        payload["probationary_count"] = len(probationary_warnings)
        payload["probationary_warnings"] = probationary_warnings

    if strict_mode and probationary_warnings:
        payload["ok"] = False
        payload["error"] = "STRICT_PROBATIONARY: Findings degraded to probationary status rejected under --strict."
        return _emit(payload, args.json, exit_code=2)

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


def _strip_leading_docstring(body: List[ast.stmt]) -> List[ast.stmt]:
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


class _StringLiteralScrubber(ast.NodeTransformer):
    """Normalizes string constants to '<STR>' so pure typo/message tweaks do not trigger AST regret."""

    def visit_Constant(self, node: ast.Constant) -> ast.AST:
        if isinstance(node.value, str):
            return ast.Constant(value="<STR>")
        return node

    def visit_JoinedStr(self, node: ast.JoinedStr) -> ast.JoinedStr:
        new_values: List[ast.expr] = []
        for val in node.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                new_values.append(ast.Constant(value="<STR>"))
            else:
                v = self.visit(val)
                if isinstance(v, ast.expr):
                    new_values.append(v)
        return ast.JoinedStr(values=new_values)


class _FuncHashVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.scope: List[str] = []
        # Maps qualified_name -> (exact_ast_hash, structural_no_strings_hash)
        self.defs: Dict[str, Tuple[str, str]] = {}

    def _hash_func_node(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> Tuple[str, str]:
        stripped_body = _strip_leading_docstring(node.body)
        clone = copy.deepcopy(node)
        clone.body = stripped_body
        exact_dump = ast.dump(clone, include_attributes=False)
        exact_hash = hashlib.sha256(exact_dump.encode("utf-8")).hexdigest()

        scrubbed_tree = _StringLiteralScrubber().visit(clone)
        struct_dump = ast.dump(scrubbed_tree, include_attributes=False)
        struct_hash = hashlib.sha256(struct_dump.encode("utf-8")).hexdigest()
        return exact_hash, struct_hash

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        qualified_name = ".".join(self.scope + [node.name]) if self.scope else node.name
        self.defs[qualified_name] = self._hash_func_node(node)
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        qualified_name = ".".join(self.scope + [node.name]) if self.scope else node.name
        self.defs[qualified_name] = self._hash_func_node(node)
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()


def _extract_ast_function_hashes(py_source: str) -> Dict[str, Tuple[str, str]]:
    """
    Maps qualified function/method names (e.g. ClassName.method) to
    (exact_ast_sha256, structural_no_strings_sha256).
    """
    try:
        tree = ast.parse(py_source)
    except SyntaxError:
        return {}

    visitor = _FuncHashVisitor()
    visitor.visit(tree)
    return visitor.defs


def _git_changed_line_sets(repo_path: pathlib.Path, commit_sha: str, rel_file: str) -> Tuple[Set[str], Set[str]]:
    """Returns (added_lines, deleted_lines) stripped of whitespace for a file in a commit."""
    git_bin = _resolve_git_binary()
    cmd = [
        git_bin,
        "-C", str(repo_path),
        "-c", "core.quotepath=false",
        "show",
        "--format=",
        "--unified=0",
        commit_sha,
        "--",
        rel_file,
    ]
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


def _git_batch_changed_line_sets(
    repo_path: pathlib.Path,
    commit_shas: List[str],
    rel_files: List[str],
) -> Dict[Tuple[str, str], Tuple[Set[str], Set[str]]]:
    """Loads (added_lines, deleted_lines) for multiple commits/files in one Git process."""
    result: Dict[Tuple[str, str], Tuple[Set[str], Set[str]]] = {}
    if not commit_shas or not rel_files:
        return result
    git_bin = _resolve_git_binary()
    cmd = [
        git_bin,
        "-C", str(repo_path),
        "-c", "core.quotepath=false",
        "-c", "diff.mnemonicPrefix=false",
        "-c", "diff.noprefix=false",
        "log",
        "--no-walk",
        "--stdin",
        "--format=COMMIT|%H",
        "--unified=0",
        "--no-renames",
        "-m",
        "--first-parent",
        "-p",
        "--",
        *rel_files,
    ]
    kwargs: Dict[str, Any] = {
        "input": "\n".join(commit_shas) + "\n",
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": 15.0,
    }
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    try:
        proc = subprocess.run(cmd, **kwargs)  # nosec B603
    except (OSError, subprocess.SubprocessError):
        return result
    if proc.returncode != 0:
        return result

    cur_sha: Optional[str] = None
    cur_file: Optional[str] = None
    minus_file: Optional[str] = None
    for line in proc.stdout.splitlines():
        if line.startswith("COMMIT|"):
            cur_sha = line[7:].strip()
            cur_file = None
            minus_file = None
            continue
        if cur_sha is None:
            continue
        if line.startswith("diff --git "):
            cur_file = None
            minus_file = None
            continue
        if line.startswith("--- "):
            raw_old = line[4:].strip()
            minus_file = raw_old[2:] if raw_old.startswith("a/") else (None if raw_old == "/dev/null" else raw_old)
            continue
        if line.startswith("+++ "):
            raw_new = line[4:].strip()
            plus_file = raw_new[2:] if raw_new.startswith("b/") else (None if raw_new == "/dev/null" else raw_new)
            cur_file = plus_file or minus_file
            if cur_file is not None:
                result.setdefault((cur_sha, cur_file), (set(), set()))
            continue
        if cur_file is None or line.startswith("@@") or line.startswith("index ") or line.startswith("\\"):
            continue
        if line.startswith("+"):
            clean = line[1:].strip()
            if clean:
                result.setdefault((cur_sha, cur_file), (set(), set()))[0].add(clean)
        elif line.startswith("-"):
            clean = line[1:].strip()
            if clean:
                result.setdefault((cur_sha, cur_file), (set(), set()))[1].add(clean)
    return result


def _parse_iso_utc_ts(ts_str: str) -> Optional[int]:
    if not ts_str or not isinstance(ts_str, str):
        return None
    try:
        dt = datetime.datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)
        return int(dt.timestamp())
    except ValueError:
        return None


def _load_receipt_collision_timestamps(state_dir: Optional[pathlib.Path]) -> List[int]:
    """Extracts Unix timestamps of guard collisions and renegotiations from .ag_state."""
    if not state_dir or not state_dir.is_dir():
        return []
    timestamps: Set[int] = set()
    for fpath in state_dir.glob("merkle_guard_*.json"):
        try:
            data = json.loads(fpath.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue
            for col in data.get("collisions", []):
                if isinstance(col, dict):
                    ts_val = _parse_iso_utc_ts(col.get("timestamp_utc", ""))
                    if ts_val is not None:
                        timestamps.add(ts_val)
            raw_hist = data.get("renegotiation_history", [])
            if isinstance(raw_hist, list):
                for ren in raw_hist:
                    if isinstance(ren, dict):
                        for key in ("renegotiated_at", "timestamp"):
                            ts_val = _parse_iso_utc_ts(ren.get(key, ""))
                            if ts_val is not None:
                                timestamps.add(ts_val)
                if len(raw_hist) > 0 or data.get("status") == "RENEGOTIATED_RED":
                    ts_val = _parse_iso_utc_ts(data.get("timestamp_utc", ""))
                    if ts_val is not None:
                        timestamps.add(ts_val)
        except (OSError, json.JSONDecodeError, ValueError):
            continue
    return sorted(timestamps)


def _cmd_regret_mine(args: argparse.Namespace) -> int:
    """
    Stage-1 Deterministic Rapid-Regret Miner (Target 90):
    Scans consecutive per-file Git commits within --window-min (default 60m) for
    overlapping AST function modifications and separates genuine Trap-to-Reflex regret
    from healthy Green -> Refactor TDD cadence and pure string/typo edits via
    Commit-Intent / Test-Delta Asymmetry, structural AST hashing, and .ag_state receipt correlation.
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

    git_bin = _resolve_git_binary()
    git_cmd = [
        git_bin,
        "-C", str(repo_path),
        "-c", "core.quotepath=false",
        "log",
        "-n", str(limit),
        "--format=COMMIT|%H|%ct|%s",
        "--name-only",
    ]
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
    string_only_edits_filtered = 0

    # Memoization caches to avoid redundant `git cat-file` + `ast.parse` calls across commit pairs
    ast_defs_cache: Dict[Tuple[str, str], Dict[str, Tuple[str, str]]] = {}
    diff_lines_cache: Dict[Tuple[str, str], Tuple[Set[str], Set[str]]] = {}
    diff_batch_loaded = False

    with GitBatchReader(repo_path) as git_reader:
        def _get_cached_defs(commit_sha: str, rel_file: str) -> Dict[str, Tuple[str, str]]:
            key = (commit_sha, rel_file)
            if key not in ast_defs_cache:
                src_txt = git_reader.read_text(commit_sha, rel_file) or ""
                ast_defs_cache[key] = _extract_ast_function_hashes(src_txt)
            return ast_defs_cache[key]

        def _get_cached_diff_lines(commit_sha: str, rel_file: str) -> Tuple[Set[str], Set[str]]:
            nonlocal diff_batch_loaded
            key = (commit_sha, rel_file)
            if not diff_batch_loaded and key not in diff_lines_cache:
                diff_batch_loaded = True
                candidate_shas = [c["sha"] for c in commits]
                candidate_files = sorted({pf for c in commits for pf in c["py_files"]})
                batch_diffs = _git_batch_changed_line_sets(repo_path, candidate_shas, candidate_files)
                for b_key, b_val in batch_diffs.items():
                    diff_lines_cache.setdefault(b_key, b_val)
            if key not in diff_lines_cache:
                diff_lines_cache[key] = (set(), set())
            return diff_lines_cache[key]

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
                if delta_sec < 0 and abs(delta_sec) > window_sec:
                    continue
                abs_delta_sec = abs(delta_sec)

                shared_py = (set(newer["py_files"]) & set(older["py_files"])) - paired_files
                if not shared_py:
                    continue

                for rel_file in sorted(shared_py):
                    paired_files.add(rel_file)

                    defs_new = _get_cached_defs(newer["sha"], rel_file)
                    defs_old = _get_cached_defs(older["sha"], rel_file)

                    exact_changed_funcs = [
                        fn for fn in defs_new
                        if fn in defs_old and defs_new[fn][0] != defs_old[fn][0]
                    ]
                    if not exact_changed_funcs:
                        continue

                    # Filter out functions where only string literals (typos/messages) changed
                    overlapping_funcs = [
                        fn for fn in exact_changed_funcs
                        if defs_new[fn][1] != defs_old[fn][1]
                    ]
                    if not overlapping_funcs:
                        string_only_edits_filtered += 1
                        continue

                    has_fix_verb = bool(_FIX_VERB_RE.search(newer["subject"]))
                    is_pure_refactor = bool(_REFACTOR_VERB_RE.search(newer["subject"])) and not has_fix_verb

                    signals: List[str] = []
                    if has_fix_verb:
                        signals.append("FIX_VERB_INTENT")
                    if len(newer["test_files"]) > 0:
                        signals.append("TEST_ASSERTION_DELTA")
                    low_ts, high_ts = min(older["ts"], newer["ts"]), max(older["ts"], newer["ts"])
                    if any(low_ts <= ev_ts <= high_ts for ev_ts in receipt_events_ts):
                        signals.append("GUARD_COLLISION_RECEIPT")

                    if not is_pure_refactor:
                        added_k, _ = _get_cached_diff_lines(older["sha"], rel_file)
                        _, deleted_k1 = _get_cached_diff_lines(newer["sha"], rel_file)
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
                        "delta_minutes": round(abs_delta_sec / 60.0, 2),
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
            "string_only_edits_filtered": string_only_edits_filtered,
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
    p_guard.add_argument("guard_action", choices=["witness-red", "verify-green", "renegotiate", "check-scope"])
    p_guard.add_argument("--test-dir", default=None, help="Test file or directory to seal in Merkle tree.")
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
    p_guard.add_argument("--allow-head-move", action="store_true", help="Allow Git HEAD to differ from witnessed_head_sha during verify-green/renegotiate.")
    p_guard.add_argument("--base-ref", default=None, help="Anchor branch/ref for git merge-base ancestor and spec immutability checks.")
    p_guard.add_argument("--base", default="origin/main", help="Base ref for guard check-scope diff comparison (default: origin/main).")
    p_guard.add_argument("--rule-paths", default="", help="Comma-separated governance/spec paths for guard check-scope.")
    p_guard.add_argument("--repo", default=".", help="Git repository path for guard check-scope (default: .).")
    p_guard.add_argument("--forbid-addopts", default="", help="Comma-separated addopts flags/patterns to forbid in pytest configs (e.g. '-p no:cov,-p no:assertion').")
    p_guard.add_argument("--allow-env-passthrough", action="store_true", help="Allow tainted environment variables (e.g. PYTEST_ADDOPTS) and record in receipt.")
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
    p_lint.add_argument("--strict", action="store_true", help="Rejects probationary findings with STRICT_PROBATIONARY (exit code 2) if anchor drift occurred.")
    p_lint.add_argument("--no-cache", action="store_true", help="Disable incremental .ag_state/stat_cache.json lookup.")
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
