# Guía de Integración Quirúrgica para `ag_ops_v2.py`

Este documento contiene **únicamente los bloques modificados** durante la auditoría y el **motivo técnico** de cada cambio, estructurados como bloques `ANTES` y `DESPUÉS` independientes del número de línea para que el agente Antigravity los integre en tu versión local sin sobrescribir tus ajustes de Windows (`_resolve_git_binary`, `_run_command_isolated`, `_is_symlink_or_junction`, etc.).

## Resumen de los 12 bloques de cambio

| Bloque | Función / Subcomando | Motivo técnico del cambio |
| :--- | :--- | :--- |
| **1** | Imports + `_atomic_write_json` | Evitar fallo `OSError: [Errno 95] Operation not supported` (`ENOTSUP` / `EOPNOTSUPP` / `EINVAL`) cuando `os.fsync` se ejecuta sobre montajes virtuales o FUSE. |
| **2** | `_sha256_file` | Evitar que `normalize_eol=True` reemplace bytes `\r\n` por `\n` dentro de archivos binarios (con bytes NUL `\x00`), lo cual impedía detectar corrupción binaria en `guard verify-green`. |
| **3** | `_compute_merkle_tree` | Evitar que `--state-dir` configurado como directorio ancestro de `--test-dir` excluya todos los archivos de prueba por la condición `resolved_state in fpath.parents` (`EMPTY_TEST_TARGET`). |
| **4** | `_validate_file_line_ref` | Rechazar archivos vacíos (`0` líneas) donde antes `max(1, total_lines)` permitía `archivo_vacio.py:1` como ancla válida en `spec-collision` / `arch-fork`. |
| **5** | `_verify_constructive_witness` (`arch-fork`) | Rechazar etiquetas vacías (`@file:line`), etiquetas repetidas o anclas `file:line` duplicadas entre las opciones de `--fork-options`. |
| **6** | `_cmd_guard` (`witness-red`, `verify-green`, `renegotiate`) | Capturar `(ValueError, OSError)` en las llamadas post-ejecución a `_compute_merkle_tree` (ej. si el comando de prueba crea un symlink dentro de `test_dir`) para devolver JSON estructurado (`SELF_MUTATING_TEST_DIR`) en vez de abortar con `Traceback`. Además, registrar `"renegotiated_at"` y preservar `"constructive_witness"` en `renegotiation_history`. |
| **7** | `_cmd_distill` | Eliminar la línea vacía sintética producida por `(stdout_txt + "\n" + stderr_txt).splitlines()` y conservar todas las líneas cuando `total_lines <= max_lines` sin truncar el inicio antes de `first_err - 2`. |
| **8** | `_cmd_state` (`write` y `status`) | Detectar conflictos de paso con distinto zero-padding (`05_*.json` vs `005_*.json`) usando `_STEP_FILE_RE`, validar que el JSON y `artifacts` sean `dict`, y usar `art_path.is_file()` en vez de `art_path.exists()` para no lanzar `IsADirectoryError` si un artefacto es reemplazado por un directorio. |
| **9** | `_AntigravityVisitor` (`ast-lint`) | Detectar `from unittest import mock` en módulos de producción (`PATH002`) y registrar en `self.ttk_direct_imports` únicamente widgets de `_TTK_WIDGETS` (evitando falsos positivos `TK002` al importar `from tkinter.ttk import Style`). |
| **10** | `_lint_dot_state_machine` (`ast-lint`) | Ignorar comentarios (`/* ... */`, `//`, `#`) preservando números de línea, soportar transiciones encadenadas (`A -> B -> C`), soportar destinos agrupados (`A -> {B C}`), soportar atributos multilínea (`[...]`) y reportar la línea exacta de cada nodo/arista en `DOT001`, `DOT002`, `SCAR-PROC-152` y `SCAR-ASYNC-01`. |
| **11** | `_FuncHashVisitor` (`regret-mine`) | Eliminar el docstring inicial (`ast.Expr(ast.Constant(str))`) del cuerpo de funciones y métodos antes de calcular el hash AST, evitando falsos positivos cuando un commit solo corrige o documenta un docstring. |
| **12** | `_load_receipt_collision_timestamps` y `_cmd_regret_mine` | Correlacionar correctamente el timestamp real en que ocurrió `guard renegotiate` (`renegotiated_at` / `timestamp_utc` en estado `RENEGOTIATED_RED`) para emitir `GUARD_COLLISION_RECEIPT`, y manejar timestamps de commits no monotónicos (`delta_sec < 0` tras rebase o clock skew) usando `abs(delta_sec)`. |

## Bloque 1: Imports y `_atomic_write_json`

**Motivo**: En montajes virtuales o FUSE, `os.fsync(f.fileno())` lanza `OSError(95, 'Operation not supported')` (`ENOTSUP` / `EOPNOTSUPP`) o `EINVAL`. Capturar esos códigos específicos evita que `guard` y `state` fallen al persistir JSON en esos sistemas de archivos.

### ANTES
```python
import argparse
import ast
import datetime
import fnmatch
```
```python
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
```

### DESPUÉS
```python
import argparse
import ast
import datetime
import errno
import fnmatch
```
```python
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
```

## Bloque 2: `_sha256_file`

**Motivo**: Si `test_dir` incluye fixtures binarios (que contienen bytes NUL `\x00` y secuencias `\r\n`, como cabeceras PNG `\x89PNG\r\n\x1a\n`), reemplazar incondicionalmente `\r\n` por `\n` ocultaba modificaciones binarias durante `verify-green`.

### ANTES
```python
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
```

### DESPUÉS
```python
def _sha256_file(path: pathlib.Path, normalize_eol: bool = False) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        if normalize_eol:
            content = f.read()
            if b"\x00" not in content:
                content = content.replace(b"\r\n", b"\n")
            h.update(content)
        else:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    return h.hexdigest()
```

## Bloque 3: `_compute_merkle_tree`

**Motivo**: Cuando el usuario pasa un `--state-dir` que es directorio padre/ancestro de `--test-dir` (por ejemplo `--state-dir .` y `--test-dir ./tests`), `resolved_state in fpath.parents` era verdadero para todos los archivos dentro de `test_dir`, excluyéndolos todos y provocando `EMPTY_TEST_TARGET`. Solo debe excluirse `resolved_state` cuando está dentro de `test_dir`.

### ANTES
```python
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
                d_raw = root_path / d
                if _is_symlink_or_junction(d_raw):
                    raise ValueError(f"Symlinks and junctions are forbidden in Merkle guard target: {d_raw}")
                d_path = d_raw.resolve()
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
                fpath_raw = root_path / fname
                if _is_symlink_or_junction(fpath_raw):
                    raise ValueError(f"Symlinks and junctions are forbidden in Merkle guard target: {fpath_raw}")
                fpath = fpath_raw.resolve()
                if resolved_receipt and fpath == resolved_receipt:
                    continue
                if resolved_state and resolved_state in fpath.parents:
                    continue
```

### DESPUÉS
```python
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
```

## Bloque 4: `_validate_file_line_ref`

**Motivo**: `max(1, total_lines)` devolvía `1` cuando el archivo estaba vacío (`total_lines == 0`), aceptando `empty.py:1` como referencia válida en `spec-collision` o `arch-fork`.

### ANTES
```python
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
```

### DESPUÉS
```python
def _validate_file_line_ref(ref: str) -> Tuple[bool, str]:
    """Validates 'path/to/file.py:42' exists on disk, is non-empty, and line is within bounds."""
    if ":" not in ref:
        return False, f"Reference '{ref}' must follow 'file:line' format."
    raw_path, raw_line = ref.rsplit(":", 1)
    if not raw_path.strip():
        return False, f"Reference '{ref}' is missing a file path."
    try:
        line_no = int(raw_line)
    except ValueError:
        return False, f"Invalid line number in '{ref}'."
    fpath = pathlib.Path(raw_path.strip()).resolve()
    if not fpath.is_file():
        return False, f"Referenced file does not exist: {fpath}"
    total_lines = len(fpath.read_text(encoding="utf-8", errors="replace").splitlines())
    if total_lines == 0:
        return False, f"Referenced file is empty (0 lines): {fpath.name}"
    if line_no < 1 or line_no > total_lines:
        return False, f"Line {line_no} out of range (1..{total_lines}) in {fpath.name}"
    return True, f"{fpath.as_posix()}:{line_no}"
```

## Bloque 5: `_verify_constructive_witness` (`arch-fork`)

**Motivo**: Impedir que un agente pase `--fork-options "@file.py:1|@file.py:1"` con etiquetas vacías o apuntando exactamente al mismo `file:line` en ambas ramas de la bifurcación.

### ANTES
```python
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
```

### DESPUÉS
```python
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
            ok_ref, msg_ref = _validate_file_line_ref(ref.strip())
            if not ok_ref:
                return False, f"INVALID_ARCH_FORK_PROOF: {msg_ref}", None
            if clean_label in seen_labels:
                return False, f"INVALID_ARCH_FORK_PROOF: Duplicate fork option label '{clean_label}'.", None
            if msg_ref in seen_anchors:
                return False, f"INVALID_ARCH_FORK_PROOF: Duplicate fork option blast-radius anchor '{msg_ref}'.", None
            seen_labels.add(clean_label)
            seen_anchors.add(msg_ref)
            verified_options.append({"option": clean_label, "anchor": msg_ref})
        return True, "VALID", {"type": "arch-fork", "options": verified_options}
```

## Bloque 6: `_cmd_guard` (captura de excepciones post-ejecución y timestamp de `renegotiate`)

**Motivo**:
1. En `witness-red` y `renegotiate`, la segunda llamada a `_compute_merkle_tree` (después de correr `--cmd`) no estaba envuelta en `try ... except (ValueError, OSError)`. Si el comando de prueba creaba un symlink dentro de `test_dir`, el programa terminaba con `Traceback` no controlado en lugar de emitir JSON (`SELF_MUTATING_TEST_DIR`).
2. En `renegotiate`, la entrada añadida a `renegotiation_history` solo guardaba `old_data.get("timestamp_utc")` (el instante previo, ej. `witness-red`) sin guardar `renegotiated_at` ni preservar `constructive_witness`, causando que `regret-mine` no pudiera correlacionar el instante en que ocurrió la renegociación entre dos commits.

### ANTES (en `witness-red`)
```python
        try:
            pre_hash, pre_files = _compute_merkle_tree(test_path, state_dir, receipt_path, cli_ignore)
        except ValueError as exc:
            return _emit({"ok": False, "error": f"GUARD_INIT_FAILED: {exc}"}, args.json, exit_code=1)
```
```python
        tree_hash, files_map = _compute_merkle_tree(test_path, state_dir, receipt_path, cli_ignore)
        if tree_hash != pre_hash:
```

### DESPUÉS (en `witness-red`)
```python
        try:
            pre_hash, pre_files = _compute_merkle_tree(test_path, state_dir, receipt_path, cli_ignore)
        except (ValueError, OSError) as exc:
            return _emit({"ok": False, "error": f"GUARD_INIT_FAILED: {exc}"}, args.json, exit_code=1)
```
```python
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
```

### ANTES (en `verify-green` y `renegotiate`)
```python
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
```
```python
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
```

### DESPUÉS (en `renegotiate` + `except (ValueError, OSError)` en `verify-green` / `renegotiate`)
```python
        old_tree_hash = None
        old_cmd = None
        inherited_ignore: List[str] = []
        renegotiated_at_iso = _utc_now_iso()

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
                hist_entry: Dict[str, Any] = {
                    "timestamp": old_data.get("timestamp_utc"),
                    "renegotiated_at": renegotiated_at_iso,
                    "status": old_data.get("status"),
                    "reason": old_data.get("reason"),
                    "tree_hash": old_tree_hash,
                    "cmd": old_cmd,
                }
                if "constructive_witness" in old_data:
                    hist_entry["constructive_witness"] = old_data["constructive_witness"]
                history.append(hist_entry)
```
```python
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

        new_receipt: Dict[str, Any] = {
            "version": 2,
            "status": "RENEGOTIATED_RED",
            "timestamp_utc": renegotiated_at_iso,
```

## Bloque 7: `_cmd_distill`

**Motivo**:
1. `(stdout_txt + "\n" + stderr_txt).splitlines()` inyectaba una línea vacía extra cuando `stderr_txt` era vacío.
2. Cuando `total_lines <= max_lines` y ocurría un error en la línea `k > 2`, `start_head = max(0, first_err - 2)` descartaba las primeras líneas `0..k-3` aunque la salida completa ya cabía dentro de `max_lines`.

### ANTES
```python
    all_lines = (stdout_txt + "\n" + stderr_txt).splitlines()
    total_lines = len(all_lines)
```
```python
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
```

### DESPUÉS
```python
    all_lines = stdout_txt.splitlines() + stderr_txt.splitlines()
    total_lines = len(all_lines)
```
```python
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
```

## Bloque 8: `_cmd_state` (`write` y `status`)

**Motivo**:
1. `_STEP_FILE_RE` acepta de 2 a 4 dígitos (`05_a.json` y `005_b.json`), pero `state write` solo buscaba conflictos con `glob(f"{step_str}_*.json")`, permitiendo pasos duplicados con distinto zero-padding.
2. En `state status`, si un artefacto había sido borrado y reemplazado por un directorio del mismo nombre, `art_path.exists()` era `True` y `_sha256_file(art_path)` lanzaba `IsADirectoryError`, marcando el archivo de estado como `CORRUPTED_STATE_FILE` en vez de `FILE_DELETED`.

### ANTES
```python
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
```
```python
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
```

### DESPUÉS
```python
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
```
```python
        for _, _, fpath in candidates:
            try:
                data = json.loads(fpath.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    raise ValueError("State record must be a JSON object")
                artifacts = data.get("artifacts", {})
                if not isinstance(artifacts, dict):
                    raise ValueError("'artifacts' field must be a JSON object")
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
                        if not art_path.is_file():
```

## Bloque 9: `_AntigravityVisitor` (`ast-lint`)

**Motivo**:
1. `from unittest import mock` tiene `node.module == "unittest"` y `alias.name == "mock"`, por lo que no era detectado por `node.module in ("unittest.mock", "mock")` en `PATH002`.
2. `from tkinter.ttk import Style` registraba `Style` en `self.ttk_direct_imports`, disparando un falso positivo `TK002` en `Style(bg="red")`. Además, si se importaba `from tkinter.ttk import Button as MyBtn`, el mensaje de `TK002` decía `ttk.MyBtn` en lugar del widget canónico `ttk.Button`.

### ANTES
```python
class _AntigravityVisitor:
    def __init__(self, filename: str):
        self.filename = filename
        self.is_test_file = _is_test_filepath(filename)
        self.violations: List[Dict[str, Any]] = []
        self.ttk_module_aliases: Set[str] = {"ttk", "tkinter.ttk"}
        self.ttk_direct_imports: Set[str] = set()
```
```python
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
```
```python
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
```

### DESPUÉS
```python
class _AntigravityVisitor:
    def __init__(self, filename: str):
        self.filename = filename
        self.is_test_file = _is_test_filepath(filename)
        self.violations: List[Dict[str, Any]] = []
        self.ttk_module_aliases: Set[str] = {"ttk", "tkinter.ttk"}
        self.ttk_direct_imports: Dict[str, str] = {}
```
```python
        elif node.module == "tkinter.ttk":
            for alias in node.names:
                if alias.name == "*":
                    for w in _TTK_WIDGETS:
                        self.ttk_direct_imports[w] = w
                elif alias.name in _TTK_WIDGETS:
                    self.ttk_direct_imports[alias.asname or alias.name] = alias.name
        elif node.module in ("unittest.mock", "mock") and not self.is_test_file:
            self.violations.append({
                "file": self.filename,
                "line": node.lineno,
                "rule": "PATH002",
                "message": f"Mocking primitives from '{node.module}' imported in production module.",
                "reflex": "Remove unittest.mock imports from production modules; pass dependencies via constructor or callable parameters.",
            })
        elif node.module == "unittest" and not self.is_test_file:
            for alias in node.names:
                if alias.name == "mock":
                    self.violations.append({
                        "file": self.filename,
                        "line": node.lineno,
                        "rule": "PATH002",
                        "message": "Mocking module 'unittest.mock' imported in production module.",
                        "reflex": "Remove unittest.mock imports from production modules; pass dependencies via constructor or callable parameters.",
                    })
```
```python
    def _check_call(self, node: ast.Call) -> None:
        widget_canonical = ""
        is_ttk = False

        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            prefix = _dotted_name(node.func.value)
            if prefix in self.ttk_module_aliases and func_name in _TTK_WIDGETS:
                is_ttk = True
                widget_canonical = func_name
        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.ttk_direct_imports:
                is_ttk = True
                widget_canonical = self.ttk_direct_imports[func_name]

        # Rule TK002: forbidden background/foreground on confirmed ttk widgets only
        if is_ttk:
            for kw in node.keywords:
                if kw.arg in ("background", "foreground", "bg", "fg"):
                    self.violations.append({
                        "file": self.filename,
                        "line": node.lineno,
                        "rule": "TK002",
                        "message": f"Direct '{kw.arg}=' argument forbidden on ttk.{widget_canonical}. Use ttk.Style() or tk equivalent.",
                        "reflex": f"Configure '{kw.arg}' via ttk.Style().configure('<Style>.T{widget_canonical}', ...) or switch to tk.{widget_canonical}.",
                    })
```

## Bloque 10: `_lint_dot_state_machine` (`ast-lint`)

**Motivo**: Limpiar comentarios (`/* ... */`, `//`, `#`) conservando los saltos de línea, soportar transiciones encadenadas (`Init -> Fetching -> Done`), soportar grupos de nodos (`Fetching -> {Done Error}`), soportar atributos `[...]` multilínea y reportar el número de línea real de cada nodo/transición en lugar de `"line": 1`.

### ANTES
```python
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
```

### DESPUÉS
```python
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

    initial_nodes = {nodes[0], "Init", "Initial", "Idle", "Start", "Created"}
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
```

## Bloque 11: `_FuncHashVisitor` (`regret-mine`)

**Motivo**: Excluir el docstring inicial (`ast.Expr(ast.Constant(str))`) antes de ejecutar `ast.dump` en `_FuncHashVisitor` para que commits que solo corrigen o agregan docstrings no cambien el hash AST de la función ni disparen falsos positivos en `regret-mine`.

### ANTES
```python
class _FuncHashVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.scope: List[str] = []
        self.defs: Dict[str, str] = {}

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        qualified_name = ".".join(self.scope + [node.name]) if self.scope else node.name
        body_dump = ast.dump(node, include_attributes=False)
        self.defs[qualified_name] = hashlib.sha256(body_dump.encode("utf-8")).hexdigest()
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        qualified_name = ".".join(self.scope + [node.name]) if self.scope else node.name
        body_dump = ast.dump(node, include_attributes=False)
        self.defs[qualified_name] = hashlib.sha256(body_dump.encode("utf-8")).hexdigest()
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()
```

### DESPUÉS
```python
def _strip_leading_docstring(body: List[ast.stmt]) -> List[ast.stmt]:
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        return body[1:]
    return body


class _FuncHashVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.scope: List[str] = []
        self.defs: Dict[str, str] = {}

    def _hash_func_node(self, node: Union[ast.FunctionDef, ast.AsyncFunctionDef]) -> str:
        stripped_body = _strip_leading_docstring(node.body)
        if isinstance(node, ast.AsyncFunctionDef):
            clone: Union[ast.FunctionDef, ast.AsyncFunctionDef] = ast.AsyncFunctionDef(
                name=node.name,
                args=node.args,
                body=stripped_body,
                decorator_list=node.decorator_list,
                returns=node.returns,
                type_comment=getattr(node, "type_comment", None),
            )
        else:
            clone = ast.FunctionDef(
                name=node.name,
                args=node.args,
                body=stripped_body,
                decorator_list=node.decorator_list,
                returns=node.returns,
                type_comment=getattr(node, "type_comment", None),
            )
        body_dump = ast.dump(clone, include_attributes=False)
        return hashlib.sha256(body_dump.encode("utf-8")).hexdigest()

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
```

## Bloque 12: `_load_receipt_collision_timestamps` y `_cmd_regret_mine`

**Motivo**:
1. Extraer `renegotiated_at` de `renegotiation_history` y `timestamp_utc` cuando `status == "RENEGOTIATED_RED"` para que `regret-mine` detecte renegociaciones ocurridas entre el commit inicial y el commit de corrección (`GUARD_COLLISION_RECEIPT`).
2. Usar `abs(delta_sec)` y `min`/`max` en la comparación de ventana temporal para que commits con timestamps no monotónicos (por rebase o clock skew) fuera de `--window-min` no se emparejen con `delta_minutes` negativo.

### ANTES
```python
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
        except (OSError, json.JSONDecodeError, ValueError):
            continue
    return sorted(timestamps)
```
```python
        for j in range(i + 1, len(commits)):
            older = commits[j]
            delta_sec = newer["ts"] - older["ts"]
            if delta_sec > window_sec:
                break

            shared_py = (set(newer["py_files"]) & set(older["py_files"])) - paired_files
```
```python
                if len(newer["test_files"]) > 0:
                    signals.append("TEST_ASSERTION_DELTA")
                if any(older["ts"] <= ev_ts <= newer["ts"] for ev_ts in receipt_events_ts):
                    signals.append("GUARD_COLLISION_RECEIPT")
```
```python
                regret_pairs.append({
                    "file": rel_file,
                    "overlapping_functions": overlapping_funcs,
                    "delta_minutes": round(delta_sec / 60.0, 2),
                    "initial_commit": older["sha"][:8],
```

### DESPUÉS
```python
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
```
```python
        for j in range(i + 1, len(commits)):
            older = commits[j]
            delta_sec = newer["ts"] - older["ts"]
            if delta_sec > window_sec:
                break
            if delta_sec < 0 and abs(delta_sec) > window_sec:
                continue
            abs_delta_sec = abs(delta_sec)

            shared_py = (set(newer["py_files"]) & set(older["py_files"])) - paired_files
```
```python
                if len(newer["test_files"]) > 0:
                    signals.append("TEST_ASSERTION_DELTA")
                low_ts, high_ts = min(older["ts"], newer["ts"]), max(older["ts"], newer["ts"])
                if any(low_ts <= ev_ts <= high_ts for ev_ts in receipt_events_ts):
                    signals.append("GUARD_COLLISION_RECEIPT")
```
```python
                regret_pairs.append({
                    "file": rel_file,
                    "overlapping_functions": overlapping_funcs,
                    "delta_minutes": round(abs_delta_sec / 60.0, 2),
                    "initial_commit": older["sha"][:8],
```

## Verificación posterior a la integración

Una vez aplicados los 12 bloques por el agente Antigravity, ejecutar:

```bash
python ag_ops_v2.py ast-lint ag_ops_v2.py --author "Francisco Grandón Vergara" --json
python test_ag_ops_v2.py -v
```
