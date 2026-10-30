# Changelog

Todos los cambios notables de `ag_ops.py` se documentan aquí.
Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/).

Creado por Francisco Grandón Vergara

## [Unreleased]

### Añadido
- Suite de pruebas `test_ag_ops_v2_1.py` (6 bloques: guard, distill, state, ast-lint, regret-mine) y `test_ag_ops_v2.py`.
- Informe `INFORME_PRUEBAS_ag_ops_v2.md` con resultados, defectos y latencia.

## [2.1] - 2026-10-30

Reemplaza a `ag_ops.py` v1 (respaldo: `_backups/ag_ops/ag_ops.py.20261030_204051.bak`).

### Añadido
- `guard`: recibos aislados por target (`merkle_guard_<sha256[:12]>.json`), `--ignore` persistido en el recibo, rechazo de directorios vacíos (`EMPTY_TEST_TARGET`), validación estricta de versión 2, `cmd` e historial (`CORRUPTED_RECEIPT`), registro de colisiones, `--witness-type` y `--require-witness` (SCAR-PROC-150).
- `state`: `ARTIFACT_NEVER_EXISTED`, validación de `--status`, `--strict` (exit 2 con drift), `STEP_CONFLICT` y `--replace`.
- `ast-lint`: `PATH001`, `PATH002`, campo `reflex`, `--context-map` (`PROBATIONARY_REVERIFY`), lint de `.dot` (`DOT001`, `DOT002`, `SCAR-PROC-152`, `SCAR-ASYNC-01`), `--author` opcional.
- Subcomando `regret-mine` (filtro determinista de etapa 1 sobre historial Git).

### Cambiado
- `distill`: regex de errores anclado al inicio de línea.
- `ast-lint`: resolución de cadenas de atributos para `TK002`; recorrido con `check_tree` (`ast.walk`) en lugar de `NodeVisitor`.
- `regret-mine`: comparación solo entre commits consecutivos por archivo y filtro de refactor explícito con guardas en `LINE_REVERSAL_OVERLAP`.

### Corregido
- `regret-mine`: falso positivo en refactor sano (C1→C2) y par duplicado C1→C3.
- Linter `.dot`: `edge_re` y `node_attr_re` usan `[ \t]*`; las aristas sin `;` ya no se pierden.

### Conocido
- Latencia de `ast-lint` ~40-43 ms por archivo (objetivo: 15 ms); `check_tree` no la redujo.
- `regret-mine` sobre `dbader/schedule` (398 commits) genera falsos positivos en correcciones de docstring, typos y estilo (`FIX_VERB_INTENT`).
