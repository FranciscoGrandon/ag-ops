# Changelog

Todos los cambios notables de `ag_ops.py` se documentan aquí.
Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/).

Creado por Francisco Grandón Vergara

## [2.4.0] - 2026-11-20

### Añadido
- **Hardening P0 de Superficie Raíz y Entorno (`guard`)**:
  - Sellado de `root_config_manifest` y `root_config_base` desde `--test-dir` hasta la raíz del repositorio/workspace (`conftest.py`, `pytest.ini`, `pyproject.toml`, `setup.cfg`, `tox.ini`, `sitecustomize.py`, `usercustomize.py`), registrando `ABSENT` para archivos inexistentes y detectando altas o mutaciones tardías como `ROOT_CONFIG_DRIFT` (exit `2`), además de rechazo a symlinks/junctions en ancestros y configuraciones raíz.
  - Inspección determinista de `addopts` con `tomllib`/`configparser` bloqueando flags evasivos (`--collect-only`, `--co`, filtros `-k`/`--ignore`/`--ignore-glob` no declarados en `--cmd`) y patrones personalizados mediante `--forbid-addopts` (`UNSAFE_PYTEST_ADDOPTS`, exit `2`).
  - Sanitización por defecto de `PYTEST_ADDOPTS` y `PYTHONSTARTUP` (`ENV_TAINT_DETECTED`, exit `2`) y política auditable `env_policy` mediante `--allow-env-passthrough` (impidiendo relajar la política entre `witness-red` y `verify-green`).
  - Extracción y verificación del conteo efectivo de pruebas ejecutadas (`witnessed_test_count`), rechazando ejecuciones vacías (`ZERO_TESTS_EXECUTED`, exit `2`) y reducciones de cobertura parametrizada (`TEST_COUNT_REGRESSION`, exit `2`).
  - Evolución del esquema de recibos a `schema_version: "2.4"` manteniendo compatibilidad de lectura/verificación con recibos históricos v2.3 sin `schema_version`.
  - +6 escenarios adversariales en `benchmark_agent_failures.py` (`TAM-07`..`TAM-12`) sobre un total de 36 escenarios.
- **Motor de Rendimiento P1 (100% stdlib)**:
  - `SinglePassVisitor` con tabla de despacho `_DEFAULT_LINT_DISPATCH` y `_LintFileContext` en un único recorrido AST por archivo `.py`, además de `_StringLiteralScrubber` directo sobre clones AST sin `ast.unparse`/`ast.parse`.
  - Hashing acelerado con `hashlib.file_digest` en archivos binarios/sin normalización y streaming por bloques de 64 KB con acarreo de `\r` en frontera para normalización CRLF->LF en `_sha256_file`.
  - `GitBatchReader` (`git cat-file --batch`) para lectura por lotes en un único subproceso de Git en `guard renegotiate` y `regret-mine`, junto con `_git_batch_changed_line_sets`.
  - Caché incremental `.ag_state/stat_cache.json` por `(mtime_ns, size, sha256, ast_rules_hash)` con guardia anti-racy de 50 ms y protección contra retroceso de reloj (`mtime_ns > now_ns`), desactivable con `--no-cache` y deshabilitada automáticamente en `--strict`.
- **Gobernanza P2 de Historial, Ciclos y Alcance**:
  - Anclaje mediante `--base-ref <ref>` en `guard witness-red` y `guard renegotiate` usando `git merge-base --is-ancestor` (habilitando commits legítimos que avanzan `HEAD` sobre pruebas selladas) y bloqueo de alteraciones en especificaciones citadas desde el `merge-base` (`SPEC_MODIFIED_SINCE_BASE`, exit `2`). Auditoría explícita `HEAD_MOVE_ALLOWED` al utilizar `--allow-head-move`.
  - Detector determinista de oscilaciones `k`-ciclo (`recent_tree_hashes` acotado a 16 estados con `collections.deque(maxlen=16)`) en `guard` (`merkle_guard_<hash>.json`) y `state` (`.ag_state/oscillation_history.json`), deteniendo ciclos ping-pong `k >= 1` con `OSCILLATION_CYCLE_DETECTED` (exit `2`).
  - Nuevo subcomando `guard check-scope --base <ref> --rule-paths <rutas> [--repo <dir>] --json` que evalúa `git diff --name-only <base>...HEAD` e impide mezclar reglas/especificaciones con código productivo (`MIXED_SCOPE_VIOLATION`, exit `2`).
- **Ergonomía y Sensor AST P3**:
  - Renegociación agrupada atómica `guard renegotiate --batch <manifiesto.json>` bajo un único testigo constructivo `SCAR-PROC-150` compartido (`batch_id`), con rollback completo (cero recibos escritos) ante cualquier objetivo en verde o testigo inválido (sin `--force`).
  - Regla AST `MUT001` integrada en `SinglePassVisitor` para detectar mutaciones ocultas en métodos de consulta (`get_*`, `is_*`, `has_*`, `validate_*`: `self.<attr> =`, `AugAssign`, `AnnAssign`, `del`, `global`, `.append/.extend/.pop/.clear/.update` sin descender a ámbitos anidados); advertencia no bloqueante por defecto, bloqueante con `--strict` y supresión explícita auditable `# ag_ops: allow-mutation: <razón>`.
- **Suite v2.4**: Nueva batería `tests/test_ag_ops_v2_4.py` (18 pruebas cubriendo cero dependencias externas y fases P0–P3).

### Cambiado
- Construcción de subparsers enfocada por subcomando en `build_parser(only_subcommand=...)`, guarda previa a `stream.reconfigure` si stdout/stderr ya están en UTF-8 y captura de `oscillation_history.json` dentro del mismo `os.scandir` en `state status`, reduciendo la latencia de arranque y estado por debajo de v2.3 en todas las métricas medidas.

### Corregido
- **Normalización de carpetas con punto inicial (`.gemini/`, `.ag_state/`)**: Reemplazo de `.lstrip("./")` por `_normalize_repo_relpath()` en `_compute_working_tree_hash` y `_guard_check_scope` para no truncar el punto inicial de rutas como `.gemini/rules/policy.md`.

### Seguridad
- Elevación de contención en *Manipulación de Pruebas* de `5/6` (`83.3 %`) en v2.3 a `12/12` (`100.0 %`) en el benchmark adversarial extendido (contención global `31/36` = `86.11 %`), documentando las fronteras remanentes en `THREAT_MODEL.md`.

## [2.3.0] - 2026-11-02

### Añadido
- **Anclaje Criptográfico contra Working-Tree y Local-Commit Forgery (Randal L. Schwartz)**: `_get_git_repo_and_head` captura `witnessed_head_sha` (`git rev-parse --verify HEAD`) en `witness-red` y lo sella en el recibo. En `verify-green` y `renegotiate` se valida que HEAD no haya mutado (`HEAD_MOVED_DURING_RED_PHASE`), admitiendo `--allow-head-move` para flujos humanos explícitos.
- **Inmutabilidad de Testigos en Repositorio Git**: `_validate_file_line_ref` lee archivos ancla directamente del objeto Git inmutable (`git show <pinned_sha>:<rel_path>`), rechazando archivos no confirmados (`UNCOMMITTED_WITNESS_FILE`) y líneas triviales/comentarios (`TRIVIAL_WITNESS_LINE`).
- **Trazabilidad de Fallo Rojo y Extractos de Testigos (Amber D. #1 y #3)**: `_extract_red_signature` extrae líneas exactas de error/aserción durante `witness-red` y `renegotiate`, persistiendo `red_signature` en el recibo y publicando `resolved_red_signature` en `verify-green`. `_verify_constructive_witness` almacena los extractos literales (`excerpt_a`, `excerpt_b`, `excerpt`) en el recibo y registra intentos fallidos en `collisions` (`INVALID_CONSTRUCTIVE_WITNESS`).
- **Filtro de Literales de Cadenas y Typo Discard (Amber D. #5)**: `_StringLiteralScrubber` normaliza constantes `str` y `JoinedStr` a `"<STR>"`, obteniendo tupla `(exact_hash, struct_hash)` en `_FuncHashVisitor`. Cambios que solo afecten literales de texto se descartan de `regret-mine` y se auditan en `string_only_edits_filtered`.
- **Cachés de Rendimiento en `regret-mine`**: Adición de `ast_defs_cache` y `diff_lines_cache` indexadas por `(commit_sha, rel_file)`, minimizando ejecuciones repetidas de `git show` y `ast.parse`.
- **Expiración TTL en Context Signatures (Amber D. #9)**: `_apply_context_signatures` soporta `"expires_utc"` en `--context-map`, reportando `TTL_EXPIRED`, `ANCHOR_SHA_DRIFT` o `ANCHOR_MISSING`.
- **Auditoría de Artefactos Tardíos en `state status`**: Detección de artefactos en estado `NOT_FOUND` al momento de `state write`. En modo estándar emite `late_sealed_notices` (`LATE_ARTIFACT_SEALED`) con sellado automático; en modo `--strict` aborta con `LATE_ARTIFACT_UNSEALED_AT_WRITE` (exit 2).
- **Validación Robusta de Nodos Iniciales en Graphviz DOT**: Priorización de nombres iniciales explícitos (`Init`, `Initial`, `Idle`, `Start`, `Created`), usando `nodes[0]` solo como fallback si ninguno existe para prevenir evasión de `DOT002`.
- **Streaming Seguro en `_sha256_file`**: Inspección de primeros 8 KB buscando bytes nulos (`\x00`) y cota `< 10 MB` para normalización CRLF->LF en memoria; archivos binarios o grandes se procesan por bloques de 64 KB.

### Corregido
- **Compatibilidad de `ast.unparse` en Python 3.12**: En `_hash_func_node`, aplicación de `ast.copy_location(clone, node)` y `ast.fix_missing_locations(clone)` previo a `ast.unparse`, evitando `AttributeError: 'FunctionDef' object has no attribute 'lineno'`.

## [2.2.0] - 2026-11-02

### Añadido
- **`guard` (Bloqueo Estricto de `--ignore` - H1)**: Los patrones de exclusión en `verify-green` se leen exclusivamente del recibo rojo sellado. Si se suministra un `--ignore` discrepante por CLI, la ejecución falla inmediatamente con error `IGNORE_PATTERN_MISMATCH` (exit code 2) y registra el evento en la auditoría de colisiones.
- **`guard` (Protección contra Symlinks y Self-Mutation)**: Rechazo explícito y determinista (`ValueError` / `GUARD_INIT_FAILED` y captura post-ejecución `SELF_MUTATING_TEST_DIR`) si el objetivo de prueba contiene un enlace simbólico o un punto de unión NTFS (junction), impidiendo escapes del árbol Merkle.
- **`guard` (Validación Estricta de Testigos Constructivos)**: Rechazo de archivos de 0 líneas como anclas (`Referenced file is empty`), y validación de etiquetas no vacías y no duplicadas para bifurcaciones arquitectónicas (`arch-fork`).
- **`guard` (Preservación Binaria sin CRLF Tampering)**: Desactivación de la normalización CRLF->LF en archivos que contienen bytes NUL (`\x00`), detectando manipulaciones en archivos binarios sellados.
- **`ast-lint` (Modo `--strict` - H3)**: Nueva bandera `--strict` para rechazar con `STRICT_PROBATIONARY` (exit code 2) cualquier infracción que haya sido degradada a `PROBATIONARY_REVERIFY` debido a divergencia, modificación o eliminación de su archivo ancla (`anchor_file`).
- **`ast-lint` (Ampliación de `PATH001`)**: Cobertura estricta para capturas amplias de excepciones (`except:` o `except Exception:`) que silencien errores mediante `continue` o retornos triviales (`return {}`, `return None`, `return []`).
- **`ast-lint` (Soporte DOT Avanzado)**: Limpieza de comentarios (`/* ... */`, `//`, `#`) preservando saltos de línea, análisis de aristas encadenadas (`A -> B -> C`) y reporte de números de línea precisos.
- **`regret-mine` (Soporte UTF-8 / Nombres con Tildes)**: Invocación de Git con `-c core.quotepath=false` para evitar el escape octal de rutas con caracteres especiales (p. ej. `diseño.py`), garantizando su análisis sintáctico.
- **`regret-mine` (Calificación Jerárquica `ClassName.method`)**: Implementación de `_FuncHashVisitor` para mapear funciones de clase con su cualificador completo (`Clase.metodo`), evitando colisiones de nombres planos.
- **`regret-mine` (Correlación con `guard renegotiate`)**: Registro e indexación de marcas temporales `renegotiated_at` en recibos de colisión para correlación temporal con commits de rectificación.
- **Documentación de Seguridad y Arquitectura**: Publicación de `THREAT_MODEL.md` (análisis de tres adversarios y tres niveles de certeza) y `docs/ARCHITECTURE_V2_2_AUTHORITY.md` (modelo de autoridad desacoplada y anclaje de CI).
- **Suite de Pruebas Multiplataforma**: 29 pruebas automatizadas (11 en `test_ag_ops_v2.py` y 18 en `tests/`) ejecutadas al 100% de éxito tanto en Linux (`posix`) como en Windows (`nt`).

### Cambiado
- **Aislamiento `argv` en Subprocesos (H2)**: `_run_command_isolated` ahora soporta `Union[str, List[str]]`. Todas las llamadas internas de Git en `regret-mine` se ejecutan mediante listas de argumentos con `shell=False`.
- **`distill`**: Preservación íntegra de la salida cuando `total_lines <= max_lines` (sin podas artificiales de encabezados informativos) y eliminación de líneas vacías sintéticas por concatenación.
- **`guard`**: Corrección en el cálculo de exclusión de `--state-dir` cuando es un directorio ancestro de `--test-dir`.
- **`state`**: Verificación de colisiones numéricas independiente del formato de relleno con ceros (`05` vs `005`) y tratamiento seguro de artefactos que sean directorios sin abortar.
- **`regret-mine`**: Tolerancia ante desfases temporales o rebases en Git mediante el cálculo de valor absoluto sobre las diferencias de tiempo (`abs(delta_sec)`).
- **Transversal**: Manejo resiliente de sistemas de archivos FUSE o virtuales donde `os.fsync` retorne `ENOTSUP` o `EINVAL`.
- **Limpieza Interna AST**: Sustitución de bloques `except Exception:` en los cargadores internos de firmas y recibos por capturas específicas `(OSError, json.JSONDecodeError, ValueError)`.

### Corregido
- **Compatibilidad de Pruebas en Windows (`nt`)**:
  - Sustitución de `ln -s` por `mklink /J` para creación de puntos de unión en `test_08`.
  - Normalización de comandos de subproceso en `cmd.exe` evitando comillas simples en argumentos `-c`.
  - Resolución dinámica de la ruta de Git para entornos Windows donde `git` no está expuesto en el PATH de sistema.

### Seguridad
- **Inmunidad contra Inyección de Shell en Git**: Mitigación completa de ejecución arbitraria de comandos a través de nombres maliciosos en el historial Git (ej. `a$(touch PWNED).py`).

## [2.1.0] - 2026-10-31

### Añadido
- Publicación formal del repositorio público de código abierto en GitHub: [`FranciscoGrandon/ag-ops`](https://github.com/FranciscoGrandon/ag-ops).
- Lanzamiento del release oficial [`v2.1.0`](https://github.com/FranciscoGrandon/ag-ops/releases/tag/v2.1.0) con notas de cambios estructuradas y licencia MIT.
- Suite de pruebas de regresión e integración pública `tests/test_ag_ops.py` (6/6 bloques aprobados al 100%).
- Aislamiento estricto de artefactos internos en el repositorio público, manteniendo en local las notas de desarrollo y publicando exclusivamente el código fuente ejecutable (`ag_ops.py`), las pruebas y la documentación técnica oficial (`README.md`, `LICENSE`, `CHANGELOG.md`).

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
