# Changelog

Todos los cambios notables de `ag_ops` se documentan en este archivo.
El formato se basa en [Keep a Changelog](https://keepachangelog.com/es-ES/1.0.0/) y este proyecto se adhiere a [Semantic Versioning](https://semver.org/lang/es/).

Creado por Francisco Grandón Vergara

## [Unreleased]

### Corregido
- **Documentación (`README.md`)**: Alineación exacta de ejemplos CLI, flags `argparse` y claves JSON frente al contrato real de `ag_ops.py` v2.1.0 (`--timeout`, clave `raw_log` y ruta por defecto `./logs/raw_<timestamp>.log` en `distill`; argumento obligatorio `--dir .ag_state` en `state`; verbos reales de `_FIX_VERB_RE` en `FIX_VERB_INTENT` y criterio de Etapa 1 `len(newer["test_files"]) > 0` en `TEST_ASSERTION_DELTA` para `regret-mine`).

## [2.1.0] - 2026-10-31

### Añadido
- **Motor CLI de Gobernanza (`ag_ops.py`)**: Implementación determinista en Python 3.9+ puro (100% biblioteca estándar, sin dependencias externas, sub-milisegundo y offline).
- **Módulo `guard`**:
  - Sellado de árbol de pruebas mediante hashes Merkle SHA-256.
  - Aislamiento de recibos criptográficos por target: `.ag_state/merkle_guard_<sha256(normcase(target))[:12]>.json`.
  - Subcomando `witness-red`: Valida fallo inicial legítimo (rechazando anomalías de sintaxis o entorno: 2, 3, 4, 5, 126, 127, 9009) y emite recibo v2.
  - Subcomando `verify-green`: Reejecuta la prueba y aborta con `EACCES_TEST_TAMPERING` (`exit 2`) ante cualquier modificación en archivos sellados, registrando colisiones en vuelo.
  - Subcomando `renegotiate`: Protocolo de Testigo Constructivo (**SCAR-PROC-150**) con `--require-witness` contra retractaciones perezosas (`LAZY_RETRACTION_REJECTED`), soportando `--witness-type` (`spec-collision`, `api-lock`, `arch-fork`).
- **Módulo `distill`**:
  - Destilación determinista de registros de prueba y compilación en grupos de procesos aislados con control de timeout.
  - Anclaje estricto de regex (`^\s*E\s{3}`, `AssertionError`, trazas y panics) para evitar falsos positivos ante salidas como `"DONE   all good"`.
- **Módulo `state`**:
  - Runlevels lexicográficos (`NN_<slug>.json`) inspirados en `/etc/init.d` para supervivencia de contexto ante compactaciones.
  - Sellado automático de hashes SHA-256 en creación de artefactos.
  - Detección de deriva con `--strict` (`exit 2`), diferenciando `ARTIFACT_NEVER_EXISTED` de `FILE_DELETED`.
- **Módulo `ast-lint`**:
  - Linter estático ultra-rápido (< 40 ms) para Python AST: `TK001`, `TK002`, `PATH001` (con emisión de Vector 4 `reflex`), `PATH002` (aislamiento de `unittest.mock`) y `AUTH001`.
  - Mitigación de deriva autoinmune con `--context-map` (`PROBATIONARY_REVERIFY`).
  - Validación topológica Graphviz DOT (Target 15): deadlocks (`DOT001`), alcanzabilidad (`DOT002`), salidas de escape en estados asíncronos (`SCAR-PROC-152`) y predicados de guarda contra callbacks zombis (`SCAR-ASYNC-01`).
- **Módulo `regret-mine`**:
  - Minería de arrepentimiento rápido en Git (Etapa 1) en ventanas configurables (`--window-min`, defecto 60 min).
  - 4 puertas de asimetría deterministas: `FIX_VERB_INTENT`, `TEST_ASSERTION_DELTA`, `LINE_REVERSAL_OVERLAP` (con protección de refactor) y `GUARD_COLLISION_RECEIPT`.
- **Suite de Pruebas**: Verificación automatizada con cobertura de 6/6 bloques (`tests/test_ag_ops.py`).
- **Documentación Técnica**: `README.md` unificado con arquitectura física, contratos y fundamentación teórica.
