# CLI Engine for Agent Governance (`ag_ops`)

> Creado por Francisco Grandón Vergara

Motor CLI determinista en Python puro (librería estándar, offline y de baja latencia) diseñado para la gobernanza estricta, trazabilidad y control de ejecución en sistemas y agentes autónomos de IA.

## Módulos y Capacidades Principales

1. **`guard` (Merkle Lock & Witnessed Verification)**:
   - Sella árboles de archivos de prueba mediante hashes SHA-256 (`merkle_guard_<sha256[:12]>.json`).
   - Evita la alteración o sabotaje de pruebas entre la fase roja (`witness-red`) y verde (`verify-green`).
   - Registro de colisiones y protocolo de testigo constructivo SCAR-PROC-150 (`renegotiate`).

2. **`distill` (Log Distillation)**:
   - Captura y destila de forma determinista la salida crítica de comandos y suites extensas.
   - Detección precisa y anclada de errores de pytest, unittest, compiladores y panics.

3. **`state` (Runlevels Lexicográficos)**:
   - Gestión de estados de ejecución persistentes en disco (`NN_<slug>.json`).
   - Detección y verificación estricta de *drift* sobre artefactos producidos (`--strict`).

4. **`ast-lint` (Linter Estático AST y Máquinas de Estado .DOT)**:
   - Análisis sintáctico estático ultra-rápido sin ejecución de código.
   - Reglas de integridad: `TK001`, `TK002`, `PATH001`, `PATH002`, `AUTH001`.
   - Validación de máquinas de estados `.dot`: `DOT001`, `DOT002`, `SCAR-PROC-152`, `SCAR-ASYNC-01`.
   - Soporte para context signatures (`--context-map`) contra *Autoimmune Drift*.

5. **`regret-mine` (Rapid-Regret AST & Receipt Miner)**:
   - Detección en historial Git de regresiones inmediatas sobre funciones AST en ventanas temporales parametrizables.
   - Puertas de asimetría para separar refactorizaciones sanas (Green -> Refactor) de regresiones reales (`FIX_VERB_INTENT`, `LINE_REVERSAL_OVERLAP`, `TEST_ASSERTION_DELTA`, `GUARD_COLLISION_RECEIPT`).

## Estructura del Proyecto

```text
├── ag_ops_v2.py           # Motor CLI ejecutable principal
├── CHANGELOG.md           # Historial de cambios (Keep a Changelog)
├── tests/
│   ├── test_ag_ops_v2.py   # Suite de pruebas automatizada
│   └── test_ag_ops_v2_1.py # Suite de pruebas de regresión completa (6/6 bloques)
└── docs/
    ├── INFORME_PRUEBAS_ag_ops_v2.md
    ├── CHANGELOG - ag_ops.py.txt
    └── Matriz de verificacion - test autonomo y re-medidcion - ag_ops.py.txt
```

## Ejecución de Pruebas

Para ejecutar la suite de pruebas automatizada en Windows:

```powershell
$env:AG_OPS_PATH = "$PWD\ag_ops_v2.py"
python tests\test_ag_ops_v2_1.py
```
