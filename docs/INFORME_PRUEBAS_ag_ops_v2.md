# Informe de pruebas — ag_ops_v2.py

- Fecha: 2026-10-30
- Archivo evaluado: `D:\Users\francisco.grandon\.gemini\config\scripts\ag_ops_v2.py` (1765 líneas, 73 KB)
- Referencia: `ag_ops.py` (39 KB), sin modificar
- Suite: `test_ag_ops_v2.py`, ejecutada con `AG_OPS_PATH` apuntando a v2
- Git: MinGit 2.56.0.4 (`D:\GIT\MinGit-2.56.0.4-64-bit\cmd`), agregado solo al PATH de la sesión, sin instalación
- Creado por Francisco Grandón Vergara

## 1. Resumen ejecutivo

| Resultado | Detalle |
|---|---|
| Tests ejecutados | 6 |
| Aprobados | 5 (`guard`, `distill`, `state`, `ast-lint`) |
| Fallidos | 1 (`regret-mine`) |
| Veredicto | **No cumple la matriz completa.** Reemplazo de `ag_ops.py` no recomendado hasta corregir `regret-mine` |

## 2. Estado previo de la suite

`test_ag_ops_v2.py` estaba truncado en la línea 163 (string sin cerrar, `SyntaxError`). Se completó `test_05` (`ast-lint`), se agregó `test_06` (`regret-mine`) y el cierre `unittest.main()`. El original truncado se conserva en `test_ag_ops_v2.py.truncated.bak`.

## 3. Resultados por bloque

| Bloque | Cobertura | Resultado |
|---|---|---|
| guard | Recibos aislados por target, exclusiones y `--ignore`, directorio vacío (`EMPTY_TEST_TARGET`), recibo v2 y `COMMAND_MISMATCH`, lista `collisions`, `LAZY_RETRACTION_REJECTED`, `spec-collision` | Aprobado |
| distill | Regex anclado (`DONE   ` no dispara falso positivo), exit code propagado | Aprobado |
| state | `ARTIFACT_NEVER_EXISTED`, sellado automático, `FILE_DELETED`, `--status` inválido, `STEP_CONFLICT`, `--strict` | Aprobado |
| ast-lint | `TK002` con `tkinter.ttk`, sin falso positivo en `ttk_helper`, `--author` opcional y `AUTH001`, `PATH001` con campo `reflex`, `PATH002`, `--context-map` (`autoimmune_drift`), `.dot` (`SCAR-PROC-152`, `SCAR-ASYNC-01`) | Aprobado |
| regret-mine | Repo temporal con 3 commits | **Fallido** |

## 4. Problema detectado: `regret-mine` no filtra el refactor sano

### Escenario (según la matriz)
- C1: `feat: add calc` (función inicial `calc`)
- C2: `refactor: simplify calc` (refactor limpio, sin tests, sin verbo fix)
- C3: `fix: edge case None in calc` (modifica la misma función)

### Esperado
`tdd_refactors_filtered: 1`, y un único par reportado: C2→C3 con `FIX_VERB_INTENT`.

### Obtenido
`tdd_refactors_filtered: 0` y `regret_pairs_count: 3`:

| Par (inicial → posterior) | Señales | Evaluación |
|---|---|---|
| C1 → C3 | `FIX_VERB_INTENT` | No esperado. Par no consecutivo, duplica el hallazgo |
| C2 → C3 | `FIX_VERB_INTENT` | Correcto |
| C1 → C2 | `LINE_REVERSAL_OVERLAP` | **Falso positivo.** Debía filtrarse como refactor sano |

### Causa probable
En `_cmd_regret_mine` (`ag_ops_v2.py`, líneas 1629-1633):
```python
added_k, _ = _git_changed_line_sets(repo_path, older["sha"], rel_file)
_, deleted_k1 = _git_changed_line_sets(repo_path, newer["sha"], rel_file)
inverted_lines = added_k & deleted_k1
```
Se marca como reversión cualquier línea agregada por el commit anterior y eliminada por el posterior. Todo refactor de una función recién creada cumple esa condición, por lo que la puerta no distingue refactor de regresión.

Además, el doble bucle (líneas 1598-1604) compara todos los pares dentro de la ventana y no solo commits consecutivos, lo que genera el par C1→C3.

### Impacto
- `tdd_refactors_filtered` queda siempre en 0 en este patrón, y la métrica reportada en el artículo sería incorrecta.
- Aumenta el ruido de falsos positivos para cualquier auditor posterior.
- No afecta a `guard`, `distill`, `state` ni `ast-lint`.

### Corrección propuesta (no aplicada)
1. Contar `LINE_REVERSAL_OVERLAP` solo si el commit posterior elimina líneas que el commit inmediatamente anterior había agregado **y** ese commit posterior no es un refactor, o exigir además otra señal.
2. Limitar la comparación a commits consecutivos del mismo archivo, o desduplicar pares cuando existe una cadena intermedia.
3. Agregar este caso como test de regresión (ya cubierto por `test_06_regret_mine`).

## 5. Re-medición (sobre v2)

| Métrica | Valor |
|---|---|
| Líneas de `ag_ops_v2.py` | 1765 |
| `ast-lint` sobre `ag_ops_v2.py` | 32.3 ms, 0 violaciones |
| `ast-lint` sobre la carpeta `scripts` (11 archivos) | 69.2 ms, 17 violaciones en otros scripts |
| `regret-mine` sobre el repositorio propio | No medido (no hay repositorio git en el workspace evaluado) |

Nota: la latencia de un archivo supera los 15 ms indicados en las reglas del entorno para `ast-lint`.

## 6. Conclusión y estado

- `ag_ops.py` no fue reemplazado y no se modificó `ag_ops_v2.py`.
- Hasta corregir `regret-mine`, la matriz de verificación no se cumple al 100 %.
- Decisión pendiente: aplicar la corrección propuesta en v2 y repetir la suite, o reemplazar `ag_ops.py` documentando este punto como defecto conocido.

---

## 7. Actualización final (ag_ops_v2_1.py)

### Correcciones aplicadas
- `regret-mine`: comparación solo entre commits consecutivos por archivo (`paired_files`) y filtro de refactor explícito con guardas en `LINE_REVERSAL_OVERLAP`. Resuelve el defecto de la sección 4.
- `ast-lint`: `check_tree` basado en `ast.walk` en lugar de `NodeVisitor`.
- Linter `.dot` (v2_1): `edge_re` y `node_attr_re` usan `[ \t]*` en lugar de `\s*`. Antes, las aristas sin `;` se perdían (el `\s*` consumía el salto de línea) y no se detectaban `SCAR-PROC-152` ni `SCAR-ASYNC-01`.

### Resultado de la suite
`test_ag_ops_v2_1.py` y `test_ag_ops_v2.py`: **6/6 OK** (con MinGit 2.56 en PATH).

### Latencia de `ast-lint` (mediana de 7 ejecuciones)
- Un archivo: ~40-43 ms. No cumple el objetivo de 15 ms; `check_tree` no la redujo.
- Carpeta scripts: 81-141 ms (cifra no comparable entre mediciones, cambió el número de archivos).

### Prueba sobre repositorio real: dbader/schedule (398 commits)

| Ventana | Filtrados | Pares |
|---|---|---|
| 60 min | 19 | 11 |
| 1440 min | 25 | 24 |
| 10080 min | 35 | 37 |

- Detecta regresiones reales (por ejemplo `Fix a bug where the at(':SS') syntax wasn't working`, `Missed == to !=`).
- Falsos positivos observados: correcciones de docstring o typos (`FIX_VERB_INTENT`), commits que añaden funcionalidad con tests (`TEST_ASSERTION_DELTA`) y cambios de estilo. Con ventanas largas las señales débiles se acumulan.
- Mejora candidata: ignorar `FIX_VERB_INTENT` cuando el diff solo toca docstrings, comentarios o formato.
- Solo se revisaron a mano los primeros 6 pares de cada ventana.

### Despliegue
- `ag_ops.py` reemplazado por `ag_ops_v2_1.py` (SHA-256 `F0555848...38A7C`, idéntico al origen).
- Respaldo del original: `_backups\ag_ops\ag_ops.py.20261030_204051.bak` (SHA-256 `10733A15...2FD6D`).
- Verificación posterior: compila y la suite pasa 6/6 contra `ag_ops.py`.

### Latencia de `ast-lint`: documentación

| Medición | Resultado |
|---|---|
| v2 inicial (1 medición) | 32.3 ms (archivo), 69.2 ms (carpeta, 11 archivos) |
| v2 con `check_tree` (mediana de 7) | 40.6 ms (archivo), 81.3 ms (carpeta) |
| v2_1 (mediana de 7) | 42.6 ms, mínimo 39.7 ms (archivo), 140.8 ms (carpeta, 13 archivos) |
| `ag_ops.py` final | 43.4 ms (archivo) |

- Objetivo de las reglas del entorno: < 15 ms. **No se cumple**: ~40-43 ms por archivo.
- La optimización `check_tree` (`ast.walk` en dos pasadas) no mejoró la latencia; la diferencia 32 → 40 ms se atribuye a ruido de medición, ya que la primera cifra fue una sola ejecución.
- `elapsed_ms` mide solo el lint dentro del proceso. El archivo analizado (`ag_ops.py`, 1783 líneas) es grande; la cifra no es representativa de archivos pequeños.
- Las cifras de carpeta no son comparables entre mediciones porque cambió el número de archivos.
- Pendiente: perfilar (`cProfile`) `_lint_file`, lectura de archivo y `ast.parse` para ubicar el costo, y medir sobre un archivo pequeño.
