# CLI Engine for Agent Governance (`ag_ops` v2.3.0)

> **Creado por Francisco Grandón Vergara**  
> *Motor determinista en Python puro (librería estándar, sin dependencias externas) diseñado para la gobernanza estricta, trazabilidad criptográfica, linters estructurales y minería de regresión.*

[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Dependencies](https://img.shields.io/badge/dependencies-zero%20(stdlib)-brightgreen.svg)](#)
[![Deterministic](https://img.shields.io/badge/architecture-100%25%20deterministic-purple.svg)](#)
[![Tests Status](https://img.shields.io/badge/tests-29%2F29%20passed%20(100%25)-success.svg)](#)
[![Adversarial Benchmark](https://img.shields.io/badge/adversarial%20benchmark-24%2F30%20contained%20(80%25)-blueviolet.svg)](#)

---

## 1. Arquitectura Implementada en la Práctica

`ag_ops.py` es el arnés determinista de ejecución y control de integridad local para agentes autónomos. En lugar de confiar en instrucciones pasivas en los prompts, actúa como un **puente físico entre la ejecución del agente y la verificación de invariantes**: sellado de pruebas, distilación de logs, bloqueo de pasos, validación estática AST, análisis de drift y minería de arrepentimiento.

### 1.1 Diagrama de Flujo y Componentes Físicos en Ejecución

```mermaid
flowchart TD
    subgraph AGY["Entorno Antigravity (Google Antigravity)"]
        Agent["Agente / Subagente Antigravity"] -->|run_command| CLI["ag_ops.py (Python stdlib)"]
    end

    subgraph Core["Motor de Gobernanza Determinista (ag_ops)"]
        CLI --> Guard["1. guard (Merkle Tree & Lock)"]
        CLI --> Distill["2. distill (Aislamiento & Regex)"]
        CLI --> State["3. state (Runlevels 00..99)"]
        CLI --> Lint["4. ast-lint (AST & Graphviz DOT)"]
        CLI --> Mine["5. regret-mine (Minería AST sobre Git)"]
    end

    subgraph Storage["Almacenamiento Local & Artefactos (.ag_state/ & ./logs/)"]
        Guard <-->|Recibo v2.3| Receipts[".ag_state/merkle_guard_<hash[:12]>.json"]
        State <-->|Fases y Hashes| StateFiles[".ag_state/NN_<slug>.json"]
        Distill -->|Log Crudo| RawLog["./logs/raw_<timestamp>.log"]
    end

    subgraph OS["Sistema Operativo & Repositorio"]
        Guard -->|Subproceso| TestRunner["pytest / unittest"]
        Lint -->|ast.walk / < 40ms| Codebase["Archivos .py y .dot"]
        Mine -->|git diff & blame| GitHistory["Historial Git (< 60m)"]
    end

    Core -->|JSON & Exit Codes 0, 1, 2| Agent
```

### 1.2 Invariantes de Ingeniería Implementadas
1. **Cero Dependencias Externas:** 100% biblioteca estándar de Python (`ast`, `hashlib`, `subprocess`, `json`, `pathlib`, `tempfile`). No requiere `pip install`, funcionando instantáneamente en entornos herméticos.
2. **Escritura Atómica con Sincronización a Disco:** Todas las mutaciones de estado en `.ag_state/` usan archivos temporales con `os.replace` y `os.fsync`, previniendo corrupción de recibos antidesordenados.
3. **Contrato Estricto de Códigos de Salida:**
   - `0`: Operación exitosa / Invariantes íntegras.
   - `1`: Error de validación, sintaxis, conflicto de pasos o directorio vacío (`EMPTY_TEST_TARGET`).
   - `2`: **Violación Crítica de Seguridad o Integridad** (sabotaje de tests `EACCES_TEST_TAMPERING`, corrupción de recibos `CORRUPTED_RECEIPT` o deriva de artefactos `has_drift` en modo `--strict`).

---

## 2. Los Cinco Módulos Operativos (Implementación y Contratos)

### 2.1 `guard` — Bloqueo Merkle de Tests y Testigo Constructivo
Sella el árbol de pruebas mediante hashes SHA-256 antes de que el agente altere el código de producción, impidiendo trampas o modificaciones no autorizadas en los tests.

* **Aislamiento por Target:** Los recibos se nombran de forma unívoca según el objetivo:  
  `.ag_state/merkle_guard_<sha256(normcase(target))[:12]>.json`.
* **Bloqueo de `--ignore` y Protección de Symlinks (v2.2+):**
  - **Invariante H1:** En `verify-green`, los patrones `--ignore` se extraen exclusivamente del recibo rojo sellado. Si el agente intenta pasar un `--ignore` discrepante (p. ej. para excluir un caso de regresión), el comando aborta con `IGNORE_PATTERN_MISMATCH` (`exit 2`).
  - **Rechazo de Symlinks:** Detección estricta de enlaces simbólicos (`is_symlink()`) en cualquier punto del árbol de pruebas, levantando `ValueError` y bloqueando posibles fugas fuera del Merkle del repositorio.
* **Subcomandos:**
  - `witness-red`: Ejecuta la suite de pruebas esperada en fallo inicial. Valida códigos de aserción (rechaza anomalías de entorno como 2, 3, 4, 5, 126, 127, 9009), genera el árbol Merkle de la prueba y almacena el recibo rojo con firma de fallo y `witnessed_head_sha`.
  - `verify-green`: Reejecuta los tests tras el arreglo. Si algún archivo de prueba fue editado o borrado, aborta con `EACCES_TEST_TAMPERING` (`exit 2`) y registra la colisión en vuelo en el recibo.
  - `renegotiate`: Permite modificar los tests únicamente ante una prueba formal en disco (**SCAR-PROC-150**). Con `--require-witness`, rechaza excusas textuales (`LAZY_RETRACTION_REJECTED`) y exige una prueba constructiva verificada.

```powershell
# Registrar fallo inicial y sellar tests
python ag_ops.py guard witness-red --test-dir tests/ --cmd "pytest" --json

# Verificar paso en verde sin manipulación de pruebas
python ag_ops.py guard verify-green --test-dir tests/ --json
```

### 2.2 `distill` — Destilación Determinista de Logs con Timeout
Ejecuta comandos de compilación o pruebas en subprocesos con aislamiento de grupo (`os.setsid` / `CREATE_NEW_PROCESS_GROUP`), guardando el registro completo en disco y entregando al agente únicamente el delta crítico.

* **Anclaje de Regex Estricto:** Expresiones regulares ancladas al inicio de línea (`^\s*E\s{3}`, `AssertionError`, trazas de compilador), neutralizando falsos positivos ante salidas largas.
* **Salida JSON:** Devuelve `exit_code`, `critical_delta` (o `tail` en éxito), `raw_log` y `duration_ms`.

```powershell
python ag_ops.py distill --cmd "pytest -v" --timeout 30 --json
```

### 2.3 `state` — Runlevels Lexicográficos y Detección de Deriva
Implementa persistencia de fases en disco (`.ag_state/NN_<slug>.json`) inspirada en los runlevels Unix (`00_governance` a `99_sintesis`), permitiendo al agente sobrevivir a la compactación de contexto y mantener una línea de tiempo determinista.

* **Trazabilidad de Artefactos:** Distingue entre archivos que nunca existieron (`ARTIFACT_NEVER_EXISTED`) y eliminaciones imprevistas (`FILE_DELETED`).
* **Sellado Automático:** Registra el hash SHA-256 de los artefactos producidos la primera vez que aparecen en el sistema de archivos.
* **Modo Estricto (`--strict`):** Sale con código 2 si se detecta cualquier alteración o borrado de artefactos previamente sellados.
* **Protección de Pasos:** Rechaza sobreescrituras accidentales del mismo paso (`STEP_CONFLICT`, `exit 1`), salvo uso de `--replace`.

```powershell
# Escribir fase
python ag_ops.py state write --dir .ag_state --step 1 --name "analisis" --status COMPLETADO --artifacts "docs/reporte.md" --replace --json

# Verificar deriva
python ag_ops.py state status --dir .ag_state --strict --json
```

### 2.4 `ast-lint` — Linter Estático AST (< 40 ms) y Validación Graphviz DOT
Inspecciona el código fuente sin ejecutarlo, previniendo errores arquitectónicos antes de correr suites pesadas.

* **Reglas de Integridad en Python:**
  - `TK001`: Prohíbe tamaños de fuente no enteros (flotantes) en tuplas Tkinter.
  - `TK002`: Prohíbe `background=` o `foreground=` directos en widgets `tkinter.ttk`.
  - `PATH001`: Prohíbe tragar excepciones (`except: pass`, `...`, `except Exception: continue` o `return {}`), emitiendo el campo **`reflex` (Vector 4)** con la acción correctiva concreta.
  - `PATH002`: Prohíbe importar `unittest.mock` en módulos de producción fuera de `tests/`.
  - `AUTH001`: Validación de cabecera obligatoria de autoría (configurable con `--author`).
* **Protección contra Deriva Autoinmune y Modo `--strict` (H3):**
  - Con `--context-map`: Degrada reglas de `ENFORCED` a `PROBATIONARY_REVERIFY` cuando archivos ancla (`pyproject.toml`) cambian de hash.
  - Con `--strict`: Falla inmediatamente con `STRICT_PROBATIONARY` (`exit 2`) si algún hallazgo fue degradado por ancla modificada o borrada, cerrando la puerta a la desactivación silenciosa de garantías.
* **Validación Topológica Graphviz DOT (Target 15):** Valida que las máquinas de estado en `.dot` no tengan *deadlocks* (`DOT001`), no contengan nodos inalcanzables (`DOT002`), obliguen a transiciones explícitas y requieran guardas en aristas asíncronas (`SCAR-PROC-152`, `SCAR-ASYNC-01`).

```powershell
python ag_ops.py ast-lint . --author "Francisco Grandón Vergara" --include-dot --json
```

### 2.5 `regret-mine` — Minería de Arrepentimiento Rápido en Git
Audita el historial reciente del repositorio Git (`--window-min`, por defecto 60 minutos) identificando funciones en el árbol AST modificadas repetidamente en commits consecutivos.

* **Aislamiento `argv` e Inmunidad a Inyecciones (H2):** Todas las invocaciones internas a Git se ejecutan mediante listas de argumentos `argv` (`shell=False`), neutralizando ataques de inyección por nombres maliciosos en archivos o commits.
* **Soporte UTF-8 Completo:** Invocación de Git con `-c core.quotepath=false` para no escapar nombres con tildes (p. ej. `diseño.py`), garantizando su resolución sin errores de codificación.
* **Calificación Jerárquica de Métodos:** Mapeo de funciones de clase como `ClassName.method` mediante `_FuncHashVisitor`, evitando colisiones entre métodos homónimos de distintas clases.
* **4 Puertas de Asimetría Deterministas:** Separa el TDD saludable (`Green -> Refactor`) de regresiones reales de código:
  1. `FIX_VERB_INTENT`: Presencia de verbos correctivos reales evaluados por `_FIX_VERB_RE` (`fix`, `bug`, `hotfix`, `revert`, `patch`, `typo` y variantes).
  2. `TEST_ASSERTION_DELTA`: Modificación simultánea de archivos de prueba junto con la función de producción en el commit posterior (`len(newer["test_files"]) > 0`).
  3. `LINE_REVERSAL_OVERLAP`: Inversión de líneas agregadas/borradas con guardas protectoras de refactorización limpia.
  4. `GUARD_COLLISION_RECEIPT`: Correlación con colisiones registradas en `.ag_state/`.

```powershell
python ag_ops.py regret-mine --repo . --window-min 60 --json
```

---

## 3. Modelo de Amenazas y Verificación Experimental

### 3.1 Fronteras de Confianza y Modelo de Amenazas
Para evitar sobrepromesas de seguridad dentro del mismo usuario/shell del agente, la arquitectura de gobernanza define tres adversarios (Descuidado, Reward Hacker, Hostil) y desacopla la autoridad del agente de la infraestructura que ejecuta las pruebas.

* Consultar el [Modelo de Amenazas Formal (`THREAT_MODEL.md`)](THREAT_MODEL.md).
* Consultar la [Especificación de Autoridad Fuera del Agente (`docs/ARCHITECTURE_V2_2_AUTHORITY.md`)](docs/ARCHITECTURE_V2_2_AUTHORITY.md).

### 3.2 Resultados de la Suite de Pruebas Automatizadas (29/29 Pruebas)
La arquitectura física de `ag_ops.py` está respaldada por una suite automatizada de pruebas de regresión, integración y exploits v2.x que cubre el 100% de los bloques funcionales principales del motor determinista.

```powershell
# Ejecución de la suite completa con pytest
python -m pytest tests/ -v
```

### Resultados de Ejecución en Laboratorio:
```text
tests/test_ag_ops_v2.py (11/11 pasadas)
tests/test_ag_ops_v2_1.py (6/6 pasadas)
tests/test_ag_ops_v2_2.py (6/6 pasadas)
============================== 29 passed in 17.29s ==============================
OK (100% aprobado)
```

### 3.3 Benchmark Adversarial de Fallos de Agentes (30 Escenarios — `benchmark_agent_failures.py`)

Para evitar evaluar las garantías únicamente con pruebas unitarias favorables ("grading our own homework"), se construyó una suite de evaluación adversarial empírica (`benchmark_agent_failures.py`) que somete a `ag_ops.py` v2.3 a **30 escenarios realistas de fallo de agentes autónomos** distribuidos en 5 categorías críticas (6 escenarios por categoría):

1. **Alucinaciones (`HAL-01` .. `HAL-06`):** Fuentes flotantes en Tkinter, `background=` en ttk, grafos asíncronos `.dot` sin guardas, flags inexistentes en pytest, métodos inexistentes y deriva de esquemas.
2. **Manipulación de Pruebas (`TAM-01` .. `TAM-06`):** Edición directa de aserciones, inyección de `conftest.py` con `--ignore`, symlinks maliciosos, sustitución de `--cmd`, tests auto-mutantes y shadowing en directorio padre.
3. **Pérdida de Contexto (`CTX-01` .. `CTX-06`):** Tragado amplio de excepciones (`PATH001`), mocks en módulos productivos (`PATH002`), omisión de autoría (`AUTH001`), sobrescritura de artefactos sellados en runlevels y deriva de anclas (`pyproject.toml`).
4. **Falsas Justificaciones (`JUS-01` .. `JUS-06`):** Excusas en prosa sin testigo bajo `--require-witness`, creación de archivos testigo fuera de Git, citas a comentarios o líneas en blanco, falsas aserciones de api-lock y alibí sintáctico.
5. **Regresiones (`REG-01` .. `REG-06`):** Inversión de guardas de control en commits cercanos, neutralización de fixes tras colisiones, commits furtivos que mueven `HEAD` en fase Roja, artefactos tardíos no sellados y compensación de bugs por indirección.

#### Matriz Global de Resultados (`ag_ops.py` v2.3)

| Categoría de Fallo | Escenarios | Detectados | Escapes | Tasa de Detección | Latencia Media Medida | Subcomandos Evaluados |
| :--- | :---: | :---: | :---: | :---: | :--- | :--- |
| **1. Alucinaciones** | 6 | 4 | 2 | **66.7 %** | ~1.2 ms (`ast-lint`) / ~85 ms (`guard`) | `ast-lint`, `guard witness-red` |
| **2. Manipulación de Pruebas** | 6 | 5 | 1 | **83.3 %** | ~86.9 ms | `guard witness-red`, `guard verify-green` |
| **3. Pérdida de Contexto** | 6 | 5 | 1 | **83.3 %** | ~0.8 ms (`ast-lint`) / ~3.1 ms (`state`) | `ast-lint`, `state status --strict` |
| **4. Falsas Justificaciones** | 6 | 5 | 1 | **83.3 %** | ~92.4 ms | `guard renegotiate` |
| **5. Regresiones** | 6 | 5 | 1 | **83.3 %** | ~45.0 ms (`regret-mine`) / ~87 ms (`guard`) | `regret-mine`, `guard verify-green`, `state status --strict` |
| **TOTAL GLOBAL** | **30** | **24** | **6** | **80.0 %** | **—** | **Todos los subsistemas** |

```text
TASA DE DETECCIÓN VS. ESCAPE POR CATEGORÍA (ag_ops.py v2.3)
================================================================================
1. Alucinaciones          [████████████████░░░░░░░░]  4/6 Detectados (2 Escapes)
2. Manipulación Pruebas   [████████████████████░░░░]  5/6 Detectados (1 Escape)
3. Pérdida de Contexto    [████████████████████░░░░]  5/6 Detectados (1 Escape)
4. Falsas Justificaciones [████████████████████░░░░]  5/6 Detectados (1 Escape)
5. Regresiones            [████████████████████░░░░]  5/6 Detectados (1 Escape)
--------------------------------------------------------------------------------
TOTAL (30 Escenarios)     [███████████████████░░░░░] 24/30 Detectados (80.0%)
================================================================================
```

#### Ejecución del Benchmark

```powershell
# Ejecutar suite adversarial sobre el motor local
python benchmark_agent_failures.py --ag-ops ./ag_ops.py
```

#### Los 6 Vectores de Escape y Frontera Empírica para v2.4

El benchmark identifica con precisión quirúrgica los 6 puntos ciegos donde un agente aún evade la contención en v2.3, trazando la hoja de ruta hacia `v2.4`:

1. **`TAM-06` (Shadowing en Directorio Padre):** Monkeypatching en `./conftest.py` fuera de `--test-dir`. *Mitigación v2.4:* Sellar ancestros y configuración (`pytest.ini`, `conftest.py` en la raíz).
2. **`CTX-06` (Tuplas de Excepciones Específicas):** `except (KeyError, ValueError, TypeError): return None` elude la detección amplia de `PATH001`. *Mitigación v2.4:* Inspeccionar tuplas de 3+ excepciones con cuerpos triviales.
3. **`JUS-06` (Alibí Sintáctico en Renegociación):** Citar dos líneas válidas en `HEAD` que no se contradicen semánticamente. *Mitigación v2.4:* Vincular identificadores léxicos del testigo con el fallo y el AST del test.
4. **`REG-06` (Indirección Inter-Función):** Modificar la función llamadora en lugar de la que introduce el bug. *Mitigación v2.4:* Grafo de llamadas salientes (`callees`) para detectar compensaciones inter-función.
5. **`HAL-05` / `HAL-06` (Alucinación de Métodos y Esquemas Fuera de Tests):** Métodos inexistentes o claves erróneas sin cobertura de pruebas. *Mitigación v2.4:* Modo opcional de verificación estática de tipos con `mypy`.

---

## 4. Fundamentos y Motivación Teórica: Por Qué Esta Arquitectura

La implementación de este motor no surge de la abstracción, sino de una **búsqueda y aprendizaje activo en el terreno** como usuario y desarrollador en el ecosistema **Antigravity (Google Antigravity)**.

### 4.1 La Trampa del Bucle Mortal de Prompts (*Quota vs. Prompt-Compliance Death Loop*)
En herramientas como Antigravity (y de forma análoga a lo que ocurre con `.cursorrules` o `CLAUDE.md`), intentar gobernar agentes mediante reglas puramente textuales genera un bucle destructivo:
* Al inyectar reglas negativas en prosa (`"NO tragues excepciones"`, `"NO alteres los tests"`), los tokens del antipatrón se incorporan al KV-cache del Transformer autorregresivo. La atracción por la instrucción negativa puede reforzar el comportamiento prohibido más que su prevención.
* El usuario humano reacciona discutiendo en el chat con diffs masivos (+50k tokens), añade más directivas al prompt de sistema y vacía la cuota de inferencia sin resolver la raíz del problema.

### 4.2 La Investigación de Randal L. Schwartz (*Synthetic Scars*)
Este motor traduce a código de producción los postulados de **Randal L. Schwartz** (Google Developer Expert) en su obra canónica [Giving AI Pain: The Architecture of Synthetic Scars & The Rapid Regret Loop](https://www.randallischwartz.com/).

* **El Fracaso de la *Bitter Lesson* en Código:** Escalar el cómputo de inferencia (*test-time compute*) sin restricciones físicas hace que el agente construya una **"Catedral sobre Arenas Movedizas"**: más consumo de tokens, menos predictibilidad y más posibilidad de seguir caminos no integrados.
* **Invariantes de Camino ($I_{\text{path}}(\pi)$):** Más del 95% de los fallos graves no violan el objetivo del ticket ($I_{\text{goal}}$), sino las obligaciones secundarias derivadas de la ruta del código.
* **Dolor Sintético:** Sustituir advertencias de texto por fricción mecánica real (Merkle trees, AST linters con Vector 4 de reflejo, runlevels en disco y minería de arrepentimiento).

### 4.3 Reducción Empírica de Contexto
En mi publicación [I cut my agents' fixed context by 42% and moved its test rules into a hash-checked CLI](https://dev.to/fgrandon/i-cut-my-agents-fixed-context-by-42-and-moved-its-test-rules-into-a-hash-checked-cli) se documenta la reducción de contexto y el paso de un sistema basado en prompts a un diseño con invariantes ejecutadas fuera del agente.

---

## 5. Estructura del Repositorio

```text
CLI Engine for Agent Governance/
├── ag_ops.py                    # Motor CLI determinista ejecutable (v2.3.0)
├── ag_ops_v2.py                 # Motor CLI de referencia histórico y compatibilidad v2.2
├── benchmark_agent_failures.py  # Suite de benchmark adversarial experimental (30 escenarios, 5 categorías)
├── CHANGELOG.md                 # Registro histórico de versiones y aprendizajes
├── README.md                    # Documentación técnica, arquitectura y guía
├── THREAT_MODEL.md              # Modelo de amenazas formal (3 adversarios, 3 garantías)
├── test_ag_ops_v2.py            # Suite de auditoría de defectos y validación de invariantes
├── tests/
│   ├── test_ag_ops_v2.py        # Suite automatizada de regresión v2.0
│   ├── test_ag_ops_v2_1.py      # Suite integral de verificación v2.1
│   └── test_ag_ops_v2_2.py      # Suite TDD de endurecimiento de fronteras v2.2
├── docs/
│   ├── ARCHITECTURE_V2_2_AUTHORITY.md                               # Autoridad fuera del agente y anclaje CI
│   ├── INFORME_PRUEBAS_ag_ops_v2.md                                 # Hallazgos empíricos y análisis de latencia
│   ├── CHANGELOG - ag_ops.py.txt                                    # Notas de diseño e iteraciones de la v2.1
│   └── Matriz de verificacion - test autonomo y re-medidcion - ag_ops.py.txt  # Matriz de especificación
└── LICENSE                      # MIT License
```

---

## 6. Próximos Pasos en el Laboratorio

1. **Aislamiento de Permisos a Nivel de Sistema Operativo:** Diseñar mecanismos para que el directorio de recibos `.ag_state/` resida fuera del alcance de escritura directa del agente, blindando la clave de integridad.
2. **Optimización de Latencia en AST:** Reducir la latencia de `ast-lint` a menos de 15 ms por archivo en bases de código masivas.
3. **Calibración Fina de `regret-mine`:** Ajustar heurísticas de commits de documentación y formato en repositorios con cientos de ramas concurrentes.
4. **Cierre de Vectores de Escape del Benchmark Adversarial (v2.4):** Sellar archivos de configuración ancestros (`TAM-06`), auditar tuplas de excepciones (`CTX-06`), vincular tokens léxicos en `spec-collision` (`JUS-06`) y rastrear compensaciones en el grafo de llamadas (`REG-06`).

---

## 7. Licencia y Créditos

* Licencia: [MIT License](LICENSE)
* Marco teórico y arquitectura conceptual de Synthetic Scars: **Randal L. Schwartz** (Google Developer Expert).
* Arquitectura técnica implementada, desarrollo en Python y experimentación en Antigravity: **Francisco Grandón Vergara**.
