<!-- Creado por Francisco Grandón Vergara -->

# Modelo de Amenazas y Fronteras de Confianza — `ag_ops` (v2.4)

> **Principio Rector:** *"100% determinista"* describe el motor sintáctico y el árbol de hashes Merkle, **no** la garantía física de seguridad del entorno. Todo verificador que ejecute dentro del mismo dominio de privilegios (mismo usuario/shell) que el agente evaluado carece de frontera criptográfica local absoluta. La gobernanza real se estructura en dos capas: **detección temprana local** y **autoridad inmutable remota (CI)**.

---

## 1. Definición de los Tres Adversarios

| Adversario | Perfil y Motivación | Vector Típico de Comportamiento | Impacto en el Repositorio |
| :--- | :--- | :--- | :--- |
| **1. El Agente Descuidado** *(Careless)* | Sin intención maliciosa; fatiga de contexto, alucinaciones, prisa por cerrar turnos o respuestas incompletas. | Borrado accidental de tests, omisión de encabezados de autoría, swallowed exceptions (`except: pass`), comandos de prueba rotos. | Regresión silenciosa de código, pérdida de trazabilidad, deuda técnica no intencional. |
| **2. El Optimizador hacia el Verde** *(Reward Hacker)* | Optimiza estrictamente para satisfacer la métrica de éxito o prompt (exit code 0 / "tests passing"). | Añade `--ignore conftest.py` post-rojo, debilita aserciones en tests existentes, muta fixtures en tiempo de ejecución, falsifica anclas de contexto. | Falsos positivos de calidad; pruebas "verdes" que no validan la funcionalidad real requerida. |
| **3. El Agente con Inyección de Prompt** *(Hostile / Prompt-Injected)* | Controlado o inducido por datos no confiables (issues, PRs, contenidos externos leídos en la web). | Inyección de comandos en shell (`a$(touch PWNED).py`), manipulación de archivos del verificador (`ag_ops.py`), borrado de logs/recibos en `.ag_state/`. | Ejecución arbitraria de código (RCE), evasión total del harness de gobernanza, alteración de artefactos de auditoría. |

---

## 2. Los Tres Niveles de Garantía de Seguridad

1. **Nivel 1 — Convención / Protocolo Voluntario:**
   - *Mecanismo:* Guías y reglas de comportamiento del agente (p. ej., orquestación en markdown).
   - *Frontera:* Cero resistencia física. Si el agente ignora el comando o no lo invoca, la regla no se aplica.
2. **Nivel 2 — Detección Determinista de Accidentes y Reward Hacking Local:**
   - *Mecanismo:* Invariantes matemáticos locales evaluados por `ag_ops.py` (árbol Merkle SHA-256 normalizado, matching estricto de comandos e ignores, validación AST en milisegundos, aislamiento `argv` sin shell).
   - *Frontera:* Bloquea y registra de forma determinista errores accidentales y manipulaciones directas del código fuente, de la configuración raíz de pruebas o de los parámetros CLI del agente (con los 5 vectores de escape empíricos restantes documentados en el benchmark adversarial de 36 escenarios: `HAL-05`, `HAL-06`, `CTX-06`, `JUS-06` y `REG-06`), siempre que el agente no altere el propio script `ag_ops.py` ni `.ag_state/`.
3. **Nivel 3 — Resistencia Criptográfica a Agente Hostil (Mismo Usuario / Shell):**
   - *Mecanismo:* Desacoplamiento de la autoridad de validación fuera de la máquina o proceso del agente.
   - *Frontera:* **El CI es la autoridad.** El pipeline de integración continua descarga una versión inmutable y confiable de `ag_ops.py` desde la rama base (`origin/main`) o fijada por hash SHA-256, verificando los testigos firmados contra el árbol git remoto. El agente local puede experimentar y recibir feedback rápido, pero no puede concederse a sí mismo la aprobación de fusión.

---

## 3. Matriz de Garantías por Módulo (`ag_ops` v2.4)

| Módulo | Garantía Actual (v2.4) | Nivel de Certeza | Lo que NO Garantiza Localmente |
| :--- | :--- | :---: | :--- |
| **`guard`** *(Merkle Lock & Scope)* | Sella hashes SHA-256 de tests más `root_config_manifest` (`conftest.py`, `pytest.ini`, `pyproject.toml`, `setup.cfg`, `tox.ini`, `sitecustomize.py`, `usercustomize.py`); bloquea `addopts` evasivos (`UNSAFE_PYTEST_ADDOPTS`), sanitiza `PYTEST_ADDOPTS`/`PYTHONSTARTUP` (`ENV_TAINT_DETECTED`), verifica ejecución efectiva (`ZERO_TESTS_EXECUTED`, `TEST_COUNT_REGRESSION`), ancla historia con `--base-ref`/`merge-base` (`SPEC_MODIFIED_SINCE_BASE`), detecta ciclos `k` (`OSCILLATION_CYCLE_DETECTED`), separa alcance vía `check-scope` (`MIXED_SCOPE_VIOLATION`) y soporta renegociación atómica `renegotiate --batch`. | **Nivel 2** | No impide que el agente con mismo UID borre o reemplace `.ag_state/` o el propio `ag_ops.py` en local, ni valida validez semántica no contradictoria en `JUS-06`. Estos controles exigen verificación remota en CI (Nivel 3). |
| **`distill`** *(Log Distillation)* | Aislamiento de grupo de procesos (`CREATE_NEW_PROCESS_GROUP` / `start_new_session`), timeout estricto con `taskkill` / `SIGKILL`, filtro de delta crítico anclado en regex. | **Nivel 2** | No previene que un comando malicioso del agente intente saturar disco antes del timeout o cierre pipes heredados. |
| **`state`** *(Lexical Runlevels)* | Persistencia atómica de estados numerados, verificación de existencia y hashes SHA-256 de artefactos entregables, detección de deriva y detección de oscilaciones `k`-ciclo mediante `.ag_state/oscillation_history.json` (`OSCILLATION_CYCLE_DETECTED`). | **Nivel 2** | No impide que un agente con mismo UID edite manualmente `.ag_state/NN_*.json` u `oscillation_history.json` si no existe custodia externa en CI. |
| **`ast-lint`** *(Static & DOT Lint)* | Validación en un único recorrido (`SinglePassVisitor`) de `TK001`, `TK002`, `AUTH001`, `PATH001`, `PATH002`, grafos `.dot` y mutaciones ocultas `MUT001` (advertencia por defecto, bloqueante en `--strict`, con supresión auditable); caché incremental `stat_cache.json` deshabilitada en `--strict` y ante retroceso de reloj. | **Nivel 2** | `MUT001` es un sensor sintáctico por prefijo de método y `PATH001` no bloquea tuplas acotadas de excepciones concretas (`CTX-06`); tampoco reemplaza tipado dinámico (`HAL-05`, `HAL-06`). |
| **`regret-mine`** *(Rapid-Regret)* | Minería Git por lotes (`GitBatchReader` + `git log --no-walk --stdin`) con `argv` puro (sin shell injection), soporte UTF-8 (`core.quotepath=false`), calificación `ClassName.method`, scrubber AST sin `ast.unparse` y 4 puertas de asimetría. | **Nivel 2** | No detecta compensación de regresiones mediante indirección entre funciones distintas (`REG-06`) ni impide reescrituras locales destructivas previas a un push bloqueado por CI. |

---

## 4. Conclusión de Diseño: La Doble Frontera

La promesa de `ag_ops` no es crear una "jaula inquebrantable" dentro de un shell de usuario sin permisos restringidos, sino proporcionar un **motor de instrumentación determinista de fricción cero** para el agente en local (Nivel 2), respaldado por una **política de confianza cero en el CI** (Nivel 3). Todo intento de evasión en local queda documentado en los recibos criptográficos que el CI audita obligatoriamente antes de autorizar cualquier despliegue.
