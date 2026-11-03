<!-- Creado por Francisco Grandón Vergara -->

# Modelo de Amenazas y Fronteras de Confianza — `ag_ops` (v2.2)

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
   - *Mecanismo:* Invariantes matemáticos locales evaluados por `ag_ops.py` (árbol Merkle SHA-256 normalizado, matching estricto de comandos e ignores, validación AST en <40ms, aislamiento `argv` sin shell).
   - *Frontera:* Bloquea y registra de forma infalible errores accidentales y manipulaciones directas del código fuente o de los parámetros CLI del agente, siempre que el agente no altere el propio script `ag_ops.py` ni `.ag_state/`.
3. **Nivel 3 — Resistencia Criptográfica a Agente Hostil (Mismo Usuario / Shell):**
   - *Mecanismo:* Desacoplamiento de la autoridad de validación fuera de la máquina o proceso del agente.
   - *Frontera:* **El CI es la autoridad.** El pipeline de integración continua descarga una versión inmutable y confiable de `ag_ops.py` desde la rama base (`origin/main`) o fijada por hash SHA-256, verificando los testigos firmados contra el árbol git remoto. El agente local puede experimentar y recibir feedback rápido, pero no puede concederse a sí mismo la aprobación de fusión.

---

## 3. Matriz de Garantías por Módulo (`ag_ops` v2.2)

| Módulo | Garantía Actual (v2.2) | Nivel de Certeza | Lo que NO Garantiza Localmente |
| :--- | :--- | :---: | :--- |
| **`guard`** *(Merkle Lock)* | Sella hashes SHA-256 de tests; detecta alteración de pruebas antes y durante `verify-green`; bloquea comandos e `--ignore` discrepantes (`IGNORE_PATTERN_MISMATCH`); rechaza symlinks. | **Nivel 2** | No impide que el agente borre el recibo en `.ag_state/` o modifique el binario de python/pytest en su entorno local. |
| **`distill`** *(Log Distillation)* | Aislamiento de grupo de procesos (`CREATE_NEW_PROCESS_GROUP` / `start_new_session`), timeout estricto con `taskkill` / `SIGKILL`, filtro de delta crítico anclado en regex. | **Nivel 2** | No previene que un comando malicioso del agente intente saturar disco antes del timeout o cierre pipes heredados. |
| **`state`** *(Lexical Runlevels)* | Persistencia atómica de estados numerados, verificación de existencia y hashes SHA-256 de artefactos entregables, detección de deriva. | **Nivel 2** | No impide que el agente reescriba archivos con `--replace` sin registrar la auditoría si el agente no consulta `status --strict`. |
| **`ast-lint`** *(Static & DOT Lint)* | Validación sintáctica AST de TK001/TK002, AUTH001, PATH002; detección ampliada de swallowed exceptions en PATH001 (`pass`, `continue`, `return {}`); modo `--strict` contra anclas modificadas. | **Nivel 2** | No evalúa tipado dinámico en runtime ni garantiza corrección lógica más allá del análisis sintáctico estático. |
| **`regret-mine`** *(Rapid-Regret)* | Minería Git sobre commits recientes con `argv` puro (sin shell injection), soporte para nombres con tildes (`core.quotepath=false`), calificación `ClassName.method`, 4 filtros de asimetría. | **Nivel 2** | No garantiza que el agente no intente hacer un `git commit --amend` o reescribir la historia local antes de la minería. |

---

## 4. Conclusión de Diseño: La Doble Frontera

La promesa de `ag_ops` no es crear una "jaula inquebrantable" dentro de un shell de usuario sin permisos restringidos, sino proporcionar un **motor de instrumentación determinista de fricción cero** para el agente en local (Nivel 2), respaldado por una **política de confianza cero en el CI** (Nivel 3). Todo intento de evasión en local queda documentado en los recibos criptográficos que el CI audita obligatoriamente antes de autorizar cualquier despliegue.
