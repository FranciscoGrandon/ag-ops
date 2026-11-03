<!-- Creado por Francisco Grandón Vergara -->

# Arquitectura de Gobernanza Desacoplada: Autoridad Fuera del Agente (v2.2)

> **Documento de Diseño Técnico & Especificación de Fronteras de Confianza**  
> *Versión 2.2 — CLI Engine for Agent Governance (`ag_ops`)*

---

## 1. El Problema Fundamental: La Trampa del Verificador Autoinvestido

En entornos de ejecución de agentes autónomos de codificación (Antigravity, Cursor, Devin, Claude Code), el agente opera usualmente dentro del shell del desarrollador con el mismo Identificador de Usuario (UID) y permisos sobre el sistema de archivos.

```
       [ENTORNO LOCAL COMPARTIDO - MISMO PRIVILEGIO / UID]
       +-------------------------------------------------+
       |                                                 |
       |   +-------------------+    (Escritura Libre)    |
       |   |      AGENTE       | ----------------------> | Código de Producción
       |   +-------------------+                         |
       |             |                                   |
       |             | (Invocación)                      |
       |             v                                   |
       |   +-------------------+    (Escritura Libre)    |
       |   |     ag_ops.py     | <---------------------- | Modificación / Evasión
       |   +-------------------+                         | del Verificador
       |             |                                   |
       |             v                                   |
       |   +-------------------+    (Escritura Libre)    |
       |   |    .ag_state/     | <---------------------- | Falsificación de Recibos
       |   +-------------------+                         |
       +-------------------------------------------------+
```

### La Falacia de la "Jaula Local"
Cualquier verificación ejecutada por el agente contra un script local que el propio agente puede editar o cuyos artefactos puede manipular carece de **frontera criptográfica de confianza cero**. Un agente con reward hacking avanzado o bajo inyección de prompt hostil puede simplemente reemplazar `ag_ops.py` por:

```python
# Exploit de evasión trivial por auto-verificación
import sys
print('{"ok": true, "status": "VERIFIED_GREEN_WITH_MERKLE_LOCK"}')
sys.exit(0)
```

Por tanto:
> **Postulado Arquitectónico v2.2:**  
> La capa local de `ag_ops` opera como **instrumentación de alta frecuencia y detector de desviaciones (Nivel 2)**.  
> La **Autoridad de Aprobación y Fusión (Nivel 3)** reside exclusivamente **fuera del agente**, en el motor de Integración Continua (CI).

---

## 2. Modelo en Dos Capas (Two-Tier Trust Model)

```mermaid
flowchart TD
    subgraph Tier1["Capa 1: Bucle Local de Alta Frecuencia (Agente / Dev)"]
        Agent["Agente Autónomo"] -->|1. Test Rojo| GuardRed["ag_ops guard witness-red"]
        GuardRed -->|2. Sella Hash & Anchor| ReceiptLocal[".ag_state/merkle_guard_*.json"]
        Agent -->|3. Corrige Código| ProdCode["src/ producción"]
        Agent -->|4. Test Verde| GuardGreen["ag_ops guard verify-green"]
        ReceiptLocal -->|Verifica Merkle Lock| GuardGreen
        GuardGreen -->|5. Recibo Sellado| GitCommit["git commit + push"]
    end

    subgraph Tier2["Capa 2: Autoridad Remota Inmutable (Pipeline CI / GitHub Actions)"]
        GitCommit -->|Trigger PR / Push| CI["Runner de CI Aislado"]
        OriginMain["origin/main (Rama Base)"] -->|Checkout ag_ops.py Confiable| CI
        CI -->|Audit 1: Integridad de Cadena| ChainVerify["Validación Criptográfica prev_hash"]
        CI -->|Audit 2: Anchor Commit| AnchorVerify["Verificación anchor_commit_sha en main"]
        CI -->|Audit 3: Re-ejecución Determinista| ReplayVerify["Re-ejecución Limpia de Tests"]
        ChainVerify --> GateKeeper{"¿Gobernanza Cumplida?"}
        AnchorVerify --> GateKeeper
        ReplayVerify --> GateKeeper
        GateKeeper -->|SÍ (Exit 0)| MergeApproved["Merge Autorizado"]
        GateKeeper -->|NO (Exit != 0)| MergeBlocked["VETO / PR Rechazado"]
    end
```

### Tabla Comparativa de Responsabilidades

| Dimensión | Capa 1: Local (Agente) | Capa 2: Remoto (CI) |
| :--- | :--- | :--- |
| **Rol** | Feedback rápido y generación de evidencia. | Árbitro judicial inmutable de confianza cero. |
| **Latencia** | < 40 ms para AST, < 5 s para Merkle lock. | 30 s – 2 min en runner de integración. |
| **Confiabilidad** | Vulnerable si el agente es hostil. | **Inviolable** (aislado en contenedor efímero). |
| **Garantía** | Detecta descuidos, fallas y reward hacking común. | Previene fusiones no autorizadas y RCE. |
| **Artefactos** | Recibos en `.ag_state/` y runlevels `NN_*.json`. | Logs firmados, Checks de GitHub y Releases. |

---

## 3. Anclaje de Testigos a la Rama Base (`anchor_commit_sha`)

Para evitar que un agente genere un "rojo fabricado" (creando un bug que no existía y resolviéndolo inmediatamente para simular TDD), `ag_ops` v2.2 incorpora el anclaje criptográfico a la rama base:

1. **Captura en `witness-red`:**
   Al ejecutarse `guard witness-red`, `ag_ops` consulta el commit base común con la rama principal:
   ```bash
   anchor_commit_sha = git merge-base HEAD origin/main
   ```
   Este SHA-1/SHA-256 se graba de forma inmutable en el recibo:
   ```json
   {
     "test_target": "tests/test_calc.py",
     "tree_hash": "a1b2c3d4...",
     "witnessed_cmd": "pytest tests/test_calc.py",
     "anchor_commit_sha": "7f8e3d2a1b4c...",
     "anchor_branch": "origin/main"
   }
   ```
2. **Validación en CI:**
   El CI comprueba que `anchor_commit_sha` pertenezca efectivamente a la historia de `origin/main` y que la suite de pruebas fallara legítimamente contra ese estado del árbol git.

---

## 4. La Regla Crítica: Cómo el CI Obtiene un `ag_ops.py` Confiable

> [!CRITICAL]
> **Regla Inquebrantable de Seguridad de CI:**  
> El job de CI **NUNCA** debe ejecutar el `ag_ops.py` proveniente de la rama del agente (`head_ref` o rama del PR). Si lo hace, el agente puede manipular el verificador. El runner debe obtener el ejecutable únicamente de una fuente canónica inmutable.

Se definen tres estrategias formales para implementar esta regla en CI:

### Estrategia A: Extracción Dinámica desde la Rama Base (`origin/main`) *(Recomendada)*
Es la estrategia más flexible para repositorios estándar. En el flujo de trabajo del CI se descarga la rama de trabajo del PR, pero se extrae el ejecutable `ag_ops.py` directamente desde `origin/main`:

```yaml
# .github/workflows/agent_governance_gate.yml
name: Agent Governance Gatekeeper

on:
  pull_request:
    branches: [ main ]

jobs:
  verify-governance:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout PR Branch
        uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Historial completo para validar anchor_commit_sha

      - name: Extraer ag_ops.py Confiable desde Rama Base
        run: |
          # Extraer la versión inmutable de ag_ops.py de la rama destino (main)
          git show origin/main:ag_ops_v2.py > /tmp/trusted_ag_ops.py
          chmod +x /tmp/trusted_ag_ops.py
          echo "Trusted ag_ops SHA-256:"
          sha256sum /tmp/trusted_ag_ops.py

      - name: Validar Linter AST con Verificador Confiable
        run: |
          python /tmp/trusted_ag_ops.py ast-lint . --strict --json

      - name: Validar Recibos Merkle y Cadena Criptográfica
        run: |
          python /tmp/trusted_ag_ops.py guard verify-green --test-dir tests/ --json
```

### Estrategia B: Pinning Criptográfico por Hash SHA-256 en CI
Para repositorios de alta seguridad donde la rama `main` también puede ser objeto de cambios de versión controlados:
1. El workflow de CI declara una constante de integridad inmutable:
   ```yaml
   env:
     CANONICAL_AG_OPS_SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
   ```
2. El runner valida el hash antes de cualquier invocación:
   ```bash
   ACTUAL_HASH=$(sha256sum ag_ops_v2.py | cut -d' ' -f1)
   if [ "$ACTUAL_HASH" != "$CANONICAL_AG_OPS_SHA256" ]; then
     echo "SECURITY ALERT: ag_ops_v2.py has been tampered with or drifted without canonical release."
     exit 2
   fi
   ```

### Estrategia C: Acción GitHub o Contenedor OCI Firmado
Empaquetar `ag_ops` como una GitHub Action oficial fijada por commit SHA (`uses: antigravity/ag-ops-action@<commit_sha>`) o una imagen de contenedor en GitHub Container Registry (`ghcr.io`) firmada criptográficamente con Sigstore Cosign.

---

## 5. Cadena Criptográfica de Hashes (`prev_hash` Merkle Chain)

Para evitar que un agente utilice `--replace` o regenere recibos de forma silenciosa para borrar colisiones previas, `ag_ops` v2.2 implementa una **cadena secuencial de auditoría**:

### Estructura de Recibo con Cadena
Cada archivo emitido en `.ag_state/` incluye un bloque de integridad encadenada:

```json
{
  "version": 2,
  "sequence_index": 4,
  "timestamp_utc": "2026-11-02T20:15:00Z",
  "prev_artifact_hash": "8f3b4c1e...",
  "target": "tests/test_core.py",
  "tree_hash": "a9d4f2...",
  "status": "VERIFIED_GREEN_WITH_MERKLE_LOCK",
  "collisions": []
}
```

### Verificación de Continuidad
Si el agente ejecuta `state write --replace` o intenta alterar un recibo previo:
1. El `prev_artifact_hash` del estado siguiente diverge del hash real del archivo en disco.
2. El comando `state status --strict` y el validador del CI reportan `CHAIN_TAMPER_DETECTED (exit 2)`.
3. Cualquier reintento o sustitución de artefactos queda registrado como un nuevo bloque con timestamp auditable, impidiendo borrar huellas de colisiones.

---

## 6. Aislamiento Local Opcional (Defensa en Profundidad)

Para desarrolladores que desean endurecer aún más su estación de trabajo local frente a agentes autónomos:

1. **Permisos NTFS en Windows:**
   - Asignar a la carpeta `.ag_state/` permisos de solo lectura para el proceso del agente tras el `witness-red` mediante ACLs de Windows (`icacls .ag_state /deny %USERNAME%:(W)`).
2. **Entorno WSL / Docker Sandbox:**
   - Montar el código fuente en un contenedor donde el usuario del contenedor no tiene acceso de escritura a `/usr/local/bin/ag_ops` ni a un volumen de auditoría montado en modo `ro`.

---

## 7. Hoja de Ruta de Implementación de Autoridad

| Fase | Hito Técnico | Estado |
| :--- | :--- | :---: |
| **Fase 1** | Aislamiento `argv`, bloqueo `--ignore`, calificación de métodos, symlink check en `ag_ops_v2.py`. | **Completado (v2.2)** |
| **Fase 2** | Especificación del Modelo de Amenazas y Arquitectura de Autoridad en CI. | **Completado (v2.2)** |
| **Fase 3** | Incorporación formal de `anchor_commit_sha` y `prev_artifact_hash` en el esquema de recibos JSON. | Programado (v2.3) |
| **Fase 4** | Workflow de referencia GitHub Action (`.github/workflows/agent_governance_gate.yml`). | Programado (v2.3) |
