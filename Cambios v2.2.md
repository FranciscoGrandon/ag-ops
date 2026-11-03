### \#\#\# Defectos reproducidos y corregidos en ag\_ops\_v2.py

\| \# \| Subcomando / Función \| Defecto reproducido (antes) \| Corrección implementada (ahora) \| Prueba en test\_ag\_ops\_v2.py \|  
\|---\|---\|---\|---\|---\|  
\| 1 \| guard (\_compute\_merkle\_tree) \| Si \--state-dir es directorio ancestro de \--test-dir (ej. \--state-dir /tmp/x \--test-dir /tmp/x/tests), la condición resolved\_state in fpath.parents excluía todos los archivos de prueba y devolvía EMPTY\_TEST\_TARGET (rc=1). \| Solo excluye resolved\_state cuando está anidado dentro de test\_dir (test\_dir in resolved\_state.parents), manteniendo siempre la exclusión exacta de resolved\_receipt. \| test\_01\_guard\_ancestor\_state\_dir \|  
\| 2 \| guard \+ regret-mine (\_load\_receipt\_collision\_timestamps) \| guard renegotiate guardaba en renegotiation\_history únicamente old\_data\["timestamp\_utc"\] (instante del witness-red original previo al primer commit) y \_load\_receipt\_collision\_timestamps ignoraba data\["timestamp\_utc"\] cuando status \== "RENEGOTIATED\_RED", omitiendo la señal GUARD\_COLLISION\_RECEIPT (regret\_pairs\_count: 0). \| Registra "renegotiated\_at" (y preserva "constructive\_witness") en renegotiation\_history, e indexa tanto renegotiated\_at como timestamp\_utc de recibos renegociados. \| test\_02\_renegotiate\_timestamp\_correlated\_in\_regret\_mine \|  
\| 3 \| ast-lint (\_check\_import\_from) \| from unittest import mock en módulos de producción no disparaba PATH002 (node.module \== "unittest" no se evaluaba), y from tkinter.ttk import Style registraba Style como widget ttk, disparando falso positivo TK002 en Style(bg='red'). \| Evalúa node.module \== "unittest" con alias mock para PATH002 y restringe self.ttk\_direct\_imports exclusivamente a nombres presentes en \_TTK\_WIDGETS. \| test\_03\_ast\_lint\_from\_unittest\_import\_mock\_and\_ttk\_style \|  
\| 4 \| distill (\_cmd\_distill) \| (stdout\_txt \+ "\\n" \+ stderr\_txt).splitlines() inyectaba una línea vacía sintética (total\_lines: 9 para 8 líneas) y truncaba las líneas 0..first\_err-3 incluso cuando total\_lines \<= max\_lines (distilled\_lines: 6 con \--max-lines 35). \| Concatena stdout\_txt.splitlines() \+ stderr\_txt.splitlines(), conserva all\_lines íntegro si total\_lines \<= max\_lines y ajusta la ventana final si no hay poda intermedia. \| test\_04\_distill\_preserves\_all\_lines\_when\_under\_max\_lines \|  
\| 5 \| ast-lint (\_lint\_dot\_state\_machine) \| No limpiaba comentarios (/\* ... \*/, //, \#), ignoraba el segundo tramo en transiciones encadenadas (Init \-\> Fetching \-\> Done;) reportando falso DOT001 sobre Fetching, y fijaba "line": 1 en todas las violaciones. \| Elimina comentarios preservando saltos de línea, descompone cadenas A \-\> B \-\> C y reporta el número de línea real de cada estado y transición. \| test\_05\_dot\_linter\_chained\_edges\_comments\_and\_line\_numbers \|  
\| 6 \| guard (\_validate\_file\_line\_ref) \| max(1, total\_lines) evaluaba 1 en archivos vacíos de 0 bytes (total\_lines \== 0), aceptando empty.py:1 como ancla en \--witness-type spec-collision (rc=0). \| Rechaza explícitamente archivos con total\_lines \== 0 devolviendo Referenced file is empty (0 lines). \| test\_06\_and\_07\_constructive\_witness\_validation \|  
\| 7 \| guard (\_verify\_constructive\_witness) \| \--witness-type arch-fork aceptaba opciones con etiqueta vacía (@spec.py:1) o anclas/etiquetas duplicadas (OptA@spec.py:1\|OptB@spec.py:1). \| Exige etiquetas no vacías, etiquetas únicas y anclas file:line distintas entre las opciones de arch-fork. \| test\_06\_and\_07\_constructive\_witness\_validation \|  
\| 8 \| guard (\_cmd\_guard) \| La segunda llamada a \_compute\_merkle\_tree tras ejecutar \--cmd en witness-red y renegotiate no capturaba (ValueError, OSError); si \--cmd creaba un symlink en test\_dir, el proceso abortaba con Traceback sin emitir JSON. \| Captura (ValueError, OSError) en el cálculo post-ejecución y emite JSON estructurado con error SELF\_MUTATING\_TEST\_DIR (rc=1). \| test\_08\_symlink\_created\_during\_witness\_red\_returns\_clean\_json \|  
\| 9 \| guard (\_sha256\_file) \| \_compute\_merkle\_tree ejecutaba normalize\_eol=True sobre todos los archivos sin distinguir binarios, reemplazando \\r\\n por \\n dentro de archivos binarios con bytes NUL (\\x00) e impidiendo detectar corrupción binaria en verify-green. \| Con normalize\_eol=True, solo normaliza \\r\\n a \\n cuando el contenido no contiene bytes NUL (b"\\x00"). \| test\_09\_binary\_file\_crlf\_tampering\_detected \|  
\| 10 \| state (\_cmd\_state) \| state write \--step 5 solo buscaba conflictos con 05\_\*.json ignorando 005\_\*.json (que state status sí agrupa como paso 5), y si un artefacto pasaba a ser directorio lanzaba IsADirectoryError marcando el JSON de estado como CORRUPTED\_STATE\_FILE. \| Detecta conflictos comparando int(m.group(1)) \== step\_num sobre \_STEP\_FILE\_RE y verifica art\_path.is\_file() antes de hashear en state status. \| test\_10\_state\_conflict\_across\_zero\_padding\_and\_dir\_artifact \|  
\| 11 \| regret-mine (\_cmd\_regret\_mine) \| Si git log contenía timestamps no monotónicos (newer\["ts"\] \< older\["ts"\] por rebase o desfase de reloj), delta\_sec era negativo, cumplía delta\_sec \<= window\_sec y emparejaba commits separados por días con delta\_minutes negativo. \| Verifica abs(delta\_sec) \<= window\_sec y calcula delta\_minutes sobre abs(delta\_sec). \| test\_11\_regret\_mine\_non\_monotonic\_commit\_timestamps \|  
\| 12 \| Transversal (\_atomic\_write\_json) \| os.fsync(f.fileno()) lanzaba OSError: \[Errno 95\] Operation not supported (ENOTSUP) al escribir recibos o estados sobre montajes virtuales/FUSE. \| Captura OSError en os.fsync únicamente para EINVAL, ENOTSUP y EOPNOTSUPP, propagando cualquier otro error de E/S. \| test\_12\_atomic\_write\_json\_on\_fuse\_mount\_without\_fsync\_support \|

### \#\#\# Evidencia de verificación ejecutada

1\. \*\*Ciclo \`guard witness-red\` (contra el archivo original sin parches) y \`guard verify-green\` (contra el archivo corregido):\*\*  
   \- Comando ejecutado:

```sh
python3 ag_ops_v2.py guard witness-red \
  --test-dir test_ag_ops_v2.py \
  --state-dir .ag_state \
  --cmd "AG_OPS_TARGET=./ag_ops_v2.py python3 test_ag_ops_v2.py -v" \
  --json
```

   \- Salida (\`witness-red\` sobre el archivo original, \`rc=0\`):

```json
{
  "ok": true,
  "status": "WITNESSED_RED",
  "tree_hash": "16d5a26e44f3e544d0edb75b30e6c464a3cdbc43ff793b63c3c7aabde464a621",
  "red_exit_code": 1,
  "files_count": 1
}
```

   \- Salida (\`verify-green\` tras aplicar las correcciones en \`ag\_ops\_v2.py\`, \`rc=0\`):

```json
{
  "ok": true,
  "status": "VERIFIED_GREEN_WITH_MERKLE_LOCK",
  "tree_hash": "16d5a26e44f3e544d0edb75b30e6c464a3cdbc43ff793b63c3c7aabde464a621",
  "elapsed_ms": 12875.47,
  "collisions_count": 0
}
```

2\. \*\*Ejecución directa de la suite \`test\_ag\_ops\_v2.py\`:\*\*  
   \- Comando ejecutado: \`python3 test\_ag\_ops\_v2.py \-v\`  
   \- Salida (\`rc=0\`): \`Ran 11 tests in 12.787s — OK\` (\`test\_01\` a \`test\_12\`, con \`test\_06\_and\_07\` agrupados en un método).  
3\. \*\*Auto-verificación estática (\`ast-lint\`) sobre ambos archivos entregados:\*\*  
   \- Comando ejecutado: \`python3 ag\_ops\_v2.py ast-lint . \--author "Francisco Grandón Vergara" \--json\`

```json
{
  "ok": true,
  "elapsed_ms": 107.153,
  "files_checked": 2,
  "violations_count": 0,
  "violations": []
}
```

### \#\#\# Componentes declarados NO VERIFICADO

\- \*\*Ramas exclusivas de Windows (\`os.name \== "nt"\`):\*\* \`NO VERIFICADO\`. La sesión se ejecuta sobre Linux (\`posix\`), por lo que no es posible ejecutar en tiempo real la creación de grupos de procesos con \`subprocess.CREATE\_NEW\_PROCESS\_GROUP\`, la terminación de árbol vía \`taskkill /F /T /PID\`, la detección de puntos de unión NTFS mediante \`pathlib.Path.is\_junction()\` ni la resolución de rutas candidatas \`D:\\GIT\\...\` / \`C:\\Program Files\\Git\\cmd\\git.exe\`.