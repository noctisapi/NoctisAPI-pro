# NOC-050 — Runner seguro de jobs operativos

## Alcance implementado

- Acciones allow-listed: `deploy`, `status`, `verify`, `upgrade`, `backup`,
  `suspend`, `teardown` y `reconcile`.
- Cada job tiene ID, clave de idempotencia, parámetros JSON, actor, progreso,
  timestamps y estado terminal.
- Un deployment queda bloqueado mientras tenga una operación mutante queued o
  running; `status`/`verify` pueden coexistir entre sí.
- El runner sólo invoca handlers registrados por código. No acepta ni ejecuta
  comandos shell provenientes de HTTP.
- Las excepciones del handler producen `failed`, nunca `succeeded`.

## Pospuesto

La cola distribuida, worker persistente, locking entre procesos/hosts y la
ejecución contra Deployer/VPS se validarán después del despliegue de
infraestructura. Esta etapa prueba únicamente la máquina de estados y sus
invariantes sobre SQLite temporal.

```text
pytest -q tests/test_control_center_jobs.py
```
