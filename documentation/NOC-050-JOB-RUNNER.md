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
- La migración `20261107_04_control_center_worker_leases` añade tokens de
  lease, heartbeat, contador y límite de intentos.
- `ReadOnlyReconciliationWorker.run_next()` y `run_forever()` procesan sólo
  `status`/`verify`/`reconcile`; un fallo temporal vuelve a `queued` hasta
  agotar el presupuesto configurado.

## Pospuesto

La supervisión de proceso, métricas, backoff avanzado, cola distribuida entre
hosts y la ejecución contra Deployer/VPS se validarán después del despliegue de
infraestructura. Esta etapa prueba leases y reintentos sobre SQLite temporal;
no hace llamadas de red ni mutaciones de infraestructura.

```text
pytest -q tests/test_control_center_jobs.py
```
