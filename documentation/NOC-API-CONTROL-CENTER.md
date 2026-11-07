# API local del Control Center

Se añadió un router JSON bajo `/control-center` y se montó en el panel.

También existe una superficie HTML read-only bajo `/control-center/ui`, con
vistas de resumen, clientes, inventario y suscripciones. Esta pantalla sólo
lee los modelos del Control Plane; no crea clientes ni ejecuta jobs.

El acceso de lectura pasa por `control_center.repository`, cuya implementación
actual es SQLite. La API/UI no dependen del SQL directamente y podrán usar un
repositorio PostgreSQL cuando el Control Plane tenga almacenamiento propio.

Los contratos de proveedor están en `control_center.ports`: `DeploymentAdapter`
para cloud/infraestructura y `BillingAdapter` para facturación. Son interfaces
sin SDK ni red; las implementaciones se inyectarán en el worker persistente,
no en las rutas HTTP.

El primer worker es deliberadamente read-only: `AdapterRegistry` sólo resuelve
adapters configurados explícitamente y `ReadOnlyReconciliationWorker` acepta
`status`, `verify` y `reconcile`. Llama a `observe`, valida el
`ProviderObservation`, actualiza estado y `last_seen_at` del inventario y marca
el job de forma veraz. Los tipos mutantes se rechazan hasta implementar una
ruta separada de autorización, aprobación y ejecución.

`ReadOnlyReconciliationWorker.run_next()` ofrece además un tick de polling
determinista: procesa el job read-only encolado más antiguo e ignora jobs
mutantes. El supervisor, backoff, métricas y ciclo de vida del proceso siguen
siendo una integración posterior.

`HetznerDeploymentAdapter` es el primer adapter de observación: usa un
transporte HTTP inyectable, exige HTTPS y `provider_ref`, traduce el estado del
servidor a estados del inventario y rechaza operaciones mutantes. El recurso
del proveedor se identifica con `cc_deployments.provider_ref`, separado de
`tenant_id`; los adapters siguientes deben conservar esta misma separación.

`CloudflareTunnelDeploymentAdapter` aplica la misma regla al túnel de cada
cuenta: usa `account_id` y `provider_ref`, observa su estado mediante `GET` y
no crea, elimina ni modifica túneles.

- Las lecturas pasan por la sesión/RBAC existente.
- Los jobs reciben sólo `job_type`, `deployment_id`, `idempotency_key` y
  parámetros JSON estructurados.
- El router ignora headers de autenticación MFA enviados por el cliente.
  Hasta conectar SSO/MFA server-side, las mutaciones responden `403`.
- El router usa la base configurada por `HP_DB_PATH`; no contacta cloud,
  billing, Terraform, SSH ni Deployer.

```text
pytest -q tests/test_control_center_router.py
```
