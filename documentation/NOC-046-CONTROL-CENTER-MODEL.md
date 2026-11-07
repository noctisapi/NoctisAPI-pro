# NOC-046 — Modelo del Control Center

## Alcance implementado

Se añadió una migración versionada (`20261106_01_control_center`) con tablas
aisladas bajo el prefijo `cc_`:

- `cc_customers` y `cc_subscriptions`: relación comercial y estado de cuenta.
- `cc_deployments` y `cc_domains`: inventario de instalaciones y endpoints.
- `cc_jobs`: operaciones tipadas, idempotencia, progreso y errores.
- `cc_versions`: catálogo de versiones publicables.
- `cc_infra_costs`: estimaciones por instalación y periodo.
- `cc_audit_log`: trazabilidad de acciones del operador.

El modelo no incorpora credenciales, contraseñas, tokens, tarjetas, tráfico de
honeypot, sesiones del panel ni eventos de ataque. Esos datos permanecen en
sus contextos existentes o en sus gestores de secretos.

## Invariantes locales

- `external_id` y `tenant_id` son identificadores únicos donde corresponde.
- Una instalación pertenece a un cliente; sus dominios y costes no pueden
  quedar huérfanos.
- Estados, modos, tipos de job y canales de versión tienen `CHECK` explícitos.
- Los jobs sólo aceptan operaciones tipadas; no existe un campo de shell o
  comando arbitrario.
- Los detalles de auditoría son JSON no secreto y referencian actor/entidad,
  no credenciales.

## Verificación realizada

```text
pytest -q tests/test_control_center_model.py
```

La prueba ejecuta toda la cadena de migraciones sobre SQLite temporal y
comprueba tablas, aislamiento, relaciones e invariantes. Quedan pospuestas las
pruebas que necesitan una base de datos desplegada, sincronización con
proveedores, infraestructura real o jobs contra VPS.
