# NOC-048 — Clientes y contratos

## Alcance implementado

- Migración `20261106_02_control_center_customers` con contactos, contratos y
  autorizaciones por cliente.
- CRUD local de clientes con `external_id`, nombre legal, estado, referencia
  de billing y notas no sensibles.
- Cada escritura crea una entrada en `cc_audit_log`.
- Las consultas aceptan `customer_scope`; cuando existe, un cliente fuera del
  alcance se comporta como inexistente y no se expone.
- Los datos de facturación se almacenan como identificadores de referencia,
  nunca como tarjetas, tokens o credenciales.

## Pendiente de despliegue

La pantalla web/API del Control Center, SSO/MFA conectado y la prueba con dos
cuentas reales quedan para la integración de aplicación. Las pruebas de esta
etapa ejecutan las migraciones sobre SQLite temporal y verifican CRUD,
auditoría y aislamiento entre clientes.

```text
pytest -q tests/test_control_center_customers.py
```
