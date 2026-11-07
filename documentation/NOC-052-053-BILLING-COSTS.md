# NOC-052/053 — Billing visible y control de costes

## Alcance local implementado

- Vista de suscripciones con plan, estado comercial, modo, versión de
  entitlements y estado de reconciliación.
- Los eventos externos son idempotentes por `external_event_id`.
- La vista sólo expone si existe una referencia de billing; no recoge tarjetas,
  PAN, CVV ni expiración.
- Costes atribuibles por deployment con separación `invoiced/actual` frente a
  `estimated` y otros orígenes.
- Presupuestos por cliente y periodo con niveles `ok`, `warning` y `critical`.

## Pospuesto

La conexión al proveedor de billing, APIs de cloud/storage/backup, horas reales
de soporte y alertas externas se dejan para la integración desplegada. Esta
fase verifica únicamente idempotencia, rechazo de datos de tarjeta,
atribución y cálculo local.

```text
pytest -q tests/test_control_center_billing_costs.py
```
