# NOC-043–045 — Ciclo comercial, billing idempotente y cambios de plan

Se implementó un contrato puro en `honey_licensing/commercial.py`; no se ha
seleccionado ni conectado un proveedor de pagos.

## NOC-043: estados comerciales

La máquina distingue `pending`, `active`, `past_due`, `suspended` y
`terminated`. Un fallo de webhook solo deja un evento pendiente de
reconciliación y no cambia el estado. La suspensión no elimina datos y la
terminación exige aprobación explícita, conserva una ventana de retención y
es terminal.

## NOC-044: eventos de facturación

`BillingEvent` contiene únicamente referencia externa y metadatos, nunca datos
de tarjeta. `verify_webhook_signature` valida HMAC; `BillingEventLedger`
registra el `event_id` antes de permitir un segundo efecto, devolviendo
`duplicate` para reenvíos. Los errores quedan como `failed` y visibles para
reconciliación manual.

## NOC-045: cambios de plan

`plan_change` calcula features retiradas y reducciones de cuotas. Un downgrade
requiere aprobación explícita; el resultado conserva `change_id`, deployment,
planes origen/destino y el diff, de forma que el Control Center pueda mantener
historial y revertir seleccionando una configuración firmada anterior. No hay
reinstalación ni eliminación de datos en esta capa.

## Verificación

```bash
python -m pytest tests/test_commercial.py \
  tests/test_managed_mode.py tests/test_entitlements.py \
  tests/test_license_grace.py tests/test_license_runtime.py \
  tests/test_license_sync.py tests/test_licensing_client.py \
  tests/test_new_offline_license.py tests/test_pro_license.py \
  tests/test_license_telemetry.py tests/test_campaigns_pro.py -q
```

Resultado actual del bloque: `169 passed, 2 xfailed`. Las pruebas no llaman a
un proveedor de pagos, webhook externo, VPS, Terraform ni infraestructura.
