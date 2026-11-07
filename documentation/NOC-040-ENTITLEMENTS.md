# NOC-040 — Entitlements y planes independientes de billing

El contrato está implementado en `honey_licensing/entitlements.py` y es
deliberadamente independiente de pagos, suscripciones y permisos de usuario.

## Schema v1

```json
{
  "schema_version": 1,
  "plan_id": "managed-pro",
  "mode": "managed",
  "features": ["cases", "analytics"],
  "quotas": {"max_cases": 1000},
  "starts_at": "2026-01-01T00:00:00Z",
  "expires_at": "2027-01-01T00:00:00Z"
}
```

`mode` solo puede ser `managed` o `self_hosted`; las fechas deben incluir
zona horaria; las features se validan contra el catálogo existente; y las
cuotas son enteros no negativos. La evaluación local devuelve razones
deterministas (`allowed`, `feature_not_entitled`, `quota_exceeded`, `expired`,
etc.).

El documento no acepta campos de billing (`payment_status`, `price_id`,
`subscription_id`, proveedor de pagos) ni de autorización de usuarios
(`user_roles`, `permissions`). La pertenencia de un usuario a la consola
continúa siendo responsabilidad de identidad/RBAC, no del entitlement.

## Compatibilidad

NOC-040 solo añade el contrato y su evaluación. El flujo actual de licencias
RS256 y los gates self-hosted no se cambian todavía. NOC-041 consumirá este
contrato para Managed Mode; NOC-042 mantendrá la ruta RS256 anterior y sus
tests de compatibilidad.

La decisión sobre aliases heredados (`advanced_scoring` para algunas rutas,
`log_export` para leases antiguos) queda explícita para NOC-041/042 y no se
convierte en un bypass global.

## Verificación realizada

```bash
python -m pytest tests/test_entitlements.py \
  tests/test_license_grace.py tests/test_license_runtime.py \
  tests/test_license_sync.py tests/test_licensing_client.py \
  tests/test_new_offline_license.py tests/test_pro_license.py \
  tests/test_license_telemetry.py tests/test_campaigns_pro.py -q
```

Resultado actual: `161 passed, 2 xfailed`. No se contactó ningún servidor de
licencias, proveedor de pagos, VPS ni infraestructura.
