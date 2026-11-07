# NOC-042 — Compatibilidad self-hosted

La ruta self-hosted continúa usando el documento RS256 existente:

```text
HP_LICENSE_MODE=offline
HP_OFFLINE_LICENSE_PATH=...
HP_OFFLINE_LICENSE_STATE_PATH=...
```

No se modifican las claves públicas, el formato de `license.json`, los leases
ni la resolución de expiración/gracia. Managed Mode se selecciona solo con
`HP_LICENSE_MODE=managed` y exige su propio envelope firmado, deployment id y
estado de generación; un documento Managed no se interpreta como licencia
self-hosted y una licencia self-hosted no activa Managed Mode.

Los gates self-hosted conservan la compatibilidad de leases anteriores,
incluido el tratamiento especial de `log_export`; los documentos Managed usan
el conjunto explícito de features del schema v1 y no reciben ese fallback
implícito.

## Baseline ejecutada

```bash
python -m pytest \
  tests/test_license_grace.py tests/test_license_runtime.py \
  tests/test_license_sync.py tests/test_licensing_client.py \
  tests/test_new_offline_license.py tests/test_pro_license.py \
  tests/test_license_telemetry.py tests/test_campaigns_pro.py \
  tests/test_managed_mode.py -q
```

Resultado: `164 passed, 2 xfailed`. No se usó servidor de licencias, pagos,
VPS ni infraestructura. Las pruebas reales contra el backend de licencias y
una licencia emitida para un deployment de laboratorio quedan para la fase de
integración final.
