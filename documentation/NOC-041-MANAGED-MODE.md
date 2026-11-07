# NOC-041 — Managed Mode sin activación visible

Managed Mode consume un envelope firmado por el operador, no una variable
booleana ni una licencia introducida manualmente por el cliente:

```text
HP_LICENSE_MODE=managed
HP_MANAGED_ENTITLEMENTS_PATH=/var/lib/myapp/managed_entitlements.json
HP_MANAGED_ENTITLEMENTS_STATE_PATH=/var/lib/myapp/managed_entitlements_state.json
```

El envelope usa la misma verificación RSA canónica que los documentos de
licencia existentes y contiene `product`, `deployment_id`, `generation` y el
schema de entitlements de NOC-040. La instancia solo tiene la clave pública.
La generación máxima se persiste con escritura atómica; una configuración
firmada con una generación menor se rechaza.

La autenticación, el binding al deployment y las fechas se validan antes de
exponer capacidades. Un documento Managed sin features no habilita ninguna
feature. `app/pro_ops.py` aplica además el conjunto de features del documento,
por lo que un entitlement parcial no se convierte en PRO global. Los permisos
de usuario siguen siendo responsabilidad de identidad/RBAC.

La ruta self-hosted conserva el flujo de licencia RS256 existente. Managed
Mode solo cambia la fuente autenticada del snapshot cuando el modo se declara
explícitamente y no introduce `LICENSE_DISABLED` ni un bypass universal.

## Verificación local

```bash
python -m pytest tests/test_managed_mode.py tests/test_entitlements.py \
  tests/test_license_grace.py tests/test_license_runtime.py \
  tests/test_license_sync.py tests/test_licensing_client.py \
  tests/test_new_offline_license.py tests/test_pro_license.py \
  tests/test_license_telemetry.py tests/test_campaigns_pro.py -q
```

Resultado actual: `164 passed, 2 xfailed`. Las pruebas generan claves RSA
efímeras y documentos firmados en directorios temporales; no contactan el
servidor de licencias, pagos, VPS, Terraform ni infraestructura.
