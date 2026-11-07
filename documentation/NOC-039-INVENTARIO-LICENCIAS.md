# NOC-039 — Inventario de verificaciones PRO

Issue: NOC-039 / GitHub #42.

Este inventario se realizó sobre `origin/main` en la rama de trabajo de
`NOC-038`. No cambia producción ni modifica la decisión actual de licencia.
Su objetivo es dejar una matriz auditable antes de introducir entitlements
Managed en NOC-040/041.

## Fuentes de decisión

1. `honey_licensing/offline_license.py` valida el documento firmado, producto,
   tier, expiración/gracia, binding de instancia y generación.
2. `app/pro_license.py` convierte esa decisión en el snapshot backend y aplica
   el online gate cuando `online_check_required=true`.
3. `honey_licensing/feature_flags.py` expone el tier global y el conjunto de
   nueve features PRO.
4. `app/pro_ops.py` vuelve a autorizar la feature contra las features del lease,
   con aliases de compatibilidad y fail-closed.
5. `app/honeypot_public.py` y `app/panel_mvp.py` son los consumidores de los
   gates; `app/pro_router.py` y `app/log_export_stream.py` cubren exportación.

## Matriz de features y puntos de control

| Feature | Declaración | Gates de ejecución encontrados | Comportamiento sin PRO | Estado para NOC-040 |
|---|---|---|---|---|
| `cases` | `feature_flags.py` | Panel: listado, detalle, CRUD, actores, evidencia y exportación; `pro_ops.authorize_pro_feature` | UI de upgrade o HTTP 404 | Entitlement directo |
| `campaigns` | `feature_flags.py` | Panel: recompute, estado, CRUD y vínculos; `pro_ops` | UI de upgrade, no se ejecuta recompute | Entitlement directo; conservar alias legado |
| `replay` | `feature_flags.py` | Panel: vistas y endpoints `/api/replay`; redirect alternativo para Core | Vista legacy/HTTP 404 según ruta | Entitlement directo |
| `advanced_scoring` | `feature_flags.py` | No hay consumidor directo de `Feature.ADVANCED_SCORING`; aparece como alias para `api_mutation`/`analytics` en `pro_ops.py` | Depende de la feature consumidora | Resolver como capacidad explícita o eliminar alias implícito |
| `file_pipeline` | `feature_flags.py` | `/files`, `/import`, `/admin/restore`, `/plugins/install`, `/themes/upload` y derivados llaman `_require_feature` | HTTP 404 antes de leer/escribir datos | Entitlement directo y cuota de tamaño/volumen |
| `api_mutation` | `feature_flags.py` | API modular pública y panel modular; `pro_ops` aplica alias con `advanced_scoring`/`campaigns` | Ruta no disponible | Entitlement directo; revisar aliases |
| `analytics` | `feature_flags.py` | Cuatro endpoints públicos internos y panel analytics; `pro_ops` aplica alias | HTTP 404 o UI no visible | Entitlement directo y cuota temporal |
| `webhooks` | `feature_flags.py` | Alertas de eventos usan `licensing.has_feature`; receivers GitHub/GitLab son rutas de señuelo y no son el mismo control | No se emite alerta PRO | Separar claramente alertas salientes de receivers señuelo |
| `log_export` | `feature_flags.py` | Emisión SIEM pública, panel y `pro_router.py` mediante `authorize_pro_feature` | No se exporta | Mantener compatibilidad de leases antiguos y definir cuota |

## Controles transversales

| Control | Evidencia | Observación |
|---|---|---|
| Producto | `offline_license.py`, `honey_licensing/product.py` | Se rechaza mismatch de producto |
| Firma | `LicenseVerifier` con clave pública | No se acepta tier por una variable de entorno |
| Tier | `LicenseValidator` + `feature_flags` | Actualmente es un interruptor global PRO/Core |
| Expiración y gracia | `LicenseValidator` + `license_online.py` | Hay pruebas de activo, expirado y gracia |
| Binding | `HP_DEPLOYMENT_ID`, fingerprint y `LicenseStateResolver` | Debe mantenerse separado del tenant Managed |
| Online check | `pro_license.is_pro_enabled()` | Si el documento exige online y no hay manager/gate, se deniega PRO |
| Fail closed | `pro_ops.authorize_pro_feature` | Errores o features desconocidas deniegan |
| Compatibilidad de leases | alias `log_export` y `_LEASE_FEATURE_ALIASES` | Debe convertirse en regla versionada en NOC-040 |
| UI | `_license_context`, `_has_feature`, `_pro_feature_status` | La visibilidad no sustituye al gate del endpoint |

## Baseline local de licencia

La baseline de NOC-039 se ejecuta sin red, Docker, VPS, Terraform ni servidor
de licencias:

```bash
python -m pytest \
  tests/test_license_grace.py \
  tests/test_license_runtime.py \
  tests/test_license_sync.py \
  tests/test_licensing_client.py \
  tests/test_new_offline_license.py \
  tests/test_pro_license.py \
  tests/test_license_telemetry.py \
  tests/test_campaigns_pro.py -q
```

Los tests que requieran una licencia firmada real, un backend de licencias o
una instancia desplegada quedan fuera de este paso y se ejecutarán en la
validación de integración final.

## Decisiones bloqueantes para NOC-040

- El modelo actual mezcla tier global y features listadas en el lease.
- `advanced_scoring` no tiene un consumidor independiente identificable.
- `webhooks` tiene dos conceptos distintos: alertas salientes y endpoints
  señuelo receptores.
- Los aliases de `pro_ops.py` son compatibilidad implícita, no un schema
  versionado.

NOC-040 debe definir el schema de entitlements sin cambiar todavía el flujo
self-hosted; NOC-041 podrá consumirlo en Managed Mode y NOC-042 deberá demostrar
que los leases RS256 anteriores siguen funcionando.
