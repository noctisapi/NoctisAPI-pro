# NOC-054–059 — Release readiness

Este documento separa lo que puede verificarse localmente de lo que exige un
proveedor, una auditoría externa o un piloto autorizado. No declara `Managed
PRO 1.0` hasta cerrar todas las dependencias de la fase de release.

## Estado actual

| Issue | Alcance | Estado | Evidencia o bloqueo |
|---|---|---|---|
| NOC-054 | Flujo contratación → entrega | Parcial local | El flujo de contratos locales está cubierto por `tests/test_control_center_release_flow.py`; falta probar provisionado real y entrega de dominio/secretos. |
| NOC-055 | Auditoría de seguridad independiente | Pendiente externo | Requiere auditoría independiente y remediación de hallazgos. |
| NOC-056 | Documentación comercial, soporte y privacidad | Pendiente | Debe revisarse con el producto y los requisitos legales/comerciales definitivos. |
| NOC-057 | Restauración, fallo y baja | Parcial local | Existen contratos y tests unitarios; las pruebas destructivas sobre backup, provider y teardown quedan pospuestas. |
| NOC-058 | Piloto real | Bloqueado por autorización | Requiere cliente/entorno de piloto, ventanas operativas y aprobación explícita. |
| NOC-059 | Cierre Managed PRO 1.0 | Bloqueado | Depende como mínimo de NOC-055 y NOC-058, además de los puntos anteriores. |

## Validación local disponible

La prueba de flujo local cubre la secuencia:

```text
cliente → suscripción activa → deployment → job reconcile
        → adapter inyectado → observación → inventario actualizado
```

El adapter de la prueba sólo devuelve una observación en memoria. No usa
Terraform, Docker remoto, SSH, Cloudflare, Hetzner ni billing externo.

```bash
python -m pytest -q tests/test_control_center_release_flow.py
```

La suite completa de regresión se ejecuta en WSL/Docker Linux. Las pruebas que
impliquen estado remoto, credenciales, restauración real, teardown o piloto se
mantienen fuera de la suite automática hasta disponer de autorización y un
entorno aislado.

## Criterio para commit y merge

El siguiente commit debe agrupar únicamente una unidad revisable y conservar
esta separación entre contratos locales y acciones externas. Antes del merge a
`main` deben estar revisados el diff, los tests locales y el impacto sobre el
pipeline de release de `main`; el merge no autoriza por sí mismo un piloto ni
una prueba destructiva.
