# NOC-036 — Operaciones de instancia desde el Deployer

El Deployer privado expone las operaciones recurrentes sin requerir SSH manual:

```text
python scripts/deployer.py backup  --manifest ... --state-dir ... --ssh-private-key-file ...
python scripts/deployer.py upgrade --approved-version 1.2.3 --confirm --manifest ... --state-dir ... --ssh-private-key-file ...
python scripts/deployer.py suspend --confirm --manifest ... --state-dir ... --ssh-private-key-file ...
python scripts/deployer.py resume  --confirm --manifest ... --state-dir ... --ssh-private-key-file ...
```

## Precondiciones y seguridad

- Todas las operaciones resuelven el servidor por el `deployment_id` del manifiesto y el estado Terraform asociado.
- `upgrade` exige una versión explícita distinta de `latest`; el host aborta si la imagen resuelta no coincide con la versión aprobada.
- `upgrade` reutiliza `scripts/upgrade.py` (NOC-029): backup previo, migraciones, health gate y rollback automático.
- `--force` solo permite continuar cuando el operador ha revisado una migración marcada irreversible; sigue requiriendo `--confirm`.
- `suspend` ejecuta únicamente `docker compose stop app admin`: no elimina contenedores, volúmenes, estado ni backups.
- `resume` arranca `app` y `admin` y ejecuta la verificación remota completa antes de marcar la instancia como activa.
- `backup` usa `backup_sqlite.sh` con el override Managed para resolver los volúmenes e imagen correctos; conserva cifrado, integridad, retención y límite de backups.

## Idempotencia y auditoría

- Suspender una instancia ya suspendida y reanudar una ya activa son operaciones `noop` exitosas.
- Las transiciones se escriben en `status_history` y cada resultado en `operation_history`, ambos sin secretos y limitados a las últimas 20 entradas.
- Un fallo de upgrade deja la instancia como `degraded` y conserva el resultado; un aborto de precondición no modifica el estado operativo.
- El rollback de Managed establece tanto `APP_VERSION` como `MANAGED_APP_VERSION`, evitando que Compose vuelva a arrancar accidentalmente la versión fallida.

La operación real debe ejecutarse desde el entorno del operador con las credenciales SSH configuradas y sobre una instancia de staging antes de usarla en producción.
