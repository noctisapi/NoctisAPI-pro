# NOC-037 — Teardown controlado y reconciliación

El Deployer añade dos operaciones separadas:

```text
python scripts/deployer.py reconcile --manifest ... --state-dir ...

python scripts/deployer.py teardown \
  --manifest ... --state-dir ... \
  --deployment-id <id-exacto-del-manifiesto> \
  --retention-dir <directorio-protegido> \
  --cloudflare-account-id <account-id> \
  --ssh-private-key-file <key> \
  --ssh-public-key-file <public-key> \
  --ssh-allowed-cidr <cidr> \
  --confirm --confirm-deletion
```

## Secuencia protegida

1. Comprueba que el `deployment_id` indicado coincide exactamente con el manifiesto y que la instancia está `active`, `degraded` o `suspended`.
2. Ejecuta un backup cifrado final sin borrar datos.
3. Exporta los artefactos cifrados y `backup_encryption_key.txt` a una ruta de retención separada por deployment e instante UTC.
4. Cambia el manifiesto a `decommissioning` y genera planes Terraform explícitos de destrucción.
5. El Deployer copia los módulos a un directorio efímero de auditoría y retira únicamente las líneas literales `prevent_destroy = true` en esa copia; los módulos fuente mantienen siempre la protección y no aceptan una variable Terraform para desactivarla.
6. Destruye Hetzner y después Cloudflare, verifica que ambos estados Terraform quedan sin recursos y marca el manifiesto como `decommissioned`.

Si falla el backup, la exportación o el plan, el teardown no empieza. Si falla después de comenzar, se conserva el manifiesto en `decommissioning`, el estado Terraform y el registro de operación para reanudar/reconciliar de forma explícita.

`reconcile` inspecciona los estados Terraform en modo lectura, exige recursos identificables por el deployment exacto y no ejecuta `apply`, `destroy` ni cambios remotos.
