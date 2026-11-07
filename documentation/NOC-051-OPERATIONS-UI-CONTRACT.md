# NOC-051 — UI de operaciones

## Contrato local implementado

- `preflight` valida la operación tipada y el deployment antes de crear un
  job.
- `teardown` requiere primera confirmación y una segunda frase exacta:
  `CONFIRM TEARDOWN <deployment_id>`.
- La proyección de estado separa `success`, `error` y `pending`; un job
  fallido nunca se presenta como éxito.

La futura pantalla deberá usar este contrato y enviar la operación al runner
NOC-050. No se ha montado todavía la UI en producción ni se ha ejecutado
Deployer, SSH, Terraform o una operación destructiva real.

```text
pytest -q tests/test_control_center_operations.py
```
