# NOC-038 — Estado Terraform y secretos del Deployer

## Decisión implementada

Las operaciones reales del Deployer usan un backend Terraform S3-compatible
con cifrado del lado del backend y bloqueo DynamoDB. Cada módulo obtiene una
clave independiente y estable:

```text
<prefix>/<customer_id>/<deployment_id>/<module>.tfstate
```

El `deployment_id` sigue siendo el identificador de reconciliación de NOC-031;
`customer_id` añade el límite de tenant exigido por NOC-038. El backend se
configura en tiempo de ejecución, nunca en Git ni en los módulos Terraform.

La CLI rechaza estado local durante `deploy`, `status`, `verify`,
`reconcile` y operaciones de instancia. El estado local solo se permite para
tests y `deploy --dry-run`, que inicializa Terraform con
`-backend=false` y no contacta proveedores.

## Configuración del runner

```text
NOCTISAPI_TF_STATE_BACKEND=s3
NOCTISAPI_TF_STATE_BUCKET=noctisapi-tf-state
NOCTISAPI_TF_STATE_REGION=eu-west-1
NOCTISAPI_TF_STATE_LOCK_TABLE=noctisapi-tf-lock
NOCTISAPI_TF_STATE_PREFIX=noctisapi
NOCTISAPI_TF_STATE_ROLE_ARN=arn:aws:iam::<account>:role/noctisapi-deployer
```

Opcionalmente puede usarse `NOCTISAPI_TF_STATE_ENDPOINT` para un servicio
S3-compatible controlado por la organización; solo se acepta `https://`.
Las credenciales del backend deben provenir del rol/identidad del runner,
nunca de argumentos, `.tfvars`, el manifiesto o el repositorio.

## Secret manager

En ejecución real el Deployer usa AWS Secrets Manager mediante el comando
`aws` y el rol del runner:

```text
NOCTISAPI_SECRET_BACKEND=aws-secrets-manager
NOCTISAPI_SECRET_PREFIX=noctisapi/managed
NOCTISAPI_SECRET_REGION=eu-west-1
```

Los nombres lógicos actuales son `HCLOUD_TOKEN`, `CLOUDFLARE_API_TOKEN` y
`GIT_DEPLOY_TOKEN`; los valores se leen en memoria y no se incorporan a
argumentos de Terraform ni a logs. La rotación invoca la rotación configurada
en Secrets Manager y no imprime el valor nuevo. `NOCTISAPI_SECRET_BACKEND=env`
queda reservado para fixtures de tests; la CLI real lo rechaza.

La operación queda auditada en el manifiesto sin registrar el secreto:

```bash
python scripts/deployer.py rotate-secret \
  --manifest compose/secrets/deployment-manifest.json \
  --secret-name CLOUDFLARE_API_TOKEN --confirm
```

## Roles y auditoría

El runner debe usar roles separados: uno para leer/escribir el prefijo de
estado y adquirir el lock; otro, con permisos mínimos por proveedor, para las
acciones de infraestructura. Las acciones privilegiadas se registran en el
historial no secreto del manifiesto y los eventos del backend/Secret Manager.
La creación de esos roles y la validación contra cuentas reales se posponen
hasta la fase final de infraestructura.

## Recuperación y pruebas aplazadas

Ya están cubiertos localmente los contratos de nombres, cifrado requerido,
TLS del endpoint, rechazo de backend local, aislamiento por tenant y ausencia
de secretos en argv. Quedan deliberadamente aplazados:

1. aplicar Terraform contra S3/DynamoDB reales;
2. probar pérdida de lock, restauración de una versión del state y recuperación
   desde backup;
3. validar IAM/Secret Manager con una cuenta real;
4. ejecutar una provisión o rotación sobre una VPS.

Estas pruebas se ejecutarán juntas en la fase final, con una cuenta y un tenant
de laboratorio, antes del piloto de NOC-058.
