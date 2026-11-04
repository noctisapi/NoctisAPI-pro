# NOC-003 — Preparar CI y entorno de staging aislado

Issue: [#6 NOC-003 — Preparar CI y entorno de staging aislado](https://github.com/0x-unkwn0wn/noctisapi-pro/issues/6)
Depende de: NOC-001 (completada), NOC-002 (PR #63, pendiente de fusión — esta rama parte de
`noc-002-functional-test-baseline`, no de `main`, según la política de PRs apiladas).

## Objetivo

Disponer de validación automatizada sin afectar a clientes ni datos reales.

## 1. Workflow de pytest

Ya entregado por NOC-002 (`.github/workflows/tests.yml`, corre en cada `push`/`pull_request`).
No se duplica aquí — este PR solo lo **extiende** con lo que todavía faltaba del alcance de esta
Issue (validaciones de Compose, comprobación de dependencias):

- Nuevo paso `pip check` en el job `pytest`, tras instalar `requirements-dev.txt`.
- Nuevo job `compose-validate` que corre `docker compose -f <archivo> config --quiet` sobre los
  tres compose (`dev`, `prod`, `staging`), con variables de entorno/placeholders sintéticos para
  las que no tienen valor por defecto. No construye ni arranca ningún contenedor — solo valida
  que el YAML y la interpolación de variables son correctos.

Verificado localmente antes de subir (Docker 28.3.0 disponible en esta máquina), simulando un
checkout limpio sin `.env.dev`/`.env.prod` reales:

```bash
touch .env.dev .env.prod
docker compose -f compose/docker-compose.dev.yml config --quiet                  # OK
HP_PUBLIC_HOST=... HP_PANEL_TOKEN=... ACME_EMAIL=... APP_VERSION=... \
  docker compose -f compose/docker-compose.prod.yml config --quiet               # OK
cp .env.staging.example .env.staging
docker compose -f compose/docker-compose.staging.yml config --quiet              # OK
```

## 2. Entorno de staging aislado

Nuevo `compose/docker-compose.staging.yml` + `.env.staging.example`. Construye la imagen desde
el árbol de trabajo actual (como `dev`), no depende de un tag publicado en GHCR.

Aislamiento respecto a dev y prod (comparación completa en
`documentation/ops/STAGING.md`):

- Volúmenes propios: `hp_staging_data`, `hp_staging_myapp` (distintos de `hp_dev_*` y `hp_prod_*`).
- Sin Traefik, sin dominio público: `app` y `admin` solo se publican en `127.0.0.1` (puertos
  `8200`/`9201`, distintos de los de `dev` para poder correr ambos a la vez).
- Secretos sintéticos propios en `.env.staging.example` (`HP_SEED`, `HP_PANEL_TOKEN` de ejemplo,
  explícitamente comentados como "nunca copiar aquí un secreto de producción"). Sin licencia PRO
  configurada por defecto (CORE-only).
- `.gitignore`: se añade `!.env.staging.example` junto a la excepción ya existente de
  `.env.prod.example`, para que el ejemplo sí quede versionado.

## 3. Procedimiento documentado para levantar y destruir staging

`documentation/ops/STAGING.md` — tabla comparativa dev/staging/prod, comandos de arranque,
verificación (`/health`, `/ready`), destrucción (`down -v`, borra los volúmenes a propósito ya
que el estado de staging es desechable), y las garantías de aislamiento de la sección 2.

## 4. Pruebas

```bash
pip install -r requirements-dev.txt
pip check
python -m pytest tests/ -q
# 1017 passed, 1 skipped, 2 xfailed   (sin cambios respecto al PR #63 — este PR no toca app/)
```

No se ha tocado ningún archivo de `app/`, `honey_licensing/` ni migraciones. Las validaciones de
Compose se comprobaron localmente en la sección 1; correrán también en CI vía el nuevo job
`compose-validate`.

## 5. Criterios de aceptación

- [x] Los PR ejecutan pruebas automáticamente — ya cierto desde NOC-002; este PR añade además
      validación de Compose y de dependencias al mismo pipeline.
- [x] Staging no comparte secretos, volúmenes ni dominios de producción (sección 2).
- [x] Existe procedimiento documentado para levantar y destruir staging
      (`documentation/ops/STAGING.md`).

## 6. Efectos en seguridad / compatibilidad / despliegue / rollback

- **Seguridad**: staging se publica únicamente en `127.0.0.1`, sin Traefik ni dominio — no amplía
  la superficie expuesta. Los secretos de ejemplo son explícitamente sintéticos y están marcados
  como tales.
- **Compatibilidad**: no se ha tocado `compose/docker-compose.dev.yml` ni
  `compose/docker-compose.prod.yml` (solo se leen, sin modificar, en el nuevo job de CI).
- **Despliegue**: sin impacto en producción. El nuevo job de CI no construye ni publica ninguna
  imagen; `ghcr.yml` sigue intacto (solo construye en tags/manual).
- **Rollback**: trivial — revertir este PR quita el job `compose-validate`, el paso `pip check`,
  el compose de staging, su `.env.staging.example` y la entrada en `.gitignore`; no afecta nada
  desplegado ni a `dev`/`prod`.
