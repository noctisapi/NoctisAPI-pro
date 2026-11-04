# NOC-011 — Aislar API pública, consola y servicios internos

Issue: [#14 NOC-011 — Aislar API pública, consola y servicios internos](https://github.com/noctisapi/NoctisAPI-pro/issues/14)
Depende de: NOC-001, NOC-005 (ambas fusionadas) — esta rama parte de `main` directamente, **no**
de la cadena de Traefik (NOC-006 a NOC-009, PRs #67-#70, aún sin fusionar). Ver nota de
conflicto esperado en la sección 5.

## Objetivo

Impedir que la superficie señuelo (`app`) alcance funciones administrativas (`admin`).

## 1. Estado anterior

`compose/docker-compose.prod.yml` no declaraba ningún `networks:` — los cuatro servicios
(`migrate`, `app`, `admin`, `traefik`) compartían la red *bridge* por defecto de Compose
(documentado como riesgo R2 en `documentation/NOC-001-AUDITORIA-ARQUITECTURA.md`). En la
práctica, aunque `admin` solo se publica en `127.0.0.1:9001` a nivel de **host**, un atacante
que comprometiera `app` (el proceso diseñado para ser atacado) podía intentar alcanzar
`admin:9001` directamente **a nivel de red Docker**, sin pasar por el host en absoluto.

## 2. Cambio

Dos redes Docker nuevas en `compose/docker-compose.prod.yml`:

- **`net-edge`** (`hp-prod-edge`): solo `app`. Alcanzable desde Traefik; puede salir a Internet
  (resolución ASN/geo, proxy de egreso) — eso no cambia aquí.
- **`net-internal`** (`hp-prod-internal`): `migrate` y `admin`. `traefik` es el único servicio en
  **ambas** redes — el puente deliberado entre la superficie pública y lo interno.

`app` y `admin` **nunca comparten ninguna red** — no hay ninguna ruta de red entre ellos, en
ningún sentido.

**Efecto secundario necesario**: `admin` usaba `HONEYPOT_MONITOR_BASE_URL=http://app:8000` para
que su monitor interno comprobara el `/health` público directamente. Si `admin` se quedaba solo
en `net-internal`, perdía esa capacidad. Se cambió a
`HONEYPOT_MONITOR_BASE_URL=http://traefik:8081` — pasa por el entrypoint `webinternal` de
Traefik (el mismo que ya enruta `hp-internal` con la cabecera `X-Internal-Monitor: 1`), que SÍ
es alcanzable desde `net-internal` porque Traefik vive en ambas redes. `admin` sigue pudiendo
monitorizar la API pública; nunca necesita estar en la misma red que `app` para hacerlo.

Nota: esto además corrige una inconsistencia ya existente en la documentación —
`documentation/ops/vps/RUNBOOK.md` y `documentation/README.md` ya decían que el valor debía ser
`http://traefik:8081`, mientras que `compose/docker-compose.prod.yml` y
`documentation/ops/vps/DEPLOY.md` tenían `http://app:8000`. Ahora el compose coincide con la
mayoría de la documentación (2 de 3 referencias).

## 3. Verificación real — aislamiento de red, no solo revisión de config

Se construyó una topología de prueba con contenedores ligeros (`traefik/whoami` en vez de la
imagen real, para probar exclusivamente el enrutamiento de red — no la lógica de aplicación) con
exactamente la misma estructura de redes que el cambio real: `app`-equivalente solo en
`net-edge`, `admin`-equivalente solo en `net-internal`, `traefik` en ambas, con sondas `alpine`
en cada red.

```bash
# Sonda en net-edge intentando resolver 'admin' por nombre
wget http://admin:9001/   →  wget: bad address 'admin:9001'

# Sonda en net-internal intentando resolver 'app' por nombre
wget http://app:8000/     →  wget: bad address 'app:8000'

# Sonda en net-internal alcanzando traefik:8081 (webinternal, proxiado a app)
wget http://traefik:8081/ →  HTTP/1.1 200 OK (respuesta de app-equivalente)

# Sonda en net-edge alcanzando traefik:80 (web, proxiado a app)
wget http://traefik:80/   →  HTTP/1.1 200 OK (respuesta de app-equivalente)
```

Resultado: **fallo de resolución DNS**, no solo de conexión — `admin`/`app` ni siquiera son
nombres resolubles entre sí (el aislamiento es real a nivel de red Docker, no un bloqueo de
puerto superficial). El camino legítimo (monitor de `admin` hacia la API pública vía Traefik)
funciona exactamente igual que antes.

Durante la construcción de esta prueba se detectó y corrigió un error propio del montaje de
prueba (las labels `traefik.*` se habían puesto por error en el propio contenedor de Traefik en
vez de en el backend), **no** un problema del archivo real — se documenta aquí solo porque
produjo un falso 502 que casi se reporta como hallazgo. El archivo real
(`compose/docker-compose.prod.yml`) siempre tuvo las labels en el lugar correcto (en `app`), como
ya hacía antes de esta Issue.

## 4. Pruebas

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
# 1017 passed, 1 skipped, 2 xfailed  (baseline de main; sin cambios — esta Issue no toca app/ ni tests/)

HP_PUBLIC_HOST=... HP_PANEL_TOKEN=... ACME_EMAIL=... APP_VERSION=... \
  docker compose -f compose/docker-compose.prod.yml config --quiet   # OK
```

Más la verificación real de la sección 3 (requiere Docker; documentada como evidencia manual,
mismo patrón que NOC-006/007/009/010).

## 5. Nota de conflicto esperado con la cadena de Traefik (NOC-006 a NOC-009)

Esta Issue depende solo de NOC-001/NOC-005 según su propio campo "Dependencias", así que la rama
parte de `main` sin la migración de Traefik (NOC-006 a NOC-009, PRs #67-#70, todavía abiertas,
ninguna fusionada). Esas Issues **también** modifican el servicio `traefik` en el mismo archivo
(`image`, `command`, `volumes`). Cuando llegue el momento de fusionar, es casi seguro que haya
que resolver un conflicto de merge entre esta rama y esa cadena — ninguna de las dos está
"equivocada", simplemente tocan líneas vecinas del mismo servicio por razones distintas. Aviso
esto explícitamente para que se decida el orden de fusión; no he intentado resolverlo de
antemano apilando esta rama sobre una cadena con la que no comparto dependencia declarada.

## 6. Criterios de aceptación

- [x] Solo puertos públicos autorizados escuchan en interfaz pública — sin cambios aquí (ya
      correcto desde antes: 80/443 públicos, 8081/9001 solo `127.0.0.1`); esta Issue añade la
      capa de aislamiento a nivel de red Docker como defensa adicional.
- [x] Panel y puertos internos no son accesibles directamente desde Internet — reforzado: ahora
      tampoco son accesibles desde la red Docker de `app`, aunque `app` fuera comprometido.
- [x] Se comprueba el acceso entre redes — sección 3, verificado con fallos de resolución DNS
      reales entre `app` y `admin`, y con el camino legítimo funcionando sin cambios.

## 7. Efectos en seguridad / compatibilidad / despliegue / rollback

- **Seguridad**: mejora real — `app` (la superficie diseñada para ser atacada) pierde toda ruta
  de red hacia `admin`/`migrate`. Antes dependía solo del binding de host de `admin`; ahora hay
  una segunda capa independiente.
- **Compatibilidad**: el único cambio funcional es la ruta que usa el monitor interno de `admin`
  (vía Traefik en vez de directo) — mismo resultado observable, verificado en la sección 3.
- **Despliegue**: el próximo `up -d` creará las dos redes nuevas (`hp-prod-edge`,
  `hp-prod-internal`); no requiere cambios en `.env.prod`.
- **Rollback**: revertir este commit restaura la red compartida única y
  `HONEYPOT_MONITOR_BASE_URL=http://app:8000` — sin migración de datos de por medio.
