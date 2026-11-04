# NOC-009 — Diseñar alternativa Socket Proxy de mínimos privilegios

Issue: [#12 NOC-009 — Diseñar alternativa Socket Proxy de mínimos privilegios](https://github.com/noctisapi/NoctisAPI-pro/issues/12)
Depende de: NOC-007 (PR #68), NOC-008 (PR #69) — ambas pendientes de fusión. Esta rama parte de
`noc-008-remove-docker-socket`.

## Objetivo

Documentar una ruta segura si el descubrimiento dinámico fuese imprescindible — sin implantarla,
porque File Provider (NOC-007) ya cubre el caso.

## 1. Evaluación

`tecnativa/docker-socket-proxy` (HAProxy + ACL por recurso/método delante del socket real),
configurado con:

- `CONTAINERS=1` — único recurso de lectura habilitado (lo mínimo que un `providers.docker` de
  Traefik necesitaría para descubrir contenedores).
- `POST=0` — bloquea toda escritura (crear/arrancar/parar/eliminar/exec) sea cual sea el recurso.
- Todo lo demás (`IMAGES`, `NETWORKS`, `VOLUMES`, `EXEC`, `BUILD`, `COMMIT`, `SECRETS`,
  `SERVICES`, `SWARM`, `SYSTEM`, etc.) explícitamente en `0`.
- Socket real montado **solo en el proxy** (`:ro`), nunca en Traefik.
- Sin `ports:` — solo alcanzable por nombre de servicio en la red privada del proyecto Compose.

## 2. Verificación real — tests negativos, no solo configuración

Se levantó el proxy en un stack de prueba aislado (red privada, sin publicar puertos) y se probó
desde otro contenedor en la misma red:

```bash
# GET de solo lectura -- habilitado por CONTAINERS=1
wget -qO- -S http://docker-socket-proxy:2375/containers/json
# → HTTP/1.1 200 OK

# POST de escritura -- bloqueado por POST=0
wget -qO- -S --post-data='{}' http://docker-socket-proxy:2375/containers/create?name=pwn
# → HTTP/1.0 403 Forbidden

# POST exec -- bloqueado por POST=0 (EXEC=0 es redundante aquí, pero también está puesto)
wget -qO- -S --post-data='{"Cmd":["id"]}' http://docker-socket-proxy:2375/containers/<id>/exec
# → HTTP/1.0 403 Forbidden
```

```bash
docker ps --format "table {{.Names}}\t{{.Ports}}"
# docker-socket-proxy   2375/tcp   <- EXPOSE de la imagen, sin binding al host (confirmado sin publicar)
```

Resultado: lectura permitida, escritura y exec bloqueados, sin puerto publicado — los tres
criterios de aceptación de esta Issue, verificados contra el proxy real, no solo leídos en su
documentación.

## 3. Entregable — configuración de referencia, NO desplegada por defecto

`compose/traefik/docker-socket-proxy.optional.yml`: override de Compose independiente, con
comentarios explicando que es una contingencia y cómo activarla si algún día hiciera falta
(`docker compose -f docker-compose.prod.yml -f compose/traefik/docker-socket-proxy.optional.yml ...`).
**No se referencia desde ningún `make`/script del repo** — activarla es una decisión explícita
futura, no algo que ocurra por accidente.

Verificado que el merge con `docker-compose.prod.yml` es válido y reemplaza correctamente el
`command` de `traefik` (Compose sustituye listas al fusionar `-f`, no las concatena):

```bash
docker compose -f compose/docker-compose.prod.yml \
                -f compose/traefik/docker-socket-proxy.optional.yml \
                config --quiet   # OK
docker compose -f compose/docker-compose.prod.yml \
                -f compose/traefik/docker-socket-proxy.optional.yml \
                config --services
# migrate, admin, app, docker-socket-proxy, traefik-config, traefik
```

`compose/docker-compose.prod.yml` en sí **no se modifica** — este archivo es puramente opcional
y aditivo.

## 4. ADR actualizada

`documentation/adr/0003-traefik-file-provider-vs-docker-socket-proxy.md` pasa de "Propuesta" a
"Implementada", con la evidencia de la sección 2 incorporada directamente en la ADR (no solo en
este informe), ya que su propio criterio de aceptación original era "ADR explica cuándo se
permitiría Socket Proxy" — ahora la ADR no solo lo explica, demuestra que la configuración que lo
permitiría ya está evaluada y funciona.

## 5. Pruebas

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
# 1020 passed, 1 skipped, 2 xfailed  (sin cambios — este PR no toca app/ ni tests/)
```

Más la verificación manual de la sección 2 (requiere Docker; no se automatizó como test de
`pytest` porque montaría el socket Docker real del runner, algo que no es necesario para una
configuración que no se despliega por defecto — y que rompería el patrón actual de
`tests/test_compose_security.py`, que deliberadamente no necesita Docker).

## 6. Criterios de aceptación

- [x] ADR explica cuándo se permitiría Socket Proxy — ya existía desde NOC-004 (ADR 0003);
      actualizada aquí con la evidencia real de que la configuración propuesta funciona.
- [x] Permisos POST/EXEC y operaciones de escritura quedan bloqueados cuando proceda — sección 2,
      verificado con tests negativos reales (403 en create y en exec).
- [x] No se despliega por defecto ni se publica Docker API — `docker-socket-proxy.optional.yml`
      es un archivo aparte, sin referencias en el repo; sin `ports:` en la configuración.

## 7. Efectos en seguridad / compatibilidad / despliegue / rollback

- **Seguridad**: no cambia la postura actual (File Provider, sin socket) — esto es
  documentación + un artefacto de contingencia inerte, no una activación.
- **Compatibilidad**: cero impacto en `docker-compose.prod.yml`; el archivo opcional es aditivo.
- **Despliegue**: ninguno, salvo que alguien decida activamente usar el override en el futuro.
- **Rollback**: borrar `compose/traefik/docker-socket-proxy.optional.yml` no afecta nada, porque
  nada lo usa por defecto.
