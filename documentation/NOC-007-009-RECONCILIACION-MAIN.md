# Reconciliación: NOC-007/008/009 nunca llegaron a `main`, y un bug encontrado al fusionarlas

No es una Issue nueva del backlog NOC-001..059 — es una corrección de integración sobre Issues
ya cerradas (NOC-006, NOC-007, NOC-008, NOC-009), necesaria antes de poder seguir con NOC-013 (que
depende de NOC-011 y comparte `compose/docker-compose.prod.yml`).

## 1. Hallazgo: los PRs #68, #69, #70 están "MERGED" en GitHub pero nunca tocaron `main`

La cadena de PRs apilados se abrió correctamente (cada rama contra la anterior, no contra
`main`), pero solo el primer eslabón se fusionó contra `main`:

| PR | rama | base real en el merge | ¿llegó a `main`? |
|----|------|------------------------|-------------------|
| #67 (NOC-006) | `noc-006-pin-traefik-v3` | `main` | sí |
| #68 (NOC-007) | `noc-007-traefik-file-provider` | `noc-006-pin-traefik-v3` | **no** |
| #69 (NOC-008) | `noc-008-remove-docker-socket` | `noc-007-traefik-file-provider` | **no** |
| #70 (NOC-009) | `noc-009-socket-proxy-contingency` | `noc-008-remove-docker-socket` | **no** |

Cada uno de esos tres merges actualizó la rama *predecesora*, no `main`. Como esas ramas
predecesoras nunca se fusionaron (de nuevo) contra `main` después, su contenido quedó aislado.
Confirmado con `git diff --stat main origin/noc-009-socket-proxy-contingency`: 16 archivos de
diferencia, incluyendo que **`main` seguía con Traefik usando `providers.docker=true` y
`/var/run/docker.sock` montado** — exactamente lo que NOC-007/NOC-008 existían para eliminar — a
pesar de que ambas Issues estaban documentadas como completadas.

Mientras tanto, NOC-010/011/012 se bifurcaron directamente de `main` (sin la migración a File
Provider) y sí llegaron a `main` correctamente. Las dos líneas de trabajo son divergentes, no una
superconjunto de la otra.

## 2. Fusión

Rama `fix-traefik-stack-merge-gap` desde `main` actual + `git merge origin/noc-009-socket-proxy-contingency`.
Único conflicto real: `compose/docker-compose.prod.yml`, en el bloque `labels:` de `app` — main
lo tenía (enrutado por Docker labels, pre-NOC-007) y la rama stranded lo había eliminado
(enrutado por File Provider). Resuelto a favor de File Provider (NOC-007/008 son la versión
correcta y más reciente), conservando intacta la segmentación de redes de NOC-011
(`net-edge`/`net-internal`) y el split de middlewares de NOC-012 (`hp-health-ratelimit` separado
de `hp-monitor-headers`) — ninguna de las dos existía cuando se escribió la rama stranded.

Añadido además `network_mode: "none"` al nuevo servicio `traefik-config` (solo renderiza un
fichero a un volumen compartido; no necesita red alguna) — coherente con el principio de mínimo
privilegio de red que NOC-011 estableció para el resto de servicios.

## 3. Bug encontrado al fusionar (no estaba en ninguna rama individual): `customRequestHeaders` de Traefik sobrescribe, no solo añade

Al combinar el router `hp-internal` (NOC-011/012, en `main`) con el enrutado File-Provider
(NOC-007, en la rama stranded), quedó expuesto algo que ninguna de las dos Issues verificó de
forma aislada: `hp-internal` seguía usando el middleware `hp-monitor-headers`, que inyecta
`X-Internal-Monitor: "1"` **de forma incondicional**.

**Verificado con Traefik v3.7.16 real** (no asumido): un middleware `customRequestHeaders` con un
valor fijo **sobrescribe** cualquier cabecera del mismo nombre que el cliente ya haya enviado —
no es un "solo si falta".

```
# cliente envía X-Internal-Monitor: a-real-random-secret-value
# el backend (whoami) recibe:
X-Internal-Monitor: 1          <-- Traefik lo pisó
```

Consecuencia real: `app/honeypot_monitor.py::_base_headers()` (corregido en NOC-012 para enviar
el `HP_MONITOR_SECRET` real) nunca consigue que ese secreto llegue a
`app/honeypot_public.py::_is_monitor()` — Traefik lo sustituye por el literal `"1"` antes de que
llegue a `app`. Dos efectos, según cómo esté configurado `HP_MONITOR_SECRET`:

- Si es un secreto real (≠ "1"): `_is_monitor()` nunca reconoce al monitor de `admin` como
  interno — regresión funcional (justo lo que NOC-012 ya había señalado como riesgo, pero
  causado ahora por Traefik, no por `honeypot_monitor.py`).
- Si fuese literalmente `"1"` (el escenario débil que NOC-012 advertía evitar): **cualquiera**
  que alcance el entrypoint `webinternal` queda auto-reconocido como monitor sin conocer ningún
  secreto, porque Traefik se lo asigna igual sin importar lo que el cliente envíe — el propio
  bypass de cabecera externa que esa Issue existía para prevenir, ahora por otra vía.

Alcance de explotación: `webinternal` solo es alcanzable desde `127.0.0.1` del host o desde
`net-internal` (NOC-011) — no es internet-facing — pero el fallo anula por completo el propósito
del secreto en el único camino legítimo que debía usarlo.

### Corrección

Eliminado `hp-monitor-headers` del router `hp-internal` (y la definición del middleware entera,
ya sin uso en ningún router tras el fix de NOC-012 a `hp-health`). La confianza pasa a depender
solo de: (a) el aislamiento de red de NOC-011 (`webinternal` únicamente loopback + net-internal)
y (b) el secreto real que el cliente ya envía, sin que nada lo toque de camino a `app`.

**Verificado de nuevo con Traefik real tras el fix** (`compose/traefik/render-dynamic-config.sh`
real, Traefik v3.7.16, `whoami` como backend):

```bash
# hp-health (público) -- cabecera adivinada por un atacante llega intacta,
# sin que Traefik la toque; _is_monitor() del lado de app la rechazará porque
# no coincide con HP_MONITOR_SECRET -- el comportamiento correcto siempre fue
# este, no algo que Traefik deba reforzar.
curl .../status -H "Host: ..." -H "X-Internal-Monitor: attacker-guess"
# -> X-Internal-Monitor: attacker-guess   (intacta, no sobrescrita ni añadida)

# hp-internal, cliente envía el secreto real -- antes se perdía, ahora llega intacto
curl http://.../ -H "X-Internal-Monitor: a-real-random-secret-value"
# -> X-Internal-Monitor: a-real-random-secret-value

# hp-internal, cliente no envía nada -- sigue sin aparecer "1" de regalo
curl http://.../
# -> (ausente)
```

## 4. Pruebas

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
# 1012 passed, 1 skipped, 2 xfailed
python -m pytest tests/test_compose_security.py -q
# 3 passed -- hereda los guardas de NOC-008 (sin docker.sock, sin providers.docker)
```

10 fallos preexistentes en `tests/test_panel_api_modular_v2.py`, `test_panel_geo_flags.py` y
`test_panel_replay.py` **no** son de esta rama: reproducidos también contra `main` limpio (vía
`git worktree`) y causados por un Starlette/FastAPI más nuevo instalado globalmente en esta
máquina que el pin de `requirements.txt` (`TypeError:
_PanelAuthMiddleware.__init__() got an unexpected keyword argument 'app'`) — el mismo patrón de
falso-negativo por entorno local ya documentado en NOC-002. CI en GitHub (entorno limpio, pins
exactos) está en verde sobre el `main` actual (run de "Tests" tras el merge de #72).

Verificación real de infraestructura (secciones 1 y 3) con Docker/Traefik v3.7.16 real, no
simulada.

## 5. Criterios de aceptación

- [x] `main` refleja de verdad el estado de NOC-006/007/008/009: Traefik v3.7.16, File Provider,
      sin `/var/run/docker.sock`, contingencia de Socket Proxy documentada — no solo PRs
      marcados como fusionados.
- [x] Sin regresión de NOC-010/011/012: aislamiento de redes y split de middlewares de
      `hp-health` se conservan intactos.
- [x] El bug de sobrescritura de cabecera encontrado al fusionar queda corregido y verificado
      contra Traefik real, no solo razonado.

## 6. Efectos en seguridad / compatibilidad / despliegue / rollback

- **Seguridad**: cierra el hueco de integración (File Provider + sin socket realmente en
  `main`) y corrige un bug real que anulaba el secreto del monitor interno en el único camino
  que debía usarlo.
- **Compatibilidad**: ningún comportamiento observable de la API señuelo cambia. El monitor de
  `admin` pasa a funcionar como se documentó en NOC-012 (antes no, por este bug).
- **Despliegue**: quien despliegue `compose/docker-compose.prod.yml` desde este punto obtiene
  directamente la versión reconciliada; no hay paso manual adicional.
- **Rollback**: revertir este commit devuelve a el estado actual de `main` (con el hueco de
  integración y el bug de cabecera); no hay cambios de datos ni migraciones involucradas.
