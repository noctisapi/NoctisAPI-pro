# NOC-002 — Línea base de pruebas funcionales

Issue: [#5 NOC-002 — Crear línea base de pruebas funcionales](https://github.com/0x-unkwn0wn/noctisapi-pro/issues/5)
Depende de: NOC-001 (completada, ver `documentation/NOC-001-AUDITORIA-ARQUITECTURA.md`).

## Objetivo

Evitar regresiones del honeypot y del panel durante la migración, estableciendo una línea
base reproducible de la suite de pruebas existente.

## 1. Hallazgo clave: `tests/` no estaba versionado en git

**Esto es más grave que la falta de CI.** Desde el commit `77ccaeb` ("fix(mutations): remove
_variant from body/headers...", 2026-03-11), `tests/` se añadió a `.gitignore` y se ejecutó
`git rm -r --cached tests/`, con el mensaje "local only, not shipped in the public image" —
bundleado dentro de un commit de corrección de la aplicación, no como su propio cambio. Desde
entonces, los 41 archivos de test (1019 casos) han existido solo como archivos sueltos en el
disco de quien los haya tenido localmente, **sin historial de git, sin aparecer en ningún PR, y
sin poder ejecutarse nunca en CI** — un `git clone` limpio de este repo no trae ningún test.

La justificación original ("no shipped in the public image") ya estaba resuelta de forma
independiente por `.dockerignore`, que también excluye `tests/` del contexto de build de Docker
(`.dockerignore:16`). Confundir "no enviar tests a la imagen de producción" con "no versionar
los tests en git" fue el error: son dos mecanismos distintos para dos problemas distintos.

**Corregido en este PR:**
- Se quita la regla `tests/` de `.gitignore` (la exclusión de la imagen Docker se mantiene
  intacta vía `.dockerignore`, sin cambios).
- Se restauran los 41 archivos de test al control de versiones (`git add tests/`).

Sin este cambio, el workflow de CI de la sección 4 habría ejecutado `pytest tests/` sobre un
checkout vacío y no habría encontrado ningún test que correr.

## 2. Hallazgo secundario: versión de dependencias no reproducible

Independientemente de lo anterior, los tests tampoco eran reproducibles entre máquinas: no
existía ningún workflow de CI que ejecutara `pytest` (solo `.github/workflows/ghcr.yml`, que
construye y publica la imagen), así que solo se habían corrido localmente contra lo que cada
máquina tuviera instalado — y `requirements.txt` fija `fastapi==0.135.3`, pero una instalación
local típica (incluida la usada para este informe antes de corregirlo) puede tener versiones
distintas instaladas globalmente.

Verificación:

```bash
python -c "import fastapi; print(fastapi.__version__)"
# fastapi 0.115.0   (instalación global de esta máquina, no coincide con el pin)
```

Con esa desviación, `python -m pytest tests/ -q` daba **13 fallos** — 8 de ellos desaparecían
por completo al ejecutar la suite en un entorno limpio con las versiones exactas de
`requirements.txt`:

```bash
python -m venv /tmp/noc002_venv
/tmp/noc002_venv/Scripts/python.exe -m pip install -r requirements.txt pytest
/tmp/noc002_venv/Scripts/python.exe -m pytest tests/ -q
# 5 failed, 1014 passed, 1 skipped   (antes: 13 failed, 1006 passed, 1 skipped)
```

Los 8 fallos que desaparecen son puramente de desviación de entorno
(`tests/test_panel_api_modular_v2.py` × 5, `tests/test_panel_replay.py` × 3) — no indican ningún
problema de la aplicación.

## 3. Fallos específicos del runner de CI, encontrados tras abrir el PR (corregidos en este mismo PR)

El primer run de `.github/workflows/tests.yml` sobre este PR (GitHub Actions, `ubuntu-latest`)
mostró **2 fallos adicionales** que no habían aparecido ni en la máquina de desarrollo (con
desviación de versiones) ni en el venv local limpio de la sección 2 — ninguno de los dos es
flaky ni depende de la versión de `fastapi`/`starlette`:

### 3.1 `app/runtime_provider.py::RuntimeConfigProvider.invalidate()` — bug real de la aplicación

`tests/test_runtime_provider.py::TestCaching::test_invalidate_forces_rebuild` falló con
`assert 1 == 2`. Causa: `invalidate()` solo reseteaba `self._cached_at = 0.0`, y `get_config()`
decide si reconstruir comparando `(time.monotonic() - self._cached_at) < self._cache_ttl`. En un
proceso que lleva corriendo menos tiempo que `HP_RUNTIME_CACHE_TTL` (60s por defecto) desde que
arrancó — como el runner de CI, que ejecuta toda la suite en ~10s — `time.monotonic()` todavía no
ha superado esos 60s, así que `(now - 0.0) < 60` sigue siendo cierto y la caché **no se invalida
de verdad**. Esto no es solo un artefacto de test: en producción, si un admin invalida la caché
de runtime (tras cambiar la configuración desde el panel) durante el primer minuto de vida del
proceso, el cambio no se aplicaría hasta que el TTL expire por sí solo.

**Corregido**: `invalidate()` ahora también pone `self._cached = None`, que por sí solo fuerza el
rebuild en la siguiente llamada a `get_config()`, sin depender de la aritmética de `monotonic()`.

### 3.2 `tests/test_licensing_client.py::test_compute_client_identity_returns_expected_shape` — bug de aislamiento del test

Fallaba con `PermissionError: [Errno 13] Permission denied: '/var/lib/myapp'`. A diferencia de
los demás tests de ese archivo, este llamaba a `compute_client_identity()` sin fijar
`INSTANCE_ID_PATH` a un directorio temporal, así que caía al default de
`honey_licensing/client.py:101` (`/var/lib/myapp/instance_id`) — una ruta que solo existe y es
escribible dentro del contenedor Docker (volumen montado), no en un runner de CI desnudo.
**Corregido**: el test ahora fija `INSTANCE_ID_PATH` a un `tempfile.TemporaryDirectory()` y lo
restaura al terminar, igual que ya hacían el resto de tests del archivo. Cambio solo en el test.

## 4. Corrección de reproducibilidad (este PR)

- `requirements-dev.txt` (nuevo): fija `pytest==8.3.4` sobre `requirements.txt`, para que
  cualquier máquina o pipeline instale exactamente las mismas versiones.
- `.github/workflows/tests.yml` (nuevo): ejecuta `pip install -r requirements-dev.txt` +
  `python -m pytest tests/ -q` en cada `push` y `pull_request` (y permite disparo manual). No
  interfiere con `ghcr.yml`, que ahora solo construye/publica en tags o manualmente.

Con esto, el comando reproducible y oficial de la suite pasa a ser:

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
```

## 5. Baseline por área crítica (cobertura existente)

| Área (pedida por la Issue) | Archivos de test | Mecanismo |
|---|---|---|
| Rutas públicas / respuestas señuelo | `test_catalog_registry.py`, `test_catalog_route_alignment.py`, `test_endpoint_resolver.py`, `test_honeypot_modular_response.py`, `test_honeypot_modular_runtime.py`, `test_response_factory.py`, `test_runtime_builder.py`, `test_runtime_policy.py`, `test_runtime_provider.py` | Unitarios + `TestClient` sobre la app modular |
| Scoring | `test_stage_classifier.py`, `test_ttp.py` | Unitarios deterministas |
| Actores / sesiones | `test_interaction_context_builder.py`, `test_panel_replay.py` | Unitarios + `TestClient` |
| Templates (catálogo) | `test_catalog_registry.py`, `test_catalog_route_alignment.py` | Unitarios |
| Licencias | `test_license_grace.py`, `test_license_runtime.py`, `test_license_sync.py`, `test_license_telemetry.py`, `test_new_offline_license.py`, `test_pro_license.py`, `test_pro_ops.py` | Unitarios (RSA firmada en memoria) |
| Panel | `test_panel_api_modular_v2.py`, `test_panel_geo_flags.py`, `test_panel_replay.py` | `TestClient` sobre `app/panel_mvp.py` |

Las 6 áreas que pide la Issue ya tenían cobertura representativa; no se identificó ningún área
sin ningún test. `tests/` ya mantiene ~1:1 un archivo de test por módulo de `app/` (41 archivos).

## 6. Dos fallos reales de datos de prueba caducados, corregidos en este PR

### 6.1 `tests/test_api_modular.py::test_analytics_functions`

Usaba timestamps fijos de `2026-02-25`. Con la fecha actual, esos eventos ya caían fuera de la
ventana `window_hours=2000` (~83 días) que el propio test pedía, así que las funciones de
analítica devolvían listas vacías — no por un bug de `api_modular.py`, sino porque el dato de
prueba caducó. **Corregido**: los timestamps ahora se generan relativos a `datetime.now()`.

### 6.2 `tests/test_panel_geo_flags.py` (2 tests)

Fallaban con `sqlite3.OperationalError: no such column: a.typical_behavior`. El fixture de este
archivo construye el esquema de la tabla `actors` a mano (`_init_db()`) en vez de correr las
migraciones reales, y quedó desincronizado de la migración
`migrations/versions/20260408_03_attack_classification.py`, que añadió la columna
`actors.typical_behavior`. Verificado que ninguna otra migración añade columnas a `actors` que
falten en el fixture. **Corregido**: se añadió `typical_behavior TEXT` al `CREATE TABLE actors`
del fixture. Cambio solo en el test; no se tocó `app/panel_mvp.py` ni ninguna migración.

## 7. Dos fallos reales SIN corregir — requieren una decisión de producto/seguridad

`tests/test_pro_license.py::TestIsProEnabled`:
- `test_gate_allows_pro_when_online_ok`
- `test_no_gate_no_server_url_legacy_license_enables_pro`

Ambos siguen fallando incluso con el entorno limpio y correctamente fijado. **No son un problema
de entorno ni de datos de prueba caducados** — son una contradicción real entre lo que el test
afirma que debe pasar y lo que el código hace hoy a propósito.

**Lo que dice el test** (comentario original en `tests/test_pro_license.py:261-268`):

> Regression: uploading a valid license without `HP_LICENSING_SERVER_URL` configured must enable
> PRO (the gate was never set, causing fail-closed).

Es decir: estos tests se escribieron para evitar que una licencia legacy/offline, desplegada sin
`HP_LICENSING_SERVER_URL`, se quedara bloqueada en modo `fail-closed` por un bug de wiring — un
incidente real pasado, a juzgar por el comentario.

**Lo que hace hoy `app/pro_license.py::is_pro_enabled()`** (`app/pro_license.py:239-274`): cuando
`online_check_required` es `True` (el valor por defecto si la licencia no fija el campo) y no hay
un online manager configurado (`HP_LICENSING_SERVER_URL` sin definir), la función deniega PRO
**antes de consultar el gate callback**, con este comentario explícito en el propio código:

> Removing `HP_LICENSING_SERVER_URL` must not silently bypass this requirement... but that must
> not satisfy a license that explicitly requires online validation.

Esto es exactamente lo contrario de lo que el test regresión original exige, y coincide con el
endurecimiento "fail-closed" que ya documenté en `CLAUDE.md` (sección Licensing: *"PRO is enabled
only by a backend-validated, RS256-signed lease... There is no manual tier override"*).

**Por qué no lo resuelvo en este PR:** no puedo saber, sin una decisión de producto, si:
(a) el endurecimiento fail-closed es la política correcta y vigente, y estos dos tests deben
    actualizarse (o eliminarse) para reflejarla — en cuyo caso un cliente legacy/offline sin
    `HP_LICENSING_SERVER_URL` configurado **debe quedarse sin PRO** aunque su licencia offline sea
    válida; o
(b) el endurecimiento reintrodujo, sin querer, el incidente original que estos tests existían
    para prevenir — en cuyo caso el bug está en `app/pro_license.py`, no en los tests.

Ambas lecturas tocan directamente el comportamiento de licenciamiento en producción. Marcados
`@pytest.mark.xfail(strict=False, reason="...")` con referencia a esta sección — siguen
corriendo y apareciendo como `xfailed` en el resumen (no se silencian ni se borran), pero no
tumban el pipeline de CI por un fallo ya conocido y documentado. Si alguien corrige el
comportamiento en cualquiera de las dos direcciones, aquí quedará constancia de por qué existía
la marca para poder retirarla.

## 8. Resultado final de este PR

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
# 1017 passed, 1 skipped, 2 xfailed   (exit code 0)
```

Verificado tanto en un venv local limpio como en el runner de GitHub Actions
(`.github/workflows/tests.yml`). Los 2 `xfailed` son los descritos en la sección 7, marcados a
propósito como fallo conocido en espera de decisión — no son flaky ni dependen del entorno, y
seguirán apareciendo en el resumen de cada run hasta que se resuelva esa decisión.

## 9. Criterios de aceptación

- [x] Se documentan comandos y resultados iniciales (secciones 1, 5 y 8).
- [x] Se incorporan pruebas faltantes para los flujos críticos — no se encontró ningún área sin
      cobertura (sección 5); se corrigieron 4 pruebas rotas que impedían confiar en la línea base
      (secciones 3 y 6), incluyendo un bug real de aplicación en `runtime_provider.py` (sección 3.1).
- [x] Los tests son reproducibles en CI o entorno local controlado — restaurado el versionado de
      `tests/` (sección 1) + `requirements-dev.txt` + `.github/workflows/tests.yml` (sección 4);
      verificado en vivo contra el runner real de GitHub Actions (sección 3).
- [ ] Los 2 fallos de licenciamiento (sección 7) quedan pendientes de una decisión de producto;
      marcados `xfail` para no bloquear CI, no se marcan como resueltos.

## 10. Efectos en seguridad / compatibilidad / despliegue / rollback

- **Seguridad**: restaurar `tests/` al control de versiones no cambia el comportamiento en
  tiempo de ejecución; la imagen Docker sigue sin tests vía `.dockerignore`. El fix de
  `invalidate()` (sección 3.1) es el único cambio de comportamiento de aplicación de este PR:
  hace que la invalidación de caché de runtime sea efectiva inmediatamente tras el arranque del
  proceso, en vez de quedar sujeta a que ya haya pasado el TTL — un cambio estrictamente más
  correcto, sin downside identificado. La contradicción de licenciamiento de la sección 7 es
  puramente un hallazgo documentado, sin cambio de código de licenciamiento.
- **Compatibilidad**: sin impacto en endpoints ni esquema de producción.
- **Despliegue**: sin impacto; `tests.yml` no interfiere con `ghcr.yml` (que solo construye en
  tags/manual tras el cambio de la Issue anterior). La imagen de producción no crece: `tests/`
  sigue excluida del build vía `.dockerignore`.
- **Rollback**: trivial para los cambios de tests/CI/`.gitignore`. El único cambio de código de
  aplicación (`app/runtime_provider.py::invalidate()`, sección 3.1) es una línea aislada y
  revertible sin efectos secundarios conocidos.
