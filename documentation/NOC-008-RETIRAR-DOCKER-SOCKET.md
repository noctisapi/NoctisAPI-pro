# NOC-008 — Eliminar el montaje del socket Docker de Traefik

Issue: [#11 NOC-008 — Eliminar el montaje del socket Docker de Traefik](https://github.com/noctisapi/NoctisAPI-pro/issues/11)
Depende de: NOC-007 (PR #68, pendiente de fusión — esta rama parte de
`noc-007-traefik-file-provider`, no de `main`).

## Objetivo

Suprimir la capacidad de Traefik de hablar con el daemon Docker.

## 0. Corrección previa en NOC-007

Al construir esta Issue encontré que el PR de NOC-007 ya había quitado accidentalmente
`/var/run/docker.sock` del servicio `traefik` (un efecto secundario de reescribir todo el bloque
`volumes:` al migrar a File Provider), contradiciendo lo que su propio informe decía
explícitamente ("sigue montado en este PR a propósito"). Lo corregí primero en la rama de
NOC-007 (commit `fix(noc-007): restore the docker.sock mount I accidentally dropped`, PR #68 ya
en verde con la corrección) para que el límite entre ambas Issues sea real, no accidental, antes
de hacer aquí la retirada definitiva con su propia verificación.

## 1. Cambio

`compose/docker-compose.prod.yml`: se quita la línea
`- /var/run/docker.sock:/var/run/docker.sock:ro` de `traefik.volumes`. Es la única línea que lo
montaba en todo el repo:

```bash
grep -rln "docker.sock" compose/ app/
# (sin resultados)
```

Ningún otro servicio de `compose/docker-compose.prod.yml` ni de `compose/docker-compose.dev.yml`
monta el socket, y ningún otro proxy HTTP existe en el repo — Traefik es el único.

## 2. Comprobación verificable que detectaría una reintroducción

Nuevo `tests/test_compose_security.py` (3 tests, sin necesitar Docker — parsea el YAML
directamente):

- `test_no_service_mounts_docker_socket`: falla si **cualquier** servicio de
  `docker-compose.prod.yml` vuelve a montar `docker.sock`.
- `test_traefik_does_not_use_docker_provider`: falla si el `command` de `traefik` vuelve a
  incluir `providers.docker`, y falla también si `providers.file` desaparece.
- `test_dev_compose_never_mounted_docker_socket_either`: mismo chequeo sobre el compose de
  desarrollo (que nunca tuvo Traefik, pero lo deja comprobado explícitamente).

Verificado que el test detecta de verdad la reintroducción, no solo que pasa en verde hoy:

```bash
# se reintrodujo la línea del socket manualmente
python -m pytest tests/test_compose_security.py -v
# FAILED test_no_service_mounts_docker_socket -- ['traefik']
# (se revirtió la reintroducción antes de continuar)
```

`requirements-dev.txt` ahora fija `pyyaml==6.0.3` explícitamente — ya estaba disponible como
dependencia transitiva, pero fijarla evita que este test dependa de una cadena de dependencias
no documentada.

## 3. Pruebas

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
# 1020 passed, 1 skipped, 2 xfailed   (1017 + los 3 tests nuevos de esta Issue)
```

## 4. Criterios de aceptación

- [x] El Compose gestionado no monta `docker.sock` en Traefik — sección 1.
- [x] Traefik sigue enrutando mediante File Provider — sin cambios respecto a NOC-007; el test
      `test_traefik_does_not_use_docker_provider` lo deja comprobado de forma permanente.
- [x] Hay test o comprobación verificable que detectaría reintroducción del socket — sección 2,
      verificado activamente (no solo escrito).

## 5. Efectos en seguridad / compatibilidad / despliegue / rollback

- **Seguridad**: mejora directa — Traefik ya no tiene ninguna vía de acceso al socket Docker del
  host. Compromiso de Traefik ya no implica compromiso potencial del daemon Docker/host.
- **Compatibilidad**: sin impacto — el socket ya estaba sin uso desde NOC-007 (providers.docker
  desactivado); esta Issue solo retira el acceso físico, ya comprobado como innecesario.
- **Despliegue**: ninguno — es la retirada de una línea de un bind mount, no requiere ninguna
  migración de datos ni reinicio especial más allá del `up -d` habitual.
- **Rollback**: trivial, una línea — revertir este commit vuelve a montar el socket (aunque no
  habría ninguna razón funcional para hacerlo, ya que Traefik no lo usa desde NOC-007).
