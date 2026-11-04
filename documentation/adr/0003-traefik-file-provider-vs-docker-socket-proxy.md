# ADR 0003 — Descubrimiento de Traefik: File Provider por defecto, Docker Socket Proxy solo como contingencia documentada

**Estado**: Propuesta (NOC-004) — criterio vinculante para NOC-007, NOC-008 y NOC-009.

## Contexto

`compose/docker-compose.prod.yml` monta `/var/run/docker.sock:/var/run/docker.sock:ro` en el
contenedor de Traefik para que su `providers.docker` descubra servicios dinámicamente
(documentado como riesgo R1 en `documentation/NOC-001-AUDITORIA-ARQUITECTURA.md`, y ya cubierto
por NOC-008/NOC-009 en el backlog). Aunque el montaje es de solo lectura, cualquier acceso al
socket Docker desde un contenedor — incluso "read-only" a nivel de bind mount — expone de facto
la API completa de Docker (el socket no distingue operaciones de lectura de escritura a ese
nivel); comprometer Traefik equivaldría a comprometer el host.

El backlog ya fija exactamente esta decisión como una Issue con un ADR explícito en su propio
criterio de aceptación (NOC-009: *"ADR explica cuándo se permitiría Socket Proxy"*). Esta ADR
cumple ese criterio por adelantado, para que NOC-007/008/009 tengan un criterio ya decidido en
vez de tener que decidirlo durante la implementación.

## Decisión

**Por defecto: Traefik File Provider**, con configuración estática y dinámica basada en
archivos para el router HTTPS público, el servicio `app`, el HTTP challenge de ACME y
exactamente las rutas necesarias (alcance literal de NOC-007). `providers.docker` se desactiva
en el despliegue gestionado; el socket Docker **no se monta** en Traefik (NOC-008).

**Docker Socket Proxy es una contingencia documentada, no una alternativa de igual peso**: solo
se evaluaría si, en la práctica, el descubrimiento dinámico resultase imprescindible (p. ej. el
Deployer necesita que Traefik reaccione a contenedores efímeros sin regenerar archivos de
config). Si llegara a implantarse, debe cumplir — sin excepción — los tres criterios que NOC-009
ya fija como criterios de aceptación:

1. Métodos y endpoints mínimos expuestos (solo lectura de lo estrictamente necesario para
   enrutar; `POST`/`EXEC` y cualquier operación de escritura bloqueados).
2. Red privada, **sin puerto publicado** en ninguna interfaz.
3. Tests negativos que demuestren que las operaciones bloqueadas efectivamente fallan.

Mientras File Provider cubra el caso — y hoy no hay ninguna señal en el backlog de que no lo
haga — **no se implanta** Socket Proxy. No es un "por ahora", es la posición por defecto hasta
que una necesidad concreta y documentada diga lo contrario.

## Alternativas consideradas

1. **Mantener `providers.docker` con el socket montado (estado actual)**. Descartada: es
   exactamente el riesgo que NOC-007/008 existen para eliminar; incompatible con instancias
   gestionadas donde Traefik no debería tener ninguna vía de escalar al host.
2. **Docker Socket Proxy como reemplazo directo, sin pasar por File Provider**. Descartada: sigue
   dependiendo de un proceso con visibilidad sobre el daemon Docker (aunque sea un proxy
   restringido) cuando File Provider no necesita ninguna. Más superficie, sin beneficio si el
   caso de uso no lo exige.
3. **Traefik Kubernetes/Consul provider**. Fuera de alcance: el objetivo (ADR 0001) es Docker
   Compose por instancia, no un orquestador con su propio plano de descubrimiento.

## Consecuencias / Rollback

- NOC-007 debe entregar una configuración de File Provider que cubra el 100% de lo que hoy
  provee `providers.docker` (criterio de NOC-007: *"la API señuelo responde en dominio y HTTPS
  esperados"*) antes de que NOC-008 retire el socket — en ese orden, no al revés.
- NOC-008 debe dejar, además de retirar el montaje, una comprobación verificable (test o check)
  que detecte si el socket se reintroduce — su propio criterio de aceptación ya lo exige.
- Si en el futuro se decide SÍ implantar Socket Proxy bajo los criterios de la sección
  "Decisión", esta ADR no necesita revertirse — ya contempla esa vía como contingencia válida,
  siempre que cumpla las tres condiciones. Lo que no es aceptable, bajo ninguna circunstancia, es
  volver a montar `/var/run/docker.sock` directamente en Traefik.
