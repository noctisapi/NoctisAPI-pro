# NOC-004 — Mapa de migración, dependencias y riesgos

Issue: [#7 NOC-004 — Documentar decisiones y mapa de migración](https://github.com/0x-unkwn0wn/noctisapi-pro/issues/7)
Depende de: NOC-001 (completada, en `main`).

Este documento complementa las 3 ADRs (`documentation/adr/0001`, `0002`, `0003`) con el mapa de
fases del backlog completo (NOC-005 a NOC-059, 55 Issues abiertas a fecha de este informe) y un
registro de riesgos. Las fases y prioridades usadas aquí son las etiquetas `area:*` y `P0`/`P1`
reales de cada Issue en GitHub — no son una reinterpretación.

## 1. Arquitectura actual vs objetivo (resumen)

Ver ADR 0001 para el detalle completo. En corto: de una instancia autoalojada administrada a
mano, a una instancia dedicada por cliente provisionada por un Deployer y gestionada desde un
Control Center separado, con licenciamiento por entitlements y una consola con identidad y RBAC
reales — manteniendo la ruta autoalojada actual en paralelo durante toda la migración.

## 2. Fases del backlog (por `area:*`)

| Fase | Issues | Prioridad | Objetivo de la fase |
|---|---|---|---|
| 0. Fundacional (esta y las 3 previas) | NOC-001 a NOC-004 | — | Auditoría, baseline de tests, CI+staging, esta ADR |
| 1. Auditoría de superficie | NOC-005 | — | Matriz de rutas reales vs señuelo, antes de tocar red/acceso |
| 2. Seguridad del borde | NOC-006 a NOC-015 | P0 | Traefik pinned + File Provider (ADR 0003), aislar redes, endurecer proxies/contenedores/TLS, batería adversarial |
| 3. Consola | NOC-016 a NOC-022 | P0 | Cloudflare Tunnel, identidad real, RBAC, auditoría, E2E de acceso (ADR 0002) |
| 4. Operaciones de instancia | NOC-023 a NOC-030 | P0 | Compose Managed, dominio por cliente, secretos estandarizados, backups/restore, monitorización, upgrade/rollback, runbooks |
| 5. Deployer | NOC-031 a NOC-038 | P1 | Automatización por cliente: manifiesto, Terraform, cloud-init, túnel/DNS, CLI, operaciones, teardown, protección de estado/secretos |
| 6. Licenciamiento Managed | NOC-039 a NOC-045 | P1 | Inventario de checks PRO, entitlements, Managed Mode sin activación visible, compatibilidad self-hosted, estados comerciales, billing, cambios de plan |
| 7. Control Center | NOC-046 a NOC-053 | P1 | Modelo de datos separado, auth fuerte, UI de clientes/instancias/despliegues/suscripciones, runner de jobs, control de costes |
| 8. Release | NOC-054 a NOC-059 | P0 | E2E de contratación a entrega, auditoría de seguridad independiente, docs comerciales/soporte/privacidad, pruebas de restauración/fallo/baja, piloto real, cierre de "Managed PRO 1.0" |

Dependencias explícitas ya verificadas en el cuerpo de las Issues (no exhaustivo — cada Issue
declara su propio campo "Dependencias"; estas son las que fundamentan directamente las 3 ADRs):

```
NOC-001 → NOC-002 → NOC-003 → NOC-004 (completadas/en curso)
NOC-001 → NOC-005 → NOC-011 (aislamiento de red)
NOC-002, NOC-006 → NOC-007 (File Provider) → NOC-008 (retirar socket) → NOC-009 (ADR Socket Proxy, ya cumplido por adelantado en esta Issue)
NOC-011, NOC-015 → NOC-016 (Cloudflare Tunnel) → NOC-017..NOC-022 (identidad/RBAC/auditoría consola)
NOC-015, NOC-022 → NOC-023 (Compose Managed)
NOC-039, NOC-040 → NOC-041 (Managed Mode)
NOC-031, NOC-040, NOC-043 → NOC-046 (modelo de datos Control Center)
```

La fase 8 (Release) depende transitivamente de todas las anteriores — es la puerta de salida,
no una fase paralela.

## 3. Registro de riesgos

| # | Riesgo | Fase afectada | Mitigación ya prevista en el backlog |
|---|---|---|---|
| M1 | Migrar sin mantener la ruta autoalojada rompe clientes existentes que no son "Managed" | 1-7 | NOC-023 exige explícitamente mantener la variante actual durante la migración (ver ADR 0001) |
| M2 | Retirar el socket Docker de Traefik (NOC-008) antes de que File Provider cubra el 100% de las rutas (NOC-007) deja el despliegue sin enrutar | 2 | Orden de dependencias ya fijado: NOC-008 depende de NOC-007 (ver ADR 0003) |
| M3 | Introducir Cloudflare Tunnel/Access sin que la consola tenga aún identidad/RBAC reales deja el backend protegido solo por la capa de borde | 3 | NOC-016 depende de NOC-011 y NOC-015, pero NOC-018/019 (identidad/RBAC) deben completarse antes de retirar el camino SSH como única capa (ver ADR 0002) |
| M4 | "Managed Mode sin activación visible" (NOC-041) se implementa como un bypass universal de licencia | 6 | Prohibido explícitamente en el propio criterio de aceptación de NOC-041 ("no introducir LICENSE_DISABLED universal") |
| M5 | El Control Center termina centralizando datos de ataque de todos los clientes en un único punto de fallo | 7 | Criterio de aceptación explícito de NOC-046: "sin centralización de ataques" — el Control Center es un sistema separado (ver ADR 0001) |
| M6 | Se declara "Managed PRO 1.0" sin validar con un cliente real ni con auditoría externa | 8 | NOC-058 (piloto autorizado) y NOC-055 (auditoría de seguridad independiente) son requisitos previos explícitos a NOC-059 |
| M7 | Las Issues de esta migración se implementan en una rama que depende de otra Issue aún sin fusionar | todas | Política de PRs apiladas ya documentada en `CLAUDE.md` ("Development workflow") |

## 4. Restricciones (duplicadas en `CLAUDE.md`)

Las restricciones vinculantes de esta ADR están también en `CLAUDE.md`, sección "Target
architecture constraints (NOC-004)", para que cualquier Issue futura las tenga presentes sin
tener que leer las 3 ADRs completas.

## 5. Pruebas

Esta Issue es puramente documental — no se ha tocado ningún archivo de `app/`, `honey_licensing/`
ni configuración de despliegue, ni ningún archivo de `tests/`.

Esta rama parte de `main`, donde `tests/` todavía no está versionado (eso es exactamente lo que
NOC-002/PR #63 corrige, aún sin fusionar) — así que no hay una baseline de tests completa que
ejecutar aquí sin antes fusionar #63. No se reclama ningún resultado de `pytest` como evidencia
de esta Issue; la baseline real ya está establecida y documentada en
`documentation/NOC-002-LINEA-BASE-PRUEBAS.md` y se aplicará a `main` cuando se fusione.

## 6. Criterios de aceptación

- [x] La arquitectura objetivo y la actual están diferenciadas — tabla en ADR 0001 y sección 1.
- [x] Las decisiones incluyen alternativas y rollback — sección "Alternativas consideradas" /
      "Consecuencias y Rollback" en cada una de las 3 ADRs.
- [x] Las restricciones figuran en docs y en `CLAUDE.md` — ADRs + este mapa en
      `documentation/`, resumen vinculante en `CLAUDE.md`.
