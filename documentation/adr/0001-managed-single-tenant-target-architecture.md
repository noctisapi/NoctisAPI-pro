# ADR 0001 — Arquitectura objetivo: Managed, instancia dedicada por cliente

**Estado**: Propuesta (NOC-004) — fija el rumbo para NOC-005 en adelante, no implementa nada.

## Contexto

NoctisAPI PRO es hoy un producto autoalojado: un operador clona el repo, rellena `.env.prod` a
mano y levanta `compose/docker-compose.prod.yml` en una VPS que administra él mismo (ver
auditoría completa en `documentation/NOC-001-AUDITORIA-ARQUITECTURA.md`). El backlog actual
(Issues NOC-005 a NOC-059) describe, de forma consistente por sus etiquetas `area:*`, un
producto distinto al que se está migrando: un servicio **Managed**, con un **Control Center**
interno (NOC-046 a NOC-053) que gestiona clientes, suscripciones y despliegues; un **Deployer**
(NOC-031 a NOC-038) que automatiza la provisión de infraestructura por cliente con Terraform +
cloud-init; licenciamiento basado en **entitlements** en vez de activación visible por el
cliente (NOC-039 a NOC-045); y una fase de **release** (NOC-054 a NOC-059) que exige auditoría
de seguridad independiente y un piloto real antes de cerrar "Managed PRO 1.0".

Esta ADR fija la forma concreta de ese objetivo — **single-tenant por instancia** — antes de que
NOC-005 en adelante empiece a tocar infraestructura real.

## Decisión

Cada cliente obtiene **su propia instancia dedicada** (su propia VPS/stack Docker, su propia
base de datos SQLite, su propio dominio señuelo), provisionada y administrada por el Deployer,
no una instancia multi-tenant compartida. El Control Center es un **plano de control separado**
— un sistema y modelo de datos propio (Customer, Subscription, Deployment, Domain, Job, Version,
InfraCost, AuditLog — NOC-046) que **orquesta** instancias dedicadas desde fuera, sin que la base
de datos del honeypot de un cliente sea nunca accesible desde la de otro ni desde el propio
Control Center de forma directa (criterio de aceptación explícito de NOC-046: *"sin
centralización de ataques"*).

La migración es **incremental, no un corte**: el compose autoalojado actual
(`compose/docker-compose.prod.yml`) sigue funcionando en paralelo durante toda la migración — es
un requisito explícito de NOC-023 (*"mantener la variante actual durante migración"*), no una
preferencia de esta ADR.

## Arquitectura actual vs objetivo

| | Actual | Objetivo (Managed) |
|---|---|---|
| Aprovisionamiento | Manual (`ops/vps/install.sh`, SSH) | Automatizado por el Deployer (Terraform + cloud-init, NOC-032/033) |
| Aislamiento entre clientes | N/A (un cliente = un operador = una instancia) | Instancia dedicada por cliente, sin estado compartido |
| Gestión/visibilidad | Ninguna fuera de la propia instancia | Control Center: inventario de instancias/dominios, estado de suscripción, costes (NOC-046/049/052/053) |
| Licenciamiento | Lease RS256 validado contra servidor de licencias externo | Entitlements evaluados desde config desplegada por el operador, sin activación visible del cliente (NOC-041) |
| Ciclo de vida | Manual (`docker compose pull && up -d`) | Automatizado: upgrade/rollback versionado, backup/restore, teardown controlado (NOC-029/036/037) |
| Ruta autoalojada | Es la única | Se conserva como variante soportada en paralelo |

## Alternativas consideradas

1. **Multi-tenant compartido** (un único cluster/DB sirviendo a varios clientes, aislados por
   fila/esquema). Descartada: el producto es un honeypot — el "dato" de cada cliente es tráfico
   de atacantes reales contra su dominio señuelo; mezclar clientes en infraestructura compartida
   amplía el blast radius de cualquier compromiso y complica la atribución forense por cliente.
   También contradice directamente el criterio "sin centralización de ataques" de NOC-046.
2. **Migración "big bang"** (sustituir el compose autoalojado de golpe). Descartada: NOC-023 la
   prohíbe explícitamente: la variante actual debe seguir funcionando durante toda la migración.
3. **Sin Control Center, gestión ad-hoc por cliente**. Descartada: no escala más allá de un
   puñado de clientes y es precisamente lo que NOC-046-053 buscan resolver.

## Consecuencias / Rollback

- Todo el trabajo de NOC-005 en adelante debe mantener el compose autoalojado funcional; ninguna
  Issue de esta migración puede romperlo sin una Issue de migración/deprecation explícita y
  autorizada aparte.
- El Control Center y el Deployer son sistemas nuevos, no una reescritura de `app/`; su fracaso
  o abandono no debería dejar las instancias ya desplegadas en un estado inconsistente, porque
  cada instancia sigue siendo un stack Docker autocontenible.
- Rollback de esta decisión: si "Managed" se abandona, las instancias dedicadas ya desplegadas
  siguen siendo instancias autoalojadas válidas sin cambios — no hay migración de datos que
  revertir, porque nunca hubo infraestructura compartida entre clientes.
