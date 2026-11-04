# ADR 0002 — Separación de consola y API pública

**Estado**: Propuesta (NOC-004) — fija el rumbo para NOC-011, NOC-016 a NOC-022, no implementa nada.

## Contexto

Hoy, API pública (`app/honeypot_public.py`, decoy) y consola de administración
(`app/panel_mvp.py`, real) corren en procesos distintos pero comparten la red *bridge* por
defecto de Docker Compose (sin `networks:` explícito — ver
`documentation/NOC-001-AUDITORIA-ARQUITECTURA.md`, riesgo R2) y la consola se alcanza vía túnel
SSH manual a `127.0.0.1:9001`. La autenticación de la consola es un único token compartido
(`HP_PANEL_TOKEN`) sin usuarios individuales, sesiones por persona ni RBAC
(`app/panel_mvp.py:95-130, 556-575`; riesgo R3 del mismo informe).

El backlog ya fija el objetivo con detalle operativo concreto en varias Issues:
NOC-011 (redes Docker separadas), NOC-016 (Cloudflare Tunnel por instalación, sin publicar el
puerto admin), NOC-017 (Access y validación de identidad en origen), NOC-018 (identidad de
usuarios y sesiones individuales), NOC-019 (RBAC backend en toda la consola), NOC-020 (gestión
de miembros y accesos), NOC-021 (auditoría de acciones administrativas), NOC-022 (auditoría de
seguridad del panel + E2E de acceso).

## Decisión

1. **Separación de red**: la API pública (decoy), la consola, el servicio `migrate` y la base de
   datos viven en redes Docker distintas con bindings explícitos — ningún puerto salvo los
   estrictamente públicos escucha en la interfaz pública (criterio de aceptación de NOC-011).
2. **La consola deja de depender de SSH**: se alcanza exclusivamente vía Cloudflare Tunnel
   (`cloudflared`) con credenciales aisladas por instalación, y Cloudflare Access valida
   identidad en el borde antes de llegar al panel (NOC-016, NOC-017). El puerto admin **no se
   publica en ningún interfaz**, ni siquiera loopback-con-túnel-SSH como hoy — sin el túnel
   levantado no existe ninguna ruta pública alternativa (criterio explícito de NOC-016).
3. **Identidad real detrás del borde**: el token único compartido se sustituye por usuarios
   individuales con sesión propia (NOC-018), RBAC aplicado en el backend de toda la consola, no
   solo en la UI (NOC-019), gestión de miembros/accesos (NOC-020) y auditoría de toda acción
   administrativa (NOC-021).
4. Cloudflare Access es una capa adicional de identidad **en el borde**, no un sustituto de la
   identidad de aplicación de (3) — ambas capas son necesarias: Access decide quién llega al
   túnel, RBAC decide qué puede hacer una vez dentro.

## Alternativas consideradas

1. **Mantener SSH + token compartido, solo segmentar redes**. Descartada: resuelve el aislamiento
   de red (parte de NOC-011) pero no el riesgo ya documentado R3 (sin usuarios individuales, sin
   límite de intentos de login, sin auditoría) — y no escala a un Control Center con múltiples
   operadores por cliente.
2. **VPN tipo WireGuard en vez de Cloudflare Tunnel**. Descartada por alcance: añadiría gestión
   de infraestructura de VPN por cliente que el Deployer tendría que automatizar igual que un
   túnel, sin beneficio claro sobre Cloudflare Tunnel/Access, que ya cubre identidad en el borde
   sin publicar ningún puerto.
3. **OAuth/SSO de aplicación sin capa de borde**. Descartada como sustituto (no como complemento):
   seguiría exponiendo el puerto admin públicamente salvo que se combine con un túnel — el
   criterio de NOC-016 de "sin el túnel no hay ruta pública alternativa" exige la capa de borde.

## Consecuencias / Rollback

- Mientras NOC-016 a NOC-022 no estén completas, el acceso actual por SSH sigue siendo el único
  camino soportado — esta ADR no cambia nada por sí misma, solo fija el destino.
- El orden de dependencias ya registrado en las propias Issues debe respetarse: NOC-016 depende
  de NOC-011 y NOC-015; no tiene sentido montar el túnel antes de tener la red separada y la
  batería adversarial del reverse proxy.
- Rollback por fases: cada pieza (red separada, túnel, identidad/RBAC) es reversible de forma
  independiente mientras el SSH tunnel siga disponible como camino de emergencia hasta que NOC-022
  (auditoría de seguridad del panel + E2E) confirme que la nueva ruta es equivalente o superior.
