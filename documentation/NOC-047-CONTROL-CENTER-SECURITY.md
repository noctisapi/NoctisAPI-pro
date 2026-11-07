# NOC-047 — Seguridad del Control Center

## Contrato implementado

- Las rutas `/control-center/*` quedan clasificadas en la matriz RBAC del
  servidor y, por tanto, requieren una sesión autenticada; una ruta nueva no
  clasificada sigue teniendo política `OWNER` (fail closed).
- Las lecturas requieren el rol mínimo de la matriz.
- Las mutaciones requieren rol `ADMIN` o superior y una aserción `MFA` o
  `SSO+MFA`. Una sesión normal no basta.
- La auditoría se construye con actor, acción y entidad; los campos de
  credenciales se redactan recursivamente antes de persistir.
- El contrato no expone secretos administrativos ni credenciales globales a
  frontend.

## Dependencias externas pospuestas

La integración con un proveedor SSO, la validación criptográfica de sus
claims, el enrolamiento MFA y una prueba end-to-end detrás de un proxy de
identidad requieren configuración/infraestructura externa. Se posponen hasta
la fase de despliegue. El código local ya separa el nivel de autenticación
(`session`, `sso`, `mfa`, `sso_mfa`) para que el adaptador no relaje las reglas.

## Verificación

```text
pytest -q tests/test_control_center_security.py
```
