# NOC-049 — Inventario de instancias y dominios

## Alcance implementado

- Proyección local de deployments con cliente, proveedor, región, versión,
  dominios API/consola, estado y última observación.
- Filtros por alcance de cliente y estado.
- Indicador explícito `stale` cuando la última observación falta o supera el
  umbral configurado.
- Función `record_observation` preparada para un adaptador de proveedor, sin
  realizar llamadas cloud durante esta etapa.

## Pospuesto

La lectura real de Hetzner/Cloudflare/Tunnel, reconciliación periódica y
pruebas con recursos desplegados quedan pospuestas. Hasta entonces, el panel
debe mostrar que un dato es stale y no presentarlo como salud confirmada.

```text
pytest -q tests/test_control_center_inventory.py
```
