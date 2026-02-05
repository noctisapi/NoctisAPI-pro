AUTOMATIONS (comportamiento automatico)

Este documento describe lo que el sistema hace de forma automatica en dos areas:
sesiones (agrupacion de eventos) y recompute de campaigns. La fuente de verdad
es el codigo en `app/honeypot_public.py` y `app/panel_mvp.py`.

Sessions: como se agrupan los eventos

1) Identidad de actor
- El actor_id se calcula con `sha256(ip + '|' + user-agent + '|' + HP_SEED)`.
- Por defecto, el actor se mantiene estable por IP + User-Agent (y el seed).
- El token no afecta al actor_id.

2) Fingerprint de sesion
- Para decidir si reusar una sesion, el sistema crea un fingerprint:
  `ip|user-agent|token`.
- El token solo se toma del header `Authorization: Bearer ...`.
- Si no hay token, el fingerprint es solo ip + user-agent.

3) Reutilizar o crear nueva sesion
- Se busca la ultima sesion del actor con el mismo fingerprint.
- Se compara el `ended_at` de esa sesion con el timestamp actual.
- Si el gap es <= 15 minutos, se reutiliza esa sesion.
- Si no, se crea una nueva sesion con `session_id = secrets.token_hex(8)`.
- En ambos casos se actualiza `ended_at` al tiempo actual.

4) Puntos y stages dentro de la sesion
- Cada evento asigna puntos (segun el tipo) y actualiza el score del actor.
- Si se reutiliza la sesion, se aplica un multiplicador de puntos x1.5.
- Se calcula `stage_before` y `stage_after` en base al score.
- `stage_max` de la sesion se actualiza si el nuevo stage es mayor.

5) Persistencia en base de datos
- Cada request genera un registro en `events`.
- Cada request genera un `session_step` con:
  seq incremental, timestamp, method, path, headers/query/body, status,
  stage_before y stage_after.
- Si ocurre un error en esta parte, el API no falla (solo se loguea warning).

Campaigns: como funciona el recompute

Endpoint: `POST /dashboard/campaigns/recompute` en `app/panel_mvp.py`.

1) Alcance y limpieza
- El recompute borra todo lo existente en `campaigns` y `campaign_actor_links`.
- Solo analiza los ultimos N actores por `last_seen` (configurable).

2) Features por actor
- Para cada actor, toma hasta N sesiones recientes (configurable).
- De cada sesion, usa los `session_steps` para extraer:
  - Paths normalizados (lowercase, sin querystring).
  - N-grams de paths (secuencias de 3 y 2), top 12.
  - Paths individuales, top 10.
  - Stage flow (secuencia S0-S1-... sin duplicados consecutivos).
  - Stage counts (frecuencia de stages).
  - Timing bucket segun mediana de delta entre steps:
    burst (<1s), steady (<5s), slow (>=5s), unknown (sin datos).
  - Errores (HTTP >= 400), top 3.
- Si no hay pasos, usa los ultimos 100 paths de `events` como fallback.
- El User-Agent se guarda solo como metadato (no entra en la similitud).
- Las features se cachean en `actor_fingerprints` y se reutilizan si:
  - el `updated_at` cacheado >= `actors.last_seen`
  - y la configuracion usada es la misma

3) Criterios de agrupacion
- Min features por actor: 4.
- Min intersection: 3.
- Min Jaccard: 0.4.
- La agrupacion es greedy: se toma un actor como seed y se agregan otros
  que cumplen los umbrales con ese seed.
- Solo se crean campaigns con tamaño >= 2.

4) Resultado
- Se inserta un campaign con summary (seed, paths dominantes, stage flow,
  stage counts, timing, UA, representative_session_id).
- Se insertan links por actor con reasons:
  shared_paths, shared_stage_flow, shared_timing, shared_errors, shared_ua.

Notas
- Parametros configurables via env:
  - `HP_CAMPAIGN_MIN_FEATURES` (default 4)
  - `HP_CAMPAIGN_MIN_INTERSECTION` (default 3)
  - `HP_CAMPAIGN_MIN_JACCARD` (default 0.4)
  - `HP_CAMPAIGN_MAX_SESSIONS` (default 5)
  - `HP_CAMPAIGN_PATH_NGRAM_TOP_K` (default 12)
  - `HP_CAMPAIGN_PATH_TOP_K` (default 10)
  - `HP_CAMPAIGN_ACTOR_LIMIT` (default 200)
- El recompute se ejecuta como job en background y guarda metricas en
  `campaign_jobs`. El estado se puede consultar en
  `/dashboard/campaigns/recompute/status`.
