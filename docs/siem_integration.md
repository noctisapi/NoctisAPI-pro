# SIEM Integration Guide — NoctisAPI Honeypot

This document describes how to route NoctisAPI security events to a Security Information and Event Management (SIEM) platform such as Splunk, Elastic Security, or Graylog.

---

## Architecture Overview

```
NoctisAPI honeypot_public.py
  └─ log_all_requests middleware
       └─ siem_logger.emit_event()
            └─ dispatcher (background thread, queue-based)
                 ├─ stdout  (always on)  ──► Docker log driver ──► Filebeat / Fluentbit
                 ├─ file    (optional)   ──► /var/log/noctisapi/events.json
                 └─ syslog  (optional)   ──► UDP/TCP ──► Graylog / Splunk HEC / rsyslog
```

Events are emitted as newline-delimited JSON (NDJSON). The dispatcher runs in a dedicated daemon thread with a bounded queue (10 000 items); if the queue is full the event is silently dropped rather than blocking the API request path.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `LOG_OUTPUT` | `stdout` | Comma-separated list of outputs: `stdout`, `file`, `syslog` |
| `LOG_FILE_PATH` | `/var/log/noctisapi/events.json` | Absolute path for the file output. Parent directory is created automatically. |
| `SYSLOG_ENABLED` | `false` | Set to `1`, `true`, or `yes` to enable syslog forwarding. |
| `SYSLOG_HOST` | _(empty)_ | Hostname or IP of the syslog receiver. Required when `SYSLOG_ENABLED=true`. |
| `SYSLOG_PORT` | `514` | UDP or TCP port of the syslog receiver. |
| `SYSLOG_PROTOCOL` | `udp` | Transport: `udp` or `tcp`. |
| `SYSLOG_FACILITY` | `local0` | RFC5424 facility name. Valid values: `kern user mail daemon auth syslog lpr news uucp cron local0`–`local7`. |

### Example .env.prod snippet

```env
LOG_OUTPUT=stdout,file
LOG_FILE_PATH=/var/log/noctisapi/events.json
SYSLOG_ENABLED=true
SYSLOG_HOST=siem.internal.example.com
SYSLOG_PORT=5140
SYSLOG_PROTOCOL=udp
SYSLOG_FACILITY=local0
```

---

## Event Schema

Every security event is a JSON object with the following fields.

| Field | Type | Description |
|---|---|---|
| `timestamp` | string (ISO 8601 UTC) | Event time, e.g. `2026-03-12T14:23:01Z` |
| `event_type` | string | `api_attack` (HTTP 4xx/5xx) or `api_interaction` (HTTP 2xx/3xx) |
| `source_ip` | string | Attacker's public IP address (after X-Forwarded-For resolution) |
| `method` | string | HTTP method in uppercase, e.g. `GET`, `POST` |
| `endpoint` | string | Request path, e.g. `/api/v1/users` |
| `status_code` | integer | HTTP response status code |
| `user_agent` | string | User-Agent header, truncated to 400 characters |
| `attack_type` | string | Semantic attack category (see mapping table below) |
| `ttp` | string | MITRE ATT&CK technique ID |
| `interaction_id` | string | Hex ID derived from the database row ID or request ID |
| `actor_id` | string \| null | Pseudonymous attacker fingerprint (IP + UA hash) |
| `session_id` | string \| null | Session identifier when available |

### Example event

```json
{
  "timestamp": "2026-03-12T14:23:01Z",
  "event_type": "api_attack",
  "source_ip": "185.220.101.42",
  "method": "GET",
  "endpoint": "/.env",
  "status_code": 200,
  "user_agent": "curl/8.6.0",
  "attack_type": "config_discovery",
  "ttp": "T1592.002",
  "interaction_id": "1a2b3c4d",
  "actor_id": "d41d8cd9",
  "session_id": null
}
```

---

## MITRE ATT&CK TTP Mapping

| Honeypot event kind | attack_type | MITRE TTP |
|---|---|---|
| `probe` | recon | T1595 — Active Scanning |
| `recon_docs` | api_recon | T1592 — Gather Victim Host Info |
| `recon_openapi` | api_recon | T1592 |
| `recon_swagger` | api_recon | T1592 |
| `recon_redoc` | api_recon | T1592 |
| `recon_env` | config_discovery | T1592.002 — Software |
| `recon_config` | config_discovery | T1592.002 |
| `recon_security` | config_discovery | T1592.002 |
| `token_used` | credential_use | T1078 — Valid Accounts |
| `unknown_token` | brute_force | T1110 — Brute Force |
| `keys_issued` | credential_access | T1649 — Steal or Forge Authentication Certificates |
| `internal_config` | internal_recon | T1592 |
| `backup_list` | data_discovery | T1530 — Data from Cloud Storage |
| `backup_download` | data_exfiltration | T1530 |
| `admin_secrets` | privilege_escalation | T1078.004 — Cloud Accounts |
| `infra_vault` | privilege_escalation | T1078.004 |
| `cloud_metadata` | cloud_metadata_access | T1552.005 — Cloud Instance Metadata API |
| `root_console` | privilege_escalation | T1078.003 — Local Accounts |
| `health` | availability_probe | T1595 |

---

## Docker Logging Pipeline

### stdout → Filebeat → Elasticsearch / Splunk

The recommended production pipeline uses Docker's default JSON-file log driver combined with Filebeat running as a sidecar or on the host.

**docker-compose.prod.yml** (relevant excerpt):

```yaml
services:
  app:
    image: ${HP_IMAGE}:${APP_VERSION}
    logging:
      driver: json-file
      options:
        max-size: "50m"
        max-file: "5"
    environment:
      LOG_OUTPUT: stdout
```

**filebeat.yml** (Filebeat 8.x):

```yaml
filebeat.inputs:
  - type: container
    paths:
      - /var/lib/docker/containers/*/*.log
    processors:
      - decode_json_fields:
          fields: ["message"]
          target: "siem"
          overwrite_keys: true
      - drop_fields:
          fields: ["log", "stream"]

processors:
  - add_host_metadata: ~
  - add_docker_metadata: ~

output.elasticsearch:
  hosts: ["https://elastic.internal.example.com:9200"]
  username: "${ELASTIC_USER}"
  password: "${ELASTIC_PASSWORD}"
  index: "noctisapi-siem-%{+yyyy.MM.dd}"

setup.template.name: "noctisapi-siem"
setup.template.pattern: "noctisapi-siem-*"
```

### stdout → Fluentbit → Multiple outputs

**fluent-bit.conf**:

```ini
[SERVICE]
    Flush        1
    Daemon       Off
    Log_Level    info

[INPUT]
    Name         tail
    Path         /var/lib/docker/containers/*/*.log
    Parser       docker
    Tag          noctisapi.siem
    Refresh_Interval 5

[FILTER]
    Name         parser
    Match        noctisapi.siem
    Key_Name     log
    Parser       json
    Reserve_Data On

[OUTPUT]
    Name         es
    Match        noctisapi.siem
    Host         elastic.internal.example.com
    Port         9200
    Index        noctisapi-siem
    Type         _doc
    tls          On
    tls.verify   On

[OUTPUT]
    Name         splunk
    Match        noctisapi.siem
    Host         splunk-hec.internal.example.com
    Port         8088
    Splunk_Token ${SPLUNK_HEC_TOKEN}
    tls          On
    tls.verify   On
```

---

## Syslog Configuration

### Graylog (GELF via syslog)

Configure Graylog with a Syslog UDP Input on port 5140 and set:

```env
SYSLOG_ENABLED=true
SYSLOG_HOST=graylog.internal.example.com
SYSLOG_PORT=5140
SYSLOG_PROTOCOL=udp
SYSLOG_FACILITY=local0
```

Events arrive as RFC5424 syslog messages. In Graylog, create a JSON extractor on the `message` field to parse the embedded JSON payload into structured fields.

### Splunk (syslog input)

Configure a Splunk Universal Forwarder or Heavy Forwarder with a UDP syslog input:

**inputs.conf**:

```ini
[udp://514]
sourcetype = noctisapi:siem
index = security
connection_host = dns
```

**props.conf**:

```ini
[noctisapi:siem]
KV_MODE = json
TIME_PREFIX = \"timestamp\":\"
TIME_FORMAT = %Y-%m-%dT%H:%M:%SZ
SHOULD_LINEMERGE = false
```

### rsyslog relay (Linux host)

To relay syslog events from the container host to a central SIEM:

**/etc/rsyslog.d/noctisapi.conf**:

```
# Forward local0 facility to SIEM
local0.*    @siem.internal.example.com:514
```

---

## Splunk Search Examples

```spl
index=security sourcetype="noctisapi:siem"
| spath input=_raw
| search attack_type=brute_force
| stats count by source_ip, actor_id
| sort -count
```

```spl
index=security sourcetype="noctisapi:siem" ttp="T1552.005"
| table _time, source_ip, endpoint, user_agent
```

---

## Elastic (KQL) Query Examples

```kql
siem.attack_type : "config_discovery" AND siem.status_code >= 200
```

```kql
siem.ttp : "T1110" AND siem.source_ip : "185.220.*"
```

---

## Graylog Search Examples

```
attack_type:brute_force AND source_ip:[185.0.0.0 TO 185.255.255.255]
```

```
ttp:T1595 AND NOT event_type:api_interaction
```

---

## Alert Recommendations

| Alert | Condition | Suggested threshold |
|---|---|---|
| Credential brute force | `attack_type=brute_force` from single IP | > 10 events / 5 min |
| Cloud metadata probe | `ttp=T1552.005` | Any occurrence |
| Privilege escalation attempt | `attack_type=privilege_escalation` | Any occurrence |
| Config/env file discovery | `attack_type=config_discovery` | > 3 events / 10 min |
| Mass API recon | `attack_type=api_recon` from single IP | > 20 events / 1 min |

---

## Operational Notes

- **Queue depth**: The dispatcher uses a bounded in-memory queue (10 000 events). Under extreme load events are dropped rather than blocking the API. Monitor queue saturation by counting drops in your SIEM if needed.
- **Syslog timeout**: Each syslog send is subject to a 1-second socket timeout. Network failures are silently swallowed.
- **File rotation**: The file handler appends to the configured path. Use logrotate or an external log shipper (Filebeat, Fluentbit) for rotation.
- **Startup**: `siem_logger.configure()` must be called once at process startup (already done in `main.py` and `main_panel.py`). It starts the background dispatcher thread and reads env vars.
- **Graceful shutdown**: Call `siem_logger.shutdown()` to drain the queue before process exit (e.g. in a signal handler).
