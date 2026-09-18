# Wazuh integration

Exteriq ASM forwards attack-surface changes and findings to Wazuh as flat, structured
JSON so they can be correlated with endpoint and network telemetry, alerted on and
retained in the Wazuh indexer. The integration is optional and configured per tenant under
**Integrations → Channels → Wazuh**, combined with an **alert policy** that selects which
change types and severities are forwarded.

## Event format

```json
{
  "source": "exteriq-asm",
  "event_type": "port_opened",
  "severity": "high",
  "title": "New externally exposed service: 3389/tcp on 192.0.2.20 (Remote Desktop (RDP))",
  "tenant": "acme",
  "organization": "Example Corp",
  "asset": "192.0.2.20:3389/tcp",
  "asset_type": "port",
  "ip": "192.0.2.20",
  "finding": null,
  "cve": null,
  "risk_score": 59,
  "previous": null,
  "current": {"ip": "192.0.2.20", "port": 3389, "protocol": "tcp", "service": "Remote Desktop (RDP)"},
  "event_id": "4a0c…",
  "timestamp": "2026-09-18T09:42:00+00:00",
  "url": "https://asm.example.com/assets/…"
}
```

`event_type` values are listed in [CHANGE_DETECTION.md](../CHANGE_DETECTION.md#event-catalogue).
`severity` is one of `info`, `low`, `medium`, `high`, `critical`.

## Delivery modes

| Mode | How | Use when |
|---|---|---|
| **syslog** (default) | RFC 3164 message `<PRI>Mmm dd hh:mm:ss exteriq-asm exteriq-asm: {json}` over UDP or TCP 514 to the Wazuh manager | Manager reachable from the ASM worker |
| **file** | JSON lines appended to `/data/exports/<file>` (volume `asm-exports`) | A Wazuh agent runs on the ASM host (air-gapped or no inbound syslog) |
| **webhook** | HTTPS POST of the JSON event, optional bearer token | You run an HTTP intake (e.g. Logstash/Fluent Bit/Wazuh API proxy) in front of Wazuh |

### Wazuh manager: accept syslog

`/var/ossec/etc/ossec.conf` on the manager:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>          <!-- or tcp, matching the channel config -->
  <allowed-ips>10.20.0.15/32</allowed-ips>   <!-- the ASM worker's egress address -->
</remote>
```

### Wazuh agent: read the JSON file

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/lib/docker/volumes/exteriq-asm_asm-exports/_data/exteriq-asm.json</location>
</localfile>
```

The volume prefix is the Compose project (install folder) name and the file name is the
channel's configured *file name*; check both with `docker volume ls` and the channel settings.

(Or mount the `asm-exports` volume into the agent's container.)

## Decoding

The events are JSON. Wazuh's built-in `json` decoder handles them directly in **file**
mode. In **syslog** mode the predecoder extracts `program_name: exteriq-asm` and the JSON
payload; add a dedicated decoder so the fields are decoded regardless of other syslog
decoders:

`/var/ossec/etc/decoders/exteriq_asm_decoders.xml`

```xml
<decoder name="exteriq-asm">
  <program_name>^exteriq-asm$</program_name>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>
```

Test with `/var/ossec/bin/wazuh-logtest` by pasting a line produced by the integration's
**Test** button.

## Rules

`/var/ossec/etc/rules/exteriq_asm_rules.xml` — rule IDs 100500–100599 are reserved for
Exteriq ASM (adjust if they collide with local rules).

```xml
<group name="exteriq_asm,attack_surface,">

  <!-- Base: any Exteriq ASM event -->
  <rule id="100500" level="3">
    <decoded_as>json</decoded_as>
    <field name="source">^exteriq-asm$</field>
    <description>Exteriq ASM: $(title)</description>
  </rule>
  <rule id="100501" level="3">
    <decoded_as>exteriq-asm</decoded_as>
    <field name="source">^exteriq-asm$</field>
    <description>Exteriq ASM: $(title)</description>
  </rule>

  <!-- Severity mapping -->
  <rule id="100510" level="5">
    <if_sid>100500,100501</if_sid>
    <field name="severity">^medium$</field>
    <description>Exteriq ASM (medium): $(title)</description>
  </rule>
  <rule id="100511" level="10">
    <if_sid>100500,100501</if_sid>
    <field name="severity">^high$</field>
    <description>Exteriq ASM (high): $(title)</description>
  </rule>
  <rule id="100512" level="13">
    <if_sid>100500,100501</if_sid>
    <field name="severity">^critical$</field>
    <description>Exteriq ASM (critical): $(title)</description>
  </rule>

  <!-- Specific change types -->
  <rule id="100520" level="10">
    <if_sid>100500,100501</if_sid>
    <field name="event_type">^port_opened$</field>
    <field name="severity">^high$|^critical$</field>
    <description>Exteriq ASM: high-risk service newly exposed on $(asset)</description>
    <mitre><id>T1133</id></mitre>
  </rule>
  <rule id="100521" level="8">
    <if_sid>100500,100501</if_sid>
    <field name="event_type">^new_subdomain$|^new_asset$|^asset_exposed$</field>
    <description>Exteriq ASM: new internet-facing asset $(asset)</description>
  </rule>
  <rule id="100522" level="12">
    <if_sid>100500,100501</if_sid>
    <field name="event_type">^vulnerability_detected$|^vulnerability_reopened$</field>
    <field name="severity">^high$|^critical$</field>
    <description>Exteriq ASM: $(severity) exposure on $(asset): $(finding)</description>
    <mitre><id>T1190</id></mitre>
  </rule>
  <rule id="100523" level="14">
    <if_sid>100522</if_sid>
    <field name="cve">CVE-</field>
    <field name="risk_score" type="pcre2">^(8\d|9\d|100)$</field>
    <description>Exteriq ASM: critical-risk vulnerability ($(cve)) on internet-facing $(asset)</description>
  </rule>
  <rule id="100524" level="9">
    <if_sid>100500,100501</if_sid>
    <field name="event_type">^certificate_expired$|^certificate_expiring$</field>
    <description>Exteriq ASM: TLS certificate problem on $(asset)</description>
  </rule>
  <rule id="100525" level="7">
    <if_sid>100500,100501</if_sid>
    <field name="event_type">^hosting_changed$|^ip_changed$</field>
    <description>Exteriq ASM: hosting/IP change for $(asset)</description>
  </rule>
  <rule id="100526" level="10">
    <if_sid>100500,100501</if_sid>
    <field name="event_type">^risk_increased$</field>
    <field name="severity">^high$</field>
    <description>Exteriq ASM: risk increased on $(asset)</description>
  </rule>
  <rule id="100527" level="5">
    <if_sid>100500,100501</if_sid>
    <field name="event_type">^scan_failed$</field>
    <description>Exteriq ASM: scan failed ($(organization))</description>
  </rule>
</group>
```

Notes:

- `100500` matches file/JSON-decoded events; `100501` matches the syslog decoder above. Keep
  whichever matches your delivery mode (both are harmless).
- Rule levels are suggestions: 12+ typically pages the SOC.
- Correlate `ip`/`asset` with Wazuh agent inventory (`syscollector`) and vulnerability
  detection to spot externally exposed hosts that are also vulnerable internally.
- Restart the manager after adding decoders/rules: `systemctl restart wazuh-manager`.

## Verification

1. Integrations → add a **Wazuh** channel → **Test**. The test event has
   `event_type: "test"` and severity `info` and should appear in `archives.json`
   (with `logall_json` enabled) and match rule 100500/100501.
2. Add an alert policy (e.g. severity ≥ high) pointing at the channel.
3. Delivery results are visible under Integrations → Delivery log.
