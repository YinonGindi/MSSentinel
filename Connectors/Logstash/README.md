# Logstash → Microsoft Sentinel (Windows Events, Syslog, CEF)

Ingest Windows Security events, plain syslog, and CEF into Microsoft Sentinel through a
**single Logstash pipeline** and a **single Data Collection Rule**, using the Azure Monitor
Logs Ingestion API.

All three sources arrive on **one UDP port (5044)**. Logstash performs content-based
detection and tagging only — no field renaming. All schema normalization happens in the
DCR `transformKql` expressions, which keeps the Logstash config small and puts the mapping
logic where it can be changed without restarting the pipeline.

```
  NXLog (WEF collector) ──JSON──┐
                                │
  Network devices ─────CEF──────┼──► UDP 5044 ──► Logstash ──► DCE ──► DCR ──► Log Analytics
                                │                (tag only)          (transformKql)
  Linux hosts ─────RFC3164──────┘                                            │
                                                                             ├─► SecurityEvent
                                                                             ├─► Syslog
                                                                             └─► CommonSecurityLog
```

| Tag        | Stream                          | Output stream                 | Table                |
| ---------- | ------------------------------- | ----------------------------- | -------------------- |
| `winevent` | `Custom-WindowsEvents-Stream-01` | `Microsoft-SecurityEvent`     | `SecurityEvent`      |
| `syslog`   | `Custom-Syslog-Stream-01`        | `Microsoft-Syslog`            | `Syslog`             |
| `cef`      | `Custom-CEF-Stream-01`           | `Microsoft-CommonSecurityLog` | `CommonSecurityLog`  |

---

## Quick deploy

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FYinonGindi%2FMicrosoft_Sentinel%2Fmain%2FConnectors%2FLogstash%2FLogstashDCR.json)

You will be prompted for the workspace resource ID and the resource ID of your **existing**
data collection endpoint — see [Prerequisites](#prerequisites). Then continue from
[step 2](#2-grant-the-managed-identity-permission-on-the-dcr).

---

## Contents

| File | Purpose |
| --- | --- |
| `LogstashDCR.json` | ARM template — data collection rule (3 streams, 3 transforms) |
| `logstash-sentinel.conf` | Logstash pipeline — input, detection filters, 3 outputs |
| `NXLog.conf` | NXLog config for the Windows Event Forwarding collector |
| `Send-SentinelTestEvents.ps1` | PowerShell UDP sender for syslog and CEF test events |

---

## Prerequisites

- A Log Analytics workspace with Microsoft Sentinel enabled.

- **A data collection endpoint (DCE).** This is supplied by the environment owner and is
  deliberately **not** deployed by this repo, since the DCE is usually shared across
  connectors and governed by the customer's network design. It must be in the **same region
  as the DCR**. Collect two values from it:

  | Value | Used as | Where to find it |
  | --- | --- | --- |
  | Resource ID | `dataCollectionEndpointResourceID` parameter of the DCR | DCE → Properties |
  | Logs ingestion URL | `data_collection_endpoint` in the pipeline | DCE → Overview → *Logs ingestion* |

  ```bash
  az monitor data-collection endpoint show -g <rg> -n <dce-name> \
    --query "{ResourceId:id, LogsIngestion:logsIngestion.endpoint}" -o yaml
  ```

  The ingestion URL looks like `https://<dce-name>-ab12.westus2-1.ingest.monitor.azure.com`.
  If the DCE has `publicNetworkAccess` disabled, the Logstash host must reach it over
  Private Link / AMPLS.

- The **Common Event Format** solution installed from **Content Hub**. This is what creates
  the `CommonSecurityLog` table — without it, the CEF data flow fails validation at deploy time.
  `SecurityEvent` requires the **Windows Security Events** solution. `Syslog` ships with
  LogManagement and needs nothing.

- A Logstash host (8.x tested) that can reach `*.ingest.monitor.azure.com` on TCP 443.

- A **managed identity** on the Logstash host — either an Azure VM system-assigned identity
  or **Azure Arc** for on-premises. The pipeline authenticates with `managed_identity => true`;
  no client secret is stored anywhere.

- The Sentinel output plugin:
  ```bash
  sudo /usr/share/logstash/bin/logstash-plugin install microsoft-sentinel-log-analytics-logstash-output-plugin
  ```

---

## Deployment

### 1. Deploy the data collection rule

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FYinonGindi%2FMicrosoft_Sentinel%2Fmain%2FConnectors%2FLogstash%2FLogstashDCR.json)

```bash
az deployment group create \
  --resource-group <rg> \
  --template-file LogstashDCR.json \
  --parameters \
      dataCollectionRulesLogStash=DCR_Logstash \
      location=westus2 \
      workspacesResourceID=/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace> \
      dataCollectionEndpointResourceID=/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Insights/dataCollectionEndpoints/<dce-name>
```

`location` must match the DCE's region. Record `dataCollectionRuleImmutableId` from the
outputs — that is the `dcr_immutable_id` value in `logstash-sentinel.conf`.

### 2. Grant the managed identity permission on the DCR

Scope the role assignment to the **DCR**, not the workspace.

```bash
# Arc-enabled server
PRINCIPAL=$(az connectedmachine show -g <rg> -n <logstash-host> --query identity.principalId -o tsv)
# Azure VM: az vm show -g <rg> -n <logstash-host> --query identity.principalId -o tsv

az role assignment create \
  --assignee-object-id "$PRINCIPAL" \
  --assignee-principal-type ServicePrincipal \
  --role "Monitoring Metrics Publisher" \
  --scope "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.Insights/dataCollectionRules/DCR_Logstash"
```

### 3. Configure Logstash

Copy `logstash-sentinel.conf` to `/etc/logstash/conf.d/` and replace the placeholders in all
three output blocks:

| Placeholder | Value |
| --- | --- |
| `<DCE>` | Logs ingestion URL of the DCE (see Prerequisites) |
| `dcr-<ID>` | `dataCollectionRuleImmutableId` from step 1 |

Validate and start:

```bash
sudo /usr/share/logstash/bin/logstash --path.settings /etc/logstash -f /etc/logstash/conf.d/logstash-sentinel.conf --config.test_and_exit
sudo systemctl restart logstash
sudo journalctl -u logstash -f
```

### 4. Configure NXLog on the WEF collector

Copy `NXLog.conf` and set the `Host` in the `<Output out>` block to the Logstash host.
Restart the `nxlog` service.

### 5. Apply the UDP tuning on the Logstash host

Fragmented Windows events are dropped silently once the kernel reassembly pool fills.
This is the most common cause of "some events never arrive":

```bash
cat >/etc/sysctl.d/99-logstash-udp.conf <<'EOF'
net.core.rmem_max           = 33554432
net.ipv4.ipfrag_high_thresh = 33554432
net.ipv4.ipfrag_low_thresh  = 25165824
net.ipv4.ipfrag_time        = 10
EOF
sysctl --system
```

`receive_buffer_bytes` in the pipeline is silently clamped to `net.core.rmem_max`, so this
also fixes the socket buffer.

---

## Validation

```bash
echo '<134>Aug 19 12:00:00 testhost sshd[1234]: Accepted password for alice from 10.0.0.5 port 22 ssh2' > /dev/udp/<logstash-host>/5044
echo '<134>Aug 19 12:00:00 fw-01 CEF:0|Vendor|Product|1.0|100|Test event|5|src=10.1.2.3 spt=51234 dst=8.8.8.8 dpt=443 proto=TCP act=allow dvchost=fw-01' > /dev/udp/<logstash-host>/5044
```

`/dev/udp` is a bash builtin — it fails under `sh`/`dash`.

```PowerShell
$SyslogCEF = '<134>Aug 19 15:45:00 fw-01 CEF:0|Palo Alto Networks|PAN-OS|10.2|end|TRAFFIC|3|src=10.1.2.3 spt=51234 dst=8.8.8.8 dpt=443 proto=TCP act=allow suser=jdoe dvchost=fw-01 cs1Label=Rule cs1=Allow-Web in=1234 out=5678 msg=Session ended normally'
# local0.info  -> Facility local0, SeverityLevel informational
$Syslog1='<134>Aug 19 16:05:00 web-01 sshd[4321]: Accepted password for jdoe from 10.0.0.5 port 52344 ssh2'

# user.err     -> Facility user-level, SeverityLevel error
$Syslog2='<11>Aug 19 16:06:12 db-02 postgres[988]: FATAL: password authentication failed for user "admin"'

# auth.notice, no PID -> exercises the second grok pattern
$Syslog3='<85>Aug 19 16:07:30 web-01 sudo: jdoe : TTY=pts/0 ; PWD=/home/jdoe ; USER=root ; COMMAND=/bin/systemctl restart nginx'
$u = New-Object System.Net.Sockets.UdpClient
$msg = [System.Text.Encoding]::ASCII.GetBytes($SyslogCEF)
$u.Send($msg, $msg.Length, '<collectorIP>', 5044)
$msg = [System.Text.Encoding]::ASCII.GetBytes($Syslog1)
$u.Send($msg, $msg.Length, '<collectorIP>', 5044)
$msg = [System.Text.Encoding]::ASCII.GetBytes($Syslog2)
$u.Send($msg, $msg.Length, '<collectorIP>', 5044)
$msg = [System.Text.Encoding]::ASCII.GetBytes($Syslog3)
$u.Send($msg, $msg.Length, '<collectorIP>', 5044)
$u.Close()
```

Then in the workspace:

```kusto
union SecurityEvent, Syslog, CommonSecurityLog
| where TimeGenerated > ago(15m)
| summarize Events = count(), Latest = max(TimeGenerated) by Type
```

**Expect no data for the first ~3 minutes.** The first write to a table after a DCR change
is slow; this is normal and is not an error. UDP is fire-and-forget, so a successful send
never proves delivery — always confirm on the collector as well.

---

## Design notes

- **CEF is detected before syslog.** A CEF payload carries a syslog header, so testing the
  syslog pattern first would swallow every CEF event.
- **Logstash sends raw grok field names** (`logsource`, `msg`, `program`, `procid`) and the
  DCR renames them. Do not rename in Logstash — mixing the two conventions produces rows
  where only `TimeGenerated` and `Computer` are populated.
- **`collector_host` is `%{host}`, which is the *sender's* IP**, not the Logstash host. For
  relayed syslog this is the relay, not the originating device. `Computer` prefers
  `logsource` from the syslog header and only falls back to `collector_host`.
- **`AdditionalExtensions`** currently carries the full raw CEF extension string, so mapped
  fields appear twice. AMA stores only *unmapped* keys; matching that behavior requires
  re-delimiting the extension string before stripping known keys, since KQL uses RE2 and
  has no lookahead support.

---

## Troubleshooting

**`The stream Custom-X-Stream-01 was not configured in the data collection rule with immutable Id dcr-…`**
The DCR has the stream but the endpoint is still serving a cached copy. DCE configuration
propagation takes **3–5 minutes** after any DCR change. Wait and retry before changing
anything. If it persists beyond ~10 minutes, make a trivial edit to the DCR (e.g. the
description) to force a resync.

**`LogsUploadException: null` / `Failed to upload batch; non-retryable`**
The plugin logs this for *every* upload failure regardless of cause and always labels it
non-retryable, so the message says nothing about the real problem. Do not infer a cause
from it. Enable diagnostic settings on the DCR and query `DCRLogErrors` for the actual
service-side reason.

**`ConnectTimeoutException` after 15 seconds**
`connect_timeout_seconds` defaults to 15. Confirm DNS resolution of the DCE hostname and
outbound 443 from the Logstash host.

**Logstash fails to start after adding a plugin option**
Older plugin builds use `dcr_immutable_id` and `dcr_stream_name`; current releases renamed
these to `dcr_id` and `stream_name`. This repo uses the older names. Check your installed
version before changing them — an unrecognized option aborts pipeline startup.

**`Facility` / `SeverityLevel` empty on Syslog rows**
On Logstash 8+, `ecs_compatibility` must be set **per filter**, not just on the input. In
ECS mode `syslog_pri` writes `[log][syslog][facility][name]` instead of `syslog_facility`,
and the DCR sees nothing. Both `grok` and `syslog_pri` in this config set it explicitly.
These fields are also empty for lines with no `<pri>` header, since `syslog_pri` is gated
on the `priority` field existing.

**`Unknown function: 'parse_cef_dictionary'` in the Logs query editor**
`parse_cef_dictionary` is transformation-only. It works inside `transformKql` but cannot be
run in the query editor. Not a deployment problem.

**Windows events arriving with missing or empty fields**
Large Security events (4624, 4688, 4662) exceed the ~1472-byte UDP payload limit and are IP
fragmented; losing one fragment loses the whole event. Apply the sysctl tuning above, and
check for loss with:

```bash
nstat -az | grep -iE 'reasm|frag'
netstat -su | grep -iE 'reassemb|fail|receive buffer'
```

Rising `ReasmFails` or `RcvbufErrors` means events are being lost. If the collector and
Logstash share an L2 segment, setting MTU 9000 on both NICs fits a full event into a single
unfragmented datagram and removes the problem entirely.

---

## Known limitations

- UDP only, no delivery guarantee or TLS in transit.
- CEF `start` / `end` extensions are not mapped to `StartTime` / `EndTime` — they are epoch
  milliseconds and `todatetime()` does not convert them.
- `cfp*`, `c6a*`, `flex*`, and `OldFile*` CEF extensions are unmapped.
- `Keywords` for non-audit Windows events falls through as a signed decimal rather than the
  hex form native `SecurityEvent` rows use.
