# MITRE-ATTACK-Watch-eBPF (kwatch-ebpf)

Monitors kernel-level process activity, emits detailed execution logs, and is intended to map observed behavior to relevant [MITRE ATT&CK](https://attack.mitre.org/) techniques for detection and analysis.

> An experimentation project — built to experiment/learn eBPF, not for production use.

eBPF-based kernel process monitor. Hooks into kernel tracepoints to capture process execution, network connections, and sensitive file access.

## What it traces

| Event | Hook |
|---|---|
| Process exec + argv | `tracepoint/syscalls/sys_enter_execve` |
| Process exit + lifetime | `tracepoint/sched/sched_process_exit` |
| Outbound connections (IPv4) | `tracepoint/syscalls/sys_enter_connect` |
| Inbound connections (IPv4) | `tracepoint/syscalls/sys_enter_accept{4}` |
| Sensitive file access | `tracepoint/syscalls/sys_enter_openat` |

Process events are enriched from `/proc/[pid]/` (exe, cwd, ppid, memory, fd count) immediately after the kernel event arrives.

## Stack

- **Kernel:** C + eBPF, compiled via [cilium/ebpf](https://github.com/cilium/ebpf) / bpf2go
- **Backend:** Go
- **ATT&CK metadata:** slim JSON embedded from [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data) (`enterprise-attack.json`), regenerated via `tools/extract-techniques`

## MITRE ATT&CK mapping (heuristic)

Each kernel event is enriched with possible **MITRE ATT&CK** techniques using **rules** (event type, paths, ports, command-line hints). This is an **experimental aid** for analysts, not validated detection logic. MITRE does not endorse this mapping.

- **Severity** is derived from those rules: **low** (e.g. generic exec), **medium** (e.g. network, sensitive file reads), **critical** (e.g. credential-critical paths, suspicious ports).
- **Stdout, MQTT, and the dashboard** receive the same enriched JSON shape: `id`, `observed_at`, `severity`, `event` (raw fields), `matches[]` (technique id, name, URL, rationale, rule severity), `data_source` (tracepoint summary).

### Regenerate embedded techniques

After updating the `attack-stix-data` copy, rebuild the bundled file (from the repo root):

```bash
go run ./tools/extract-techniques \
  -in ./attack-stix-data/enterprise-attack/enterprise-attack.json \
  -out ./internal/mitre/techniques_embed.json
```

Commit the updated `internal/mitre/techniques_embed.json`.

## Run

```bash
# generate ebpf bytecode
go generate ./internal/bpf/

# build
go build -o kwatch ./cmd/kwatch/

# run (requires root for eBPF)
sudo ./kwatch start
```

## Outputs

By default, events stream to stdout as JSON. You can enable additional outputs via a config file:

```bash
sudo ./kwatch start --config=config.yaml
```

### Config format

```yaml
outputs:
  prometheus:
    enabled: true
    port: 2112
  websocket:
    enabled: true
    port: 8080
  mqtt:
    enabled: true
    broker: "tcp://localhost:1883"
    topic: "kwatch/events"
```

All outputs are optional. Omit any section you don't need. Stdout is always active and prints **enriched** JSON (raw event plus MITRE fields).

### Prometheus

Exposes a `/metrics` endpoint with low-cardinality counters. Labels are limited to `type` and `command` to avoid cardinality explosion (no PIDs, paths, or addresses).

```
kwatch_events_total{type="exec", command="bash"} 47
kwatch_events_total{type="open", command="nginx"} 312
```

### Web dashboard (YAML key `websocket`)

When `outputs.websocket.enabled` is true, the agent serves:

| URL | Purpose |
|-----|---------|
| `http://<host>:<port>/` | Live table of events; **blue** = low, **yellow** = medium, **red** = critical |
| `http://<host>:<port>/log/{id}` | Detail page for one stored event (how it matched ATT&CK) |
| `http://<host>:<port>/api/events/{id}` | Same payload as JSON |
| `ws://<host>:<port>/ws` | WebSocket: initial process snapshot, then enriched events |

Recent events are kept in memory (ring buffer, default 8192) so `/log/{id}` links stay valid until the event ages out.

### MQTT

Publishes each event as a JSON string to the configured broker and topic.

## Test
```bash
sudo go test -tags=integration ./internal/tracer/ -v
```

Requires Linux 5.8+ with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`).

## References

- [eBPF — what is it?](https://ebpf.io/what-is-ebpf/)
- [cilium/ebpf Go library](https://github.com/cilium/ebpf)
- [Linux tracepoints](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)
- [BPF ring buffer](https://www.kernel.org/doc/html/latest/bpf/ringbuf.html)
- [Falco](https://falco.org) and [Tetragon](https://tetragon.io) — production tools built on similar ideas
