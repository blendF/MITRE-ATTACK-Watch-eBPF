# MITRE-ATTACK-Watch-eBPF

## What is this?

**MITRE-ATTACK-Watch-eBPF** combines **eBPF kernel tracing** with a **heuristic MITRE ATT&CK layer**. It is aimed at security learners and analysts who want to see **real kernel activity** (processes, network sockets, sensitive file opens) translated into **possible ATT&CK techniques** with human-readable rationales—not as a certified product, but as an experimentation and teaching stack.

> **Note:** This is an experimentation project for learning eBPF and ATT&CK mapping. It is **not** intended for production security operations without your own hardening, tuning, and validation.

---

## What does it do?

At a high level, the agent:

1. **Attaches eBPF programs to kernel tracepoints** so it can observe selected syscalls and scheduler events with low overhead compared to full audit pipelines.
2. **Emits structured events** (JSON) describing things like process execution with arguments, process exit and lifetime, outbound IPv4 `connect`, inbound `accept`, and **opens** of paths considered sensitive (for example under `/root`, `.ssh`, or `/etc/passwd`).
3. **Enriches** many events using `/proc` (executable path, working directory, memory, file descriptor count, and related metadata where applicable).
4. **Maps** each event to zero or more **MITRE ATT&CK** techniques using bundled metadata derived from the official [ATT&CK STIX dataset](https://github.com/mitre-attack/attack-stix-data). Each match includes a **rationale** explaining why the rule fired.
5. **Assigns a coarse severity** (low / medium / critical) used for prioritization in the **web dashboard** (blue / yellow / red).
6. **Delivers** the same enriched payload to **stdout** (always on), and optionally to **Prometheus**, **MQTT**, and a **local HTTP/WebSocket dashboard**.

The web UI shows a live table of events; clicking a row opens a **per-event detail page** with the raw kernel fields, data source (tracepoint), and the list of ATT&CK matches with links to [attack.mitre.org](https://attack.mitre.org/).

---

## How do I use it?

### Prerequisites

- **Linux** with a recent kernel (integration tests target **5.8+** with **BTF** enabled, e.g. `CONFIG_DEBUG_INFO_BTF=y`).
- **Root** (or sufficient capability) to load eBPF programs.
- **Go toolchain** matching `go.mod` (for building from source).
- After clone: run **`go generate ./internal/bpf/`** once so **bpf2go** produces the Go bindings and bytecode for your environment.

### Build

```bash
go generate ./internal/bpf/
go build -o kwatch ./cmd/kwatch/
```

### Run (stdout only)

Streams **enriched** JSON lines (each line is one event with `id`, `observed_at`, `severity`, `event`, `matches`, `data_source`, etc.):

```bash
sudo ./kwatch start
```

### Run with optional outputs (Prometheus, dashboard, MQTT)

1. Edit or copy [`config.yaml`](config.yaml) and enable the sections you need.
2. Start with:

```bash
sudo ./kwatch start --config=config.yaml
```

3. If **`outputs.websocket.enabled: true`** (the YAML name is historical; it turns on the **full dashboard**):

   | What | URL |
   |------|-----|
   | Live dashboard | `http://127.0.0.1:8080/` (or your configured port) |
   | Event detail (HTML) | `http://127.0.0.1:8080/log/{id}` |
   | Event detail (JSON) | `http://127.0.0.1:8080/api/events/{id}` |
   | Live stream | WebSocket `ws://127.0.0.1:8080/ws` |

   Severity colors in the table: **blue** = low, **yellow** = medium, **red** = critical.

4. If **Prometheus** is enabled, scrape `http://<host>:<port>/metrics` (default port **2112** if unset in YAML).

5. If **MQTT** is enabled, subscribe to the configured topic for the same JSON as stdout.

### Integration tests (tracer)

```bash
sudo go test -tags=integration ./internal/tracer/ -v
```

---

## In-depth: how the software works

### End-to-end architecture

The system splits naturally into a **kernel side** and a **userspace side**.

- **Kernel (eBPF):** Small C programs run on tracepoints. When the condition for an event is met (for example, `openat` on a sensitive path, or `execve`), they push a compact binary record into a **BPF ring buffer**.
- **Userspace (Go):** A single agent reads the ring buffer, decodes records into **`EventJSON`**, optionally enriches from `/proc`, then passes each event through the **MITRE mapper**, which produces an **`EnrichedEvent`**. That value is stored in a **fixed-size in-memory ring** (for dashboard deep links) and forwarded to every configured **output** (stdout, dashboard WebSocket, Prometheus counters, MQTT).

You can think of the pipeline as: **tracepoint → ring buffer → decode → enrich → ATT&CK rules + technique metadata → outputs**.

### What the kernel actually traces

The agent hooks are aligned with common Linux observability needs:

| User-visible event | Underlying idea | Tracepoint(s) |
|--------------------|-----------------|---------------|
| **exec** | New program started; arguments captured in chunks | `syscalls/sys_enter_execve` |
| **exit** | Process ended; duration derived from scheduler | `sched/sched_process_exit` |
| **connect** | Outbound IPv4 TCP connection attempt | `syscalls/sys_enter_connect` |
| **accept** | Inbound connection accepted | `syscalls/sys_enter_accept` / `sys_exit_accept` |
| **open** | File open via `openat`, **only if** the path matches sensitivity rules | `syscalls/sys_enter_openat` |

Not every `openat` is reported: filtering keeps noise down and focuses on paths that are more likely to matter for security narratives (credentials, privilege, scheduling, secrets mounts, etc.). The exact lists live in [`internal/models/event.go`](internal/models/event.go).

### Userspace enrichment

For **exec** events, the agent reads **`/proc/[pid]/`** to attach context such as resolved executable, current working directory, memory usage, and open file descriptor count. That makes downstream logs and the dashboard easier to interpret than raw `comm` and partial argv alone.

### MITRE ATT&CK layer (heuristic)

Technique **names**, **descriptions**, and **canonical URLs** are **not** invented at runtime from scratch. They are loaded from **`internal/mitre/techniques_embed.json`**, a **slim extract** of enterprise ATT&CK STIX (`attack-pattern` objects with MITRE `external_id` values like `T1059`). The full multi-hundred-megabyte `enterprise-attack.json` is **not** parsed on startup; only this embedded file is, keeping memory and startup predictable.

**Mapping** is **rule-based**, not machine-learning and not MITRE-validated:

- Rules consider **event type**, **file path** (including “credential-critical” paths such as `/etc/shadow` or SSH private keys under `~/.ssh`), **destination ports** for outbound connections, and **substrings in command lines** (for example hints of download-and-execute patterns).
- Each firing rule adds a **`Match`**: technique id, resolved name/URL/description from STIX, a **rationale** string, and a **per-rule severity**.
- The event’s **aggregate severity** is effectively the **maximum** of its match severities. If **no** rule matches (for example a bare **exit** event), the event still appears where outputs show it, with **low** severity and an explanatory **unmapped** message where applicable.

**Important limitations:** Any mapping from “we saw a `connect`” to “T1071” is **hypothesis**, not proof of malicious command and control. Heavy use of **exec** mapping will be **noisy** on a normal desktop or server. Treat the output as **starting context** for an analyst, not as automated detection verdicts.

### Web dashboard behavior

The dashboard server is implemented in Go and **embeds** static HTML, CSS, and JavaScript from [`internal/outputs/web/`](internal/outputs/web/). On **`GET /`**, the browser loads a table fed by **`/ws`**. The first WebSocket message after connect is still the **process snapshot** (`SnapshotJSON`); subsequent messages are **enriched events**.

**`GET /log/{id}`** renders a server-side HTML template with the stored **`EnrichedEvent`**. IDs are random hex strings; if the ring buffer has evicted an old event, the detail URL returns **404**. The default retention is **8192** events (see [`cmd/kwatch/start.go`](cmd/kwatch/start.go)).

### Output reference

| Output | Role |
|--------|------|
| **Stdout** | Always on; one JSON object per line, full enriched shape. |
| **Prometheus** | Counters `kwatch_events_total{type=...,command=...}` for volume trends (low cardinality by design). |
| **Dashboard** | HTTP + WebSocket as described above. |
| **MQTT** | Publishes enriched JSON to your broker/topic. |

Example minimal config shape:

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

### Regenerating ATT&CK metadata

When you refresh the vendored **`attack-stix-data`** tree, rebuild the embedded bundle from the repo root:

```bash
go run ./tools/extract-techniques \
  -in ./attack-stix-data/enterprise-attack/enterprise-attack.json \
  -out ./internal/mitre/techniques_embed.json
```

Commit the updated **`techniques_embed.json`** so others get consistent technique names and URLs.

### Stack summary

- **Kernel:** C + eBPF, built with [cilium/ebpf](https://github.com/cilium/ebpf) and **bpf2go**.
- **Agent:** Go ([Cobra](https://github.com/spf13/cobra) CLI, optional [Prometheus](https://prometheus.io/), [Gorilla WebSocket](https://github.com/gorilla/websocket), optional [Paho MQTT](https://github.com/eclipse/paho.mqtt.golang)).

### Related tools (context)

For production-grade, policy-driven runtime security on Linux, projects such as [Falco](https://falco.org) and [Tetragon](https://tetragon.io) are more mature. kwatch-ebpf is smaller in scope and optimized for **learning** and **ATT&CK-shaped storytelling** over your own tracepoint set.

---

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE ATT&CK STIX Data (GitHub)](https://github.com/mitre-attack/attack-stix-data)
- [eBPF — what is it?](https://ebpf.io/what-is-ebpf/)
- [cilium/ebpf](https://github.com/cilium/ebpf)
- [Linux tracepoints](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)
- [BPF ring buffer](https://www.kernel.org/doc/html/latest/bpf/ringbuf.html)
