package mitre

import (
	"time"

	"github.com/ismajl-ramadani/kwatch-ebpf/internal/models"
)

// Severity is aggregated for dashboard styling (blue / yellow / red).
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityCritical Severity = "critical"
)

// TechniqueInfo is a slim row from STIX attack-patterns.
type TechniqueInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
}

// Match is one rule hit with display metadata.
type Match struct {
	TechniqueID string   `json:"technique_id"`
	Name        string   `json:"name"`
	URL         string   `json:"url"`
	Description string   `json:"description,omitempty"`
	Rationale   string   `json:"rationale"`
	Severity    Severity `json:"severity"`
}

// EnrichedEvent is the raw kernel event plus MITRE mapping for outputs and the UI.
type EnrichedEvent struct {
	ID          string           `json:"id"`
	ObservedAt  time.Time        `json:"observed_at"`
	Event       models.EventJSON `json:"event"`
	Severity    Severity         `json:"severity"`
	Matches     []Match          `json:"matches"`
	DataSource  string           `json:"data_source"`
	UnmappedMsg string           `json:"unmapped_msg,omitempty"`
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 3
	case SeverityMedium:
		return 2
	default:
		return 1
	}
}

func maxSeverity(matches []Match) Severity {
	if len(matches) == 0 {
		return SeverityLow
	}
	best := SeverityLow
	for _, m := range matches {
		if severityRank(m.Severity) > severityRank(best) {
			best = m.Severity
		}
	}
	return best
}

// DataSourceForEventType maps kwatch event types to kernel tracepoints.
func DataSourceForEventType(t string) string {
	switch t {
	case "exec":
		return "tracepoint/syscalls/sys_enter_execve"
	case "exit":
		return "tracepoint/sched/sched_process_exit"
	case "connect":
		return "tracepoint/syscalls/sys_enter_connect"
	case "accept":
		return "tracepoint/syscalls/sys_enter_accept, sys_exit_accept"
	case "open":
		return "tracepoint/syscalls/sys_enter_openat"
	default:
		return "eBPF ring buffer"
	}
}
