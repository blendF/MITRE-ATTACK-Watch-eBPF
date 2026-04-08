package mitre

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/ismajl-ramadani/kwatch-ebpf/internal/models"
)

// Mapper enriches kernel events with MITRE matches using heuristic rules.
type Mapper struct {
	db *DB
}

func NewMapper(db *DB) *Mapper {
	return &Mapper{db: db}
}

func newEventID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Enrich applies mapping rules and resolves technique names from the DB.
func (m *Mapper) Enrich(ev models.EventJSON) *EnrichedEvent {
	matches := matchRules(ev)
	matches = m.resolveNames(matches)

	sev := maxSeverity(matches)
	unmapped := ""
	if len(matches) == 0 {
		unmapped = "No MITRE mapping rule matched this event; severity defaults to low."
	}

	return &EnrichedEvent{
		ID:          newEventID(),
		ObservedAt:  time.Now().UTC(),
		Event:       ev,
		Severity:    sev,
		Matches:     matches,
		DataSource:  DataSourceForEventType(ev.Type),
		UnmappedMsg: unmapped,
	}
}

func (m *Mapper) resolveNames(matches []Match) []Match {
	if m == nil || m.db == nil {
		return matches
	}
	out := make([]Match, 0, len(matches))
	for _, mt := range matches {
		if info, ok := m.db.Lookup(mt.TechniqueID); ok {
			if mt.Name == "" {
				mt.Name = info.Name
			}
			if mt.URL == "" {
				mt.URL = info.URL
			}
			if mt.Description == "" {
				mt.Description = info.Description
			}
		} else {
			if mt.Name == "" {
				mt.Name = mt.TechniqueID
			}
			if mt.URL == "" {
				mt.URL = "https://attack.mitre.org/"
			}
		}
		out = append(out, mt)
	}
	return out
}

func matchRules(ev models.EventJSON) []Match {
	var ms []Match
	switch ev.Type {
	case "open":
		ms = append(ms, matchOpen(ev.Path)...)
	case "connect":
		ms = append(ms, matchConnect(ev.DstAddr)...)
	case "accept":
		ms = append(ms, matchAccept(ev.DstAddr)...)
	case "exec":
		ms = append(ms, matchExec(ev)...)
	case "exit":
		// Little ATT&CK signal from exit alone; leave unmapped.
	}
	return dedupeMatches(ms)
}

func matchOpen(path string) []Match {
	p := path
	if isCredentialCritical(p) {
		return []Match{
			{TechniqueID: "T1552", Rationale: "Open on a path associated with credentials or secret material (e.g. shadow store or SSH private key).", Severity: SeverityCritical},
			{TechniqueID: "T1552.001", Rationale: "Access to unsecured credentials in local files (password hashes, keys).", Severity: SeverityCritical},
			{TechniqueID: "T1005", Rationale: "Reading data from a local system source that may contain sensitive authentication data.", Severity: SeverityCritical},
		}
	}
	if models.IsSensitive(p) {
		return []Match{
			{TechniqueID: "T1083", Rationale: "Process opened a path flagged as sensitive for discovery or collection.", Severity: SeverityMedium},
			{TechniqueID: "T1005", Rationale: "Local file read that may support credential access or collection.", Severity: SeverityMedium},
		}
	}
	return nil
}

func isCredentialCritical(path string) bool {
	if path == "/etc/shadow" || path == "/etc/gshadow" {
		return true
	}
	if strings.Contains(path, "/.ssh/") && (strings.Contains(path, "id_rsa") || strings.Contains(path, "id_ed25519")) {
		return true
	}
	return false
}

func matchConnect(dst string) []Match {
	ms := []Match{
		{TechniqueID: "T1071", Rationale: "Outbound TCP connection observed; may align with application-layer C2 or tool traffic (heuristic).", Severity: SeverityMedium},
	}
	if suspiciousC2Port(dst) {
		ms = append(ms, Match{
			TechniqueID: "T1571",
			Rationale:   "Connection to a non-standard or commonly abused destination port (heuristic bump).",
			Severity:    SeverityCritical,
		})
	}
	return ms
}

func matchAccept(dst string) []Match {
	_ = dst
	return []Match{
		{TechniqueID: "T1190", Rationale: "Inbound connection accepted on a listening socket; may reflect exposed service exploitation (heuristic).", Severity: SeverityMedium},
		{TechniqueID: "T1071", Rationale: "Network service accepting connections; traffic may be used for command and control (heuristic).", Severity: SeverityMedium},
	}
}

func matchExec(ev models.EventJSON) []Match {
	cmd := strings.ToLower(ev.Command + " " + ev.Args + " " + ev.Path)
	ms := []Match{
		{TechniqueID: "T1059", Rationale: "New process execution observed; interpreters and scripts map to command/script execution.", Severity: SeverityLow},
		{TechniqueID: "T1204", Rationale: "User-driven execution path: a process was started (may include user-opened content or interactive use).", Severity: SeverityLow},
	}
	if suspiciousExec(cmd) {
		ms = append(ms,
			Match{TechniqueID: "T1105", Rationale: "Invocation suggests ingress tool transfer (e.g. curl/wget fetching remote content) — heuristic.", Severity: SeverityMedium},
			Match{TechniqueID: "T1027", Rationale: "Arguments suggest obfuscated or encoded execution (e.g. base64) — heuristic.", Severity: SeverityMedium},
		)
	}
	return ms
}

func suspiciousExec(cmd string) bool {
	keywords := []string{
		"curl ", "wget ", "base64", "python -c", "perl -e", "ruby -e",
		"/dev/tcp", "bash -i", "nc -", "ncat ", "socat ",
	}
	for _, k := range keywords {
		if strings.Contains(cmd, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

func suspiciousC2Port(dst string) bool {
	// dst like "1.2.3.4:4444"
	idx := strings.LastIndex(dst, ":")
	if idx < 0 {
		return false
	}
	port := dst[idx+1:]
	switch port {
	case "4444", "1337", "6667", "6666", "31337", "1234", "9001":
		return true
	default:
		return false
	}
}

func dedupeMatches(ms []Match) []Match {
	byID := make(map[string]Match)
	for _, m := range ms {
		cur, ok := byID[m.TechniqueID]
		if !ok || severityRank(m.Severity) > severityRank(cur.Severity) {
			byID[m.TechniqueID] = m
		}
	}
	out := make([]Match, 0, len(byID))
	for _, m := range byID {
		out = append(out, m)
	}
	return out
}
