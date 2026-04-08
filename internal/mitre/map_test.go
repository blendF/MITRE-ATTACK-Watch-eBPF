package mitre

import (
	"testing"

	"github.com/ismajl-ramadani/kwatch-ebpf/internal/models"
)

func TestMapperEnrichExec(t *testing.T) {
	db, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	m := NewMapper(db)
	ev := m.Enrich(models.EventJSON{Type: "exec", Command: "bash", PID: 1})
	if ev.Severity != SeverityLow {
		t.Fatalf("exec baseline severity: got %s", ev.Severity)
	}
	if len(ev.Matches) < 1 {
		t.Fatal("expected at least one match for exec")
	}
}

func TestMapperEnrichShadowOpen(t *testing.T) {
	db, err := LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	m := NewMapper(db)
	ev := m.Enrich(models.EventJSON{Type: "open", Path: "/etc/shadow", Command: "cat", PID: 2})
	if ev.Severity != SeverityCritical {
		t.Fatalf("shadow open: got severity %s", ev.Severity)
	}
}
