package outputs

import (
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/mitre"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/snapshot"
)

type Output interface {
	Init() error
	SendSnapshot(snap *snapshot.SnapshotJSON) error
	SendEvent(ev *mitre.EnrichedEvent) error
	Close() error
}
