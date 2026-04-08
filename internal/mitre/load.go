package mitre

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed techniques_embed.json
var embeddedTechniques []byte

// DB holds technique metadata keyed by ATT&CK ID (e.g. T1059).
type DB struct {
	techniques map[string]TechniqueInfo
}

// LoadEmbedded parses the go:embedded slim JSON produced from enterprise ATT&CK STIX.
func LoadEmbedded() (*DB, error) {
	var m map[string]TechniqueInfo
	if err := json.Unmarshal(embeddedTechniques, &m); err != nil {
		return nil, fmt.Errorf("parse embedded techniques: %w", err)
	}
	return &DB{techniques: m}, nil
}

func (d *DB) Lookup(id string) (TechniqueInfo, bool) {
	if d == nil {
		return TechniqueInfo{}, false
	}
	info, ok := d.techniques[id]
	return info, ok
}
