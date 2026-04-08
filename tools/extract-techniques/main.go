// Command extract-techniques streams MITRE enterprise-attack STIX JSON and writes a slim technique map.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

var tidRe = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)

type techniqueOut struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	URL         string `json:"url"`
}

type extRef struct {
	SourceName string `json:"source_name"`
	ExternalID string `json:"external_id"`
	URL        string `json:"url"`
}

type attackPattern struct {
	Type               string   `json:"type"`
	Name               string   `json:"name"`
	Description        string   `json:"description"`
	ExternalReferences []extRef `json:"external_references"`
}

func main() {
	inPath := flag.String("in", "", "path to enterprise-attack.json")
	outPath := flag.String("out", "", "output techniques_embed.json path")
	maxDesc := flag.Int("max-desc", 600, "max description runes (truncated)")
	flag.Parse()
	if *inPath == "" || *outPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	f, err := os.Open(*inPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open input: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	out, err := extract(f, *maxDesc)
	if err != nil {
		fmt.Fprintf(os.Stderr, "extract: %v\n", err)
		os.Exit(1)
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outPath, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote %d techniques to %s\n", len(out), *outPath)
}

func extract(r io.Reader, maxDesc int) (map[string]techniqueOut, error) {
	dec := json.NewDecoder(r)
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("expected object")
	}

	result := make(map[string]techniqueOut)

	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := keyTok.(string)
		if key != "objects" {
			if err := skipJSONValue(dec); err != nil {
				return nil, err
			}
			continue
		}

		tok, err = dec.Token()
		if err != nil {
			return nil, err
		}
		if d, ok := tok.(json.Delim); !ok || d != '[' {
			return nil, fmt.Errorf("objects: expected array")
		}

		for dec.More() {
			var raw json.RawMessage
			if err := dec.Decode(&raw); err != nil {
				return nil, err
			}
			var probe struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(raw, &probe) != nil || probe.Type != "attack-pattern" {
				continue
			}
			var ap attackPattern
			if err := json.Unmarshal(raw, &ap); err != nil {
				continue
			}
			tid, url := pickTechniqueRef(ap.ExternalReferences)
			if tid == "" || !tidRe.MatchString(tid) {
				continue
			}
			if url == "" {
				url = "https://attack.mitre.org/techniques/" + strings.ReplaceAll(tid, ".", "/")
			}
			desc := truncateRunes(strings.TrimSpace(ap.Description), maxDesc)
			result[tid] = techniqueOut{
				Name:        ap.Name,
				Description: desc,
				URL:         url,
			}
		}

		_, err = dec.Token()
		if err != nil {
			return nil, err
		}
		break
	}

	return result, nil
}

func pickTechniqueRef(refs []extRef) (id, url string) {
	for _, ref := range refs {
		if ref.SourceName == "mitre-attack" && tidRe.MatchString(ref.ExternalID) {
			return ref.ExternalID, ref.URL
		}
	}
	for _, ref := range refs {
		if tidRe.MatchString(ref.ExternalID) {
			return ref.ExternalID, ref.URL
		}
	}
	return "", ""
}

func skipJSONValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	switch d {
	case '{':
		for dec.More() {
			if _, err := dec.Token(); err != nil {
				return err
			}
			if err := skipJSONValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	case '[':
		for dec.More() {
			if err := skipJSONValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	default:
		return nil
	}
}

func truncateRunes(s string, max int) string {
	if max <= 0 || utf8.RuneCountInString(s) <= max {
		return s
	}
	runes := []rune(s)
	if len(runes) > max {
		return string(runes[:max]) + "…"
	}
	return s
}
