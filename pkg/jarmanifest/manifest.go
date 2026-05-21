// Package jarmanifest parses META-INF/MANIFEST.MF and signature files (.SF).
// Both formats follow the same "main-section + per-entry section" layout
// where attributes are "Name: Value" lines, sections are blank-line separated,
// and continuation lines start with a single space.
package jarmanifest

import (
	"errors"
	"fmt"
	"strings"
)

// Section is one record (main section or per-entry section).
type Section struct {
	StartOffset int
	EndOffset   int // exclusive; covers the trailing blank line(s)
	Attrs       []Attribute
}

// Attribute is a single "Name: Value" line, with continuations folded.
type Attribute struct {
	Name  string
	Value string
}

// Get returns the value of the named attribute (case-insensitive on the name,
// matching the JAR spec) or "" if absent.
func (s *Section) Get(name string) string {
	for _, a := range s.Attrs {
		if strings.EqualFold(a.Name, name) {
			return a.Value
		}
	}
	return ""
}

// Name returns the "Name:" attribute (per-entry sections).
func (s *Section) Name() string { return s.Get("Name") }

// ParseAll parses the entire manifest/SF blob.
func ParseAll(data []byte) ([]Section, error) {
	p := parser{data: data}
	var sections []Section
	for {
		sec, ok, err := p.readSection()
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		sections = append(sections, sec)
	}
	return sections, nil
}

type parser struct {
	data []byte
	off  int
}

func (p *parser) readSection() (Section, bool, error) {
	// Skip leading blank lines.
	for p.off < len(p.data) && p.peekBlankLine() {
		p.consumeLine()
	}
	if p.off >= len(p.data) {
		return Section{}, false, nil
	}
	start := p.off
	var attrs []Attribute
	for {
		line, ok := p.readLogicalLine()
		if !ok {
			break
		}
		if line == "" {
			break
		}
		idx := strings.Index(line, ": ")
		if idx == -1 {
			// Tolerate "Name:" with empty value.
			if cidx := strings.IndexByte(line, ':'); cidx != -1 {
				attrs = append(attrs, Attribute{Name: line[:cidx], Value: ""})
				continue
			}
			return Section{}, false, fmt.Errorf("manifest: malformed line %q", line)
		}
		attrs = append(attrs, Attribute{Name: line[:idx], Value: line[idx+2:]})
	}
	return Section{StartOffset: start, EndOffset: p.off, Attrs: attrs}, true, nil
}

func (p *parser) peekBlankLine() bool {
	if p.off >= len(p.data) {
		return false
	}
	if p.data[p.off] == '\r' {
		if p.off+1 < len(p.data) && p.data[p.off+1] == '\n' {
			return true
		}
		return true
	}
	return p.data[p.off] == '\n'
}

func (p *parser) consumeLine() {
	for p.off < len(p.data) {
		c := p.data[p.off]
		p.off++
		if c == '\n' {
			return
		}
		if c == '\r' {
			if p.off < len(p.data) && p.data[p.off] == '\n' {
				p.off++
			}
			return
		}
	}
}

// readLogicalLine reads a line, folding continuation lines (those starting
// with a single space) into the previous one. Returns ("", false) at EOF and
// ("", true) for a blank line ending a section.
func (p *parser) readLogicalLine() (string, bool) {
	if p.off >= len(p.data) {
		return "", false
	}
	if p.peekBlankLine() {
		p.consumeLine()
		return "", true
	}
	var b strings.Builder
	first := true
	for {
		// Read one physical line (without trailing CR/LF).
		lineStart := p.off
		for p.off < len(p.data) && p.data[p.off] != '\r' && p.data[p.off] != '\n' {
			p.off++
		}
		if first {
			b.WriteString(string(p.data[lineStart:p.off]))
			first = false
		} else {
			// Continuation lines have a single leading space which is dropped.
			seg := p.data[lineStart:p.off]
			if len(seg) > 0 && seg[0] == ' ' {
				b.WriteString(string(seg[1:]))
			} else {
				b.WriteString(string(seg))
			}
		}
		// Consume CRLF / LF / CR.
		if p.off < len(p.data) {
			if p.data[p.off] == '\r' {
				p.off++
				if p.off < len(p.data) && p.data[p.off] == '\n' {
					p.off++
				}
			} else if p.data[p.off] == '\n' {
				p.off++
			}
		}
		// Continuation? next line begins with a single space.
		if p.off < len(p.data) && p.data[p.off] == ' ' {
			p.off++ // strip the leading space
			continue
		}
		break
	}
	return b.String(), true
}

// SectionBytes returns the raw bytes of a section (used for digest checking).
func SectionBytes(data []byte, s Section) ([]byte, error) {
	if s.StartOffset < 0 || s.EndOffset > len(data) || s.StartOffset > s.EndOffset {
		return nil, errors.New("section bounds out of range")
	}
	return data[s.StartOffset:s.EndOffset], nil
}
