// Package overwrite selects the redaction method.
package overwrite

import (
	"strings"
)

type Replacer interface {
	Replace(string) string
}

type Redact struct {
	Text string
}

type Mask struct {
	Char     byte
	Unmasked int
}

func (r *Redact) Replace(s string) string {
	return r.Text
}

func (m *Mask) Replace(s string) string {
	l := len(s)

	if m.Unmasked <= 0 {
		return strings.Repeat(string(m.Char), l)
	} else if m.Unmasked >= 100 {
		return s
	}

	unmasked := (l * m.Unmasked / 100) / 2
	masked := l - unmasked*2
	return s[:unmasked] + strings.Repeat(string(m.Char), masked) + s[unmasked+masked:]
}
