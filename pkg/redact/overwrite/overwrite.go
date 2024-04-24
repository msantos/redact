// Package overwrite selects the redaction method.
package overwrite

import "strings"

type Replacer interface {
	Replace(string) string
}

type Redact struct {
	Text string
}

type Mask struct {
	Char byte
}

func (r *Redact) Replace(s string) string {
	return r.Text
}

func (m *Mask) Replace(s string) string {
	return strings.Repeat(string(m.Char), len(s))
}

func (r *Redact) String() string {
	return "redact"
}

func (m *Mask) String() string {
	return "mask"
}
