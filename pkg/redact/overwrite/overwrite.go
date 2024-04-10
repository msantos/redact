// Package overwrite selects the redaction method.
package overwrite

type Remove struct {
	name string
}

var (
	Redact = &Remove{"redact"}
	Mask   = &Remove{"mask"}
)

func FromString(s string) *Remove {
	switch s {
	case "mask":
		return Mask
	case "", "redact":
		return Redact
	}

	return nil
}

func (y *Remove) String() string {
	return y.name
}
