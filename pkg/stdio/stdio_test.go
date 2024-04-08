package stdio_test

import (
	"testing"

	"codeberg.org/msantos/redact/pkg/stdio"
)

func TestOpt_Name(t *testing.T) {
	f, err := stdio.Open("-")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Name() != "-" {
		t.Fatalf("unexpected error: %v", err)
	}
}
