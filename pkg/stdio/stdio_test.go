package stdio_test

import (
	"os"
	"path/filepath"
	"testing"

	"codeberg.org/msantos/redact/pkg/stdio"
)

func TestOpen(t *testing.T) {
	f, err := stdio.Open("-")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if f.Name() != "-" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWrite(t *testing.T) {
	dir, err := os.MkdirTemp("", "redact_testwrite")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.RemoveAll(dir)

	name := filepath.Join(dir, "file")
	if err := os.WriteFile(name, []byte("abcdef"), 0666); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f, err := stdio.Open(name, stdio.WithInPlace(true))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, err := f.WriteString("test123"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Source file is unmodified.
	b0 := make([]byte, 6)
	if _, err := f.Read(b0); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(b0) != "abcdef" {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := f.Close(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(b) != "test123" {
		t.Fatalf("unexpected error: %s", b)
	}
}
