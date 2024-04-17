package stdio_test

import (
	"fmt"

	"codeberg.org/msantos/redact/pkg/stdio"
)

func ExampleOpen() {
	f, err := stdio.Open("-")
	if err != nil {
		fmt.Printf("unexpected error: %v", err)
		return
	}
	_, _ = f.WriteString("stdout")
	// Output: stdout
}
