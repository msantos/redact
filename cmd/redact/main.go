// redact secrets from files using gitleaks rules.
//
// By default, the redacted text is written to stdout. Use the -i option
// to modify the source file.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path"

	"codeberg.org/msantos/redact/pkg/redact"
	"codeberg.org/msantos/redact/pkg/redact/overwrite"
	"codeberg.org/msantos/redact/pkg/stdio"
	"github.com/rs/zerolog"
)

const (
	version = "0.2.1"
)

type state struct {
	inplace bool
}

func usage() {
	fmt.Fprintf(os.Stderr, `%s v%s
Usage: %s [<option>] <file|-> <...>

Redact secrets from files.

Examples:

  # redact files in-place
  redact -i file.txt file.json file.yml

  # from stdin
  cat file | redact -

Options:

`, path.Base(os.Args[0]), version, os.Args[0])
	flag.PrintDefaults()
}

func main() {
	remove := flag.String("remove", "redact", "Redaction method: redact, mask")
	substitute := flag.String("substitute", redact.ReplacementText, "Text used to overwrite secrets")
	flag.StringVar(substitute, "s", redact.ReplacementText, "Text used to overwrite secrets")
	inplace := flag.Bool("inplace", false, "Redact the file in-place")
	flag.BoolVar(inplace, "i", false, "Redact the file in-place")
	rules := flag.String("rules", "", "Path to file containing gitleaks rules")
	logLevel := flag.String("log-level", zerolog.LevelErrorValue, "Set log level")

	flag.Usage = func() { usage() }
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	l, err := zerolog.ParseLevel(*logLevel)
	if err != nil {
		flag.Usage()
		os.Exit(2)
	}
	zerolog.SetGlobalLevel(l)

	if *rules != "" {
		_, err := os.Stat(*rules)
		if err != nil {
			log.Fatalln(*rules, err)
		}
	}

	st := &state{
		inplace: *inplace,
	}

	var replace overwrite.Replacer = &overwrite.Redact{Text: *substitute}
	if *remove == "mask" {
		var char byte = '*'
		if len(*substitute) > 0 {
			char = (*substitute)[0]
		}
		replace = &overwrite.Mask{Char: char}
	}

	red := redact.New(
		redact.WithOverwrite(replace),
		redact.WithRules(readRules(*rules)),
	)

	for _, v := range flag.Args() {
		if err := st.run(v, red); err != nil {
			log.Fatalln(v, err)
		}
	}
}

func (st *state) run(name string, red *redact.Opt) error {
	f, err := stdio.Open(name, stdio.WithInPlace(st.inplace))
	if err != nil {
		return err
	}

	defer func() {
		f.SetErr(err)
		err = f.Close()
	}()

	b, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	s, err := red.Redact(string(b))
	if err != nil {
		return err
	}

	if _, err := f.WriteString(s); err != nil {
		return err
	}

	return nil
}

func readRules(s string) string {
	if s == "" {
		s = ".gitleaks.toml"
	}
	b, err := os.ReadFile(s)
	if err != nil {
		return ""
	}
	return string(b)
}
