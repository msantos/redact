package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path"

	"codeberg.org/msantos/redact/pkg/redact"
	"codeberg.org/msantos/redact/pkg/tmpfile"
	"github.com/rs/zerolog"
)

const (
	version = "0.1.0"
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
  redact file.txt file.json file.yml

  # from stdin
  cat file | redact -

Options:

		`, path.Base(os.Args[0]), version, os.Args[0])
	flag.PrintDefaults()
}

func main() {
	mask := flag.Bool("mask", false, "Mask secret")
	substitute := flag.String("substitute", redact.ReplacementText, "Text used to overwrite secrets")
	flag.StringVar(substitute, "s", redact.ReplacementText, "Text used to overwrite secrets")
	inplace := flag.Bool("inplace", false, "Redact the file in-place")
	flag.BoolVar(inplace, "i", false, "Redact the file in-place")
	rules := flag.String("rules", "", "Path to file containing gitleaks rules")
	logLevel := flag.String("log-level", zerolog.LevelErrorValue, "Set log level")

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

	red := redact.New(
		redact.WithMask(*mask),
		redact.WithRedactText(*substitute),
		redact.WithRules(readRules(*rules)),
	)

	for _, v := range flag.Args() {
		if err := st.run(v, red); err != nil {
			log.Fatalln(v, err)
		}
	}
}

func (st *state) run(name string, red *redact.Opt) error {
	f, err := tmpfile.Open(name, tmpfile.WithInPlace(st.inplace))
	if err != nil {
		return err
	}

	defer func() {
		err = f.CloseWithError(err)
	}()

	b, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	s, err := red.Parse(string(b))
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
