// redact secrets from files using gitleaks rules.
//
// By default, the redacted text is written to stdout. Use the -i option
// to modify the source file.
package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"codeberg.org/msantos/redact/pkg/redact"
	"codeberg.org/msantos/redact/pkg/redact/overwrite"
	"codeberg.org/msantos/redact/pkg/stdio"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	version = "0.3.0"
)

type state struct {
	inplace bool
	skip    []string
}

func usage() {
	fmt.Fprintf(os.Stderr, `%s v%s
Usage: %s [<option>] <file|directory|-> <...>

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

func getenv(s, def string) string {
	if v, ok := os.LookupEnv(s); ok {
		return v
	}
	return def
}

func main() {
	globs := getenv("REDACT_SKIP", ".git .gitleaks.toml")

	remove := flag.String("remove", "redact", "Redaction method: redact, mask")
	substitute := flag.String("substitute", redact.ReplacementText, "Text used to overwrite secrets")
	flag.StringVar(substitute, "s", redact.ReplacementText, "Text used to overwrite secrets")
	inplace := flag.Bool("inplace", false, "Redact the file in-place")
	flag.BoolVar(inplace, "i", false, "Redact the file in-place")
	rules := flag.String("rules", "", "Path to file containing gitleaks rules")
	logLevel := flag.String("log-level", zerolog.LevelErrorValue, "Set log level")
	skip := flag.String("skip", globs, "Skip glob matches in directories")
	flag.StringVar(skip, "S", globs, "Skip glob matches in directories")

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

	b, err := readRules(*rules)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	st := &state{
		inplace: *inplace,
		skip:    strings.Fields(*skip),
	}

	var replace overwrite.Replacer = &overwrite.Redact{Text: *substitute}

	before, after, ok := strings.Cut(*remove, ":")

	switch before {
	case "redact":
	case "mask":
		unmasked := 0
		if ok {
			n, err := strconv.Atoi(after)
			if err != nil {
				log.Fatal().Msg(err.Error())
			}
			if n < 0 || n > 100 {
				log.Fatal().Str("arg", after).Msg("unmasked value must be a percentage in range 0-100")
			}
			unmasked = n
		}

		var char byte = '*'
		if len(*substitute) > 0 {
			char = (*substitute)[0]
		}
		replace = &overwrite.Mask{Char: char, Unmasked: unmasked}
	default:
		log.Fatal().Str("arg", before).Msg("invalid option for --remove")
	}

	red := redact.New(
		redact.WithOverwrite(replace),
		redact.WithRules(string(b)),
	)

	for _, v := range flag.Args() {
		if fi, err := os.Stat(v); err == nil && fi.IsDir() {
			if err := filepath.WalkDir(v, st.walkFunc(red)); err != nil {
				log.Fatal().Str("path", v).Msg(err.Error())
			}
			continue
		}
		if err := st.run(v, red); err != nil {
			log.Fatal().Str("path", v).Msg(err.Error())
		}
	}
}

func (st *state) walkFunc(red *redact.Opt) fs.WalkDirFunc {
	return func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		for _, pattern := range st.skip {
			matched, err := filepath.Match(filepath.Join(filepath.Dir(path), pattern), path)
			if err != nil {
				return err
			}
			if !matched {
				log.Debug().Str("path", path).Str("match", pattern).Msg("glob")
				continue
			}
			log.Warn().Str("path", path).Str("match", pattern).Msg("skipped")
			if de.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if de.Type() != 0 {
			return nil
		}

		log.Info().Str("path", path).Msg("matched")

		return st.run(path, red)
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

func readRules(s string) ([]byte, error) {
	if s != "" {
		return os.ReadFile(s)
	}
	b, _ := os.ReadFile(".gitleaks.toml")
	return b, nil
}
