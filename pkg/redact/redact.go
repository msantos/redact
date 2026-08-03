// Package redact parses a file removing any detected secrets.
package redact

import (
	"cmp"
	_ "embed"
	"go/token"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"go.iscode.ca/redact/pkg/redact/overwrite"
)

const ReplacementText = "**REDACTED**"

type Opt struct {
	rules     string
	overwrite overwrite.Replacer
	d         *detect.Detector
	err       error
}

type Option func(*Opt)

// WithOverwrite sets the method for overwriting secrets:
//
//   - redact: substitute the secret with the redaction string
//   - mask: set each character of the secret with the first letter of the
//     redaction string
func WithOverwrite(overwrite overwrite.Replacer) Option {
	return func(o *Opt) {
		o.overwrite = overwrite
	}
}

// WithRules adds gitleaks rules to the configuration.
func WithRules(s string) Option {
	return func(o *Opt) {
		if s != "" {
			o.rules = s
		}
	}
}

// New sets the configuration for the redaction process.
func New(opt ...Option) *Opt {
	o := &Opt{
		rules:     config.DefaultConfig,
		overwrite: &overwrite.Redact{Text: ReplacementText},
	}

	for _, fn := range opt {
		fn(o)
	}

	d, err := newDetectorFromTOML(o.rules)
	if err != nil {
		o.err = err
	}
	o.d = d

	return o
}

func (o *Opt) Err() error {
	return o.err
}

// Redact removes secrets detected in the provided string.
func (o *Opt) Redact(s string) (string, error) {
	if o.err != nil {
		return "", o.err
	}

	findings := o.d.DetectString(s)

	fset := token.NewFileSet()
	f := fset.AddFile("", -1, len(s))
	f.SetLinesForContent([]byte(s))

	type interval struct {
		start int
		end   int
	}

	var intervals []interval

	for _, finding := range findings {
		if finding.Secret == "" {
			continue
		}
		// * token package
		//
		// 	* line: 1-based
		// 	* offset: 0-based (from start of file to beginning of line)
		//
		// * gitleaks detect package
		//
		//	* line: 0-based
		//	* column: 1-based, includes newline at start of line(?)
		//
		// gitleaks parses the string "abc\n\n\n123\n" as:
		//
		// abc
		// ^0:1
		// \n
		// ^1:1
		// \n
		// ^2:1
		// \n123
		// ^3:1
		//   ^3:2
		// \n
		// ^4:1
		//
		// For example, for the content:
		//
		// 		12345
		// 		ABCDE
		//
		// 01234 567890 (0-based)
		// 12345 678901 (1-based)
		// 12345\nABCDE\n
		// ^ TOKEN:1,offset=1/0 GITLEAKS:0:1
		//        ^ GITLEAKS:1:2
		//        ^ TOKEN:2,offset=7/6
		nl := 1 // gitleaks column offset is 1-based.
		if finding.StartLine > 0 {
			nl++ // Newline included in column count at start of line.
		}
		pos := f.LineStart(finding.StartLine + 1)
		// Convert 1-based column offset to 0-based string offset accounting for newline.
		off := f.Offset(pos) + (finding.StartColumn - nl)
		idx := strings.Index(finding.Match, finding.Secret)
		if idx == -1 {
			continue
		}
		off += idx
		intervals = append(intervals, interval{
			start: off,
			end:   off + len(finding.Secret),
		})
	}

	if len(intervals) == 0 {
		return s, nil
	}

	// Sort intervals by start ascending, then end descending.
	slices.SortFunc(intervals, func(a, b interval) int {
		if n := cmp.Compare(a.start, b.start); n != 0 {
			return n
		}
		return cmp.Compare(b.end, a.end)
	})

	// Merge overlapping or adjacent intervals.
	merged := []interval{intervals[0]}
	for _, curr := range intervals[1:] {
		prev := &merged[len(merged)-1]
		if curr.start <= prev.end {
			if curr.end > prev.end {
				prev.end = curr.end
			}
		} else {
			merged = append(merged, curr)
		}
	}

	// Redact merged intervals from right to left (descending).
	for i := len(merged) - 1; i >= 0; i-- {
		iv := merged[i]
		if iv.start >= 0 && iv.end <= len(s) && iv.start <= iv.end {
			secret := s[iv.start:iv.end]
			s = s[:iv.start] + o.overwrite.Replace(secret) + s[iv.end:]
		}
	}

	return s, nil
}

func newDetectorFromTOML(s string) (*detect.Detector, error) {
	viper.SetConfigType("toml")
	if err := viper.ReadConfig(strings.NewReader(s)); err != nil {
		return nil, err
	}

	var vc config.ViperConfig
	if err := viper.Unmarshal(&vc); err != nil {
		return nil, err
	}

	cfg, err := vc.Translate()
	if err != nil {
		return nil, err
	}

	// Overwrite the default private key rule with a regexp with non-greedy matching.
	cfg.Rules["private-key"] = config.Rule{
		Description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
		RuleID:      "private-key",
		Regex:       regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY( BLOCK)?-----[\s\S-]*?KEY( BLOCK)?----`),
		Keywords:    []string{"-----BEGIN"},
	}

	return detect.NewDetector(cfg), nil
}
