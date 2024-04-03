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
	"github.com/zricethezav/gitleaks/v8/report"
)

const ReplacementText = "**REDACTED**"

type Opt struct {
	redact string
	rules  string
	mask   bool
}

type Option func(*Opt)

// WithRedactText sets redaction replacement text. The default is
// **REDACT**.
func WithRedactText(s string) Option {
	return func(o *Opt) {
		if s != "" {
			o.redact = s
		}
	}
}

// WithMask overwrites each character of the secret with the first letter
// of the redaction string.
func WithMask(b bool) Option {
	return func(o *Opt) {
		o.mask = b
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

func New(opt ...Option) *Opt {
	o := &Opt{
		redact: ReplacementText,
		rules:  config.DefaultConfig,
	}

	for _, fn := range opt {
		fn(o)
	}

	return o
}

func (o *Opt) replace(s string) string {
	if o.mask {
		return strings.Repeat(string(o.redact[0]), len(s))
	}
	return o.redact
}

func (o *Opt) Parse(s string) (string, error) {
	d, err := newDetectorFromTOML(o.rules)
	if err != nil {
		return s, err
	}

	findings := d.DetectString(s)

	fset := token.NewFileSet()
	f := fset.AddFile("", -1, len(s))
	f.SetLinesForContent([]byte(s))

	// Reverse sort the findings (last line/col first): replacing
	// a secret will not affect the offset of the next finding.
	slices.SortFunc(findings, func(a, b report.Finding) int {
		if n := cmp.Compare(b.StartLine, a.StartLine); n != 0 {
			return n
		}
		return cmp.Compare(b.StartColumn, a.StartColumn)
	})

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
	// The gitleaks appears to work as follows for the string "abc\n\n\n123\n":
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
	for _, finding := range findings {
		nl := 1 // gitleaks column offset is 1-based.
		if finding.StartLine > 0 {
			nl++ // Newline included in column count at start of line.
		}
		pos := f.LineStart(finding.StartLine + 1)
		// Convert 1-based column offset to 0-based string offset accounting for newline.
		off := f.Offset(pos) + (finding.StartColumn - nl)
		off += len(finding.Match) - len(finding.Secret)
		s = s[:off] + o.replace(finding.Secret) + s[off+len(finding.Secret):]
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
