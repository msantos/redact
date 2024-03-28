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

	for _, finding := range findings {
		pos := f.LineStart(finding.StartLine + 1)
		off := f.Offset(pos) + finding.StartColumn - 2 // XXX why 2?
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
