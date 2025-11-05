package fdpair

import (
	"io"
)

type FD interface {
	Open() error
	Close() error
	In() io.Reader
	Out() io.Writer
}
