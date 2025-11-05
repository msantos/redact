package main

import (
	"io"
	"os"
)

type stdio struct {
	*state

	r *os.File
	w *os.File
}

func (rw *stdio) Open() error {
	rw.w = os.Stdout
	return nil
}

func (rw *stdio) Close() error {
	return nil
}

func (rw *stdio) In() io.Reader {
	return rw.r
}

func (rw *stdio) Out() io.Writer {
	return rw.w
}
