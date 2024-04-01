// Package stdio reads from sets the source for standard input and the
// destinaion for standard output:
//
//   - if the filename is "-", input is read from stdin and output is
//     written to stdout
//   - otherwise input is read from the named file with output written
//     to stdout
//   - if the WithInPlace option is set, a temporary file is created and
//     the original file overwritten when the file descriptor is closed
package stdio

import (
	"errors"
	"io"
	"os"
	"path"
)

type File struct {
	*os.File
	w    *os.File
	name string
}

type Opt struct {
	inplace bool
}

type Option func(*Opt)

// WithInPlace redacts the target file in-place.
func WithInPlace(b bool) Option {
	return func(o *Opt) {
		o.inplace = b
	}
}

func toOpt(opt ...Option) *Opt {
	o := &Opt{}

	for _, fn := range opt {
		fn(o)
	}

	return o
}

// Open opens the file using a temporary file by appending
// a random string to the filename. The file is renamed to the original name
// when it is closed.
//
// If the filename is "-", input is read from stdin and written to stdout.
func Open(name string, opt ...Option) (*File, error) {
	o := toOpt(opt...)

	if name == "-" {
		return &File{
			File: os.Stdin,
			w:    os.Stdout,
			name: name,
		}, nil
	}

	r, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	if !o.inplace {
		return &File{
			File: r,
			w:    os.Stdout,
			name: name,
		}, nil
	}

	w, err := os.CreateTemp(path.Dir(name), path.Base(name))
	if err != nil {
		return nil, err
	}
	return &File{
		File: r,
		w:    w,
		name: name,
	}, nil
}

// Name returns the original (non-temporary) filename.
func (f *File) Name() string {
	return f.name
}

func (f *File) Write(b []byte) (int, error) {
	return f.w.Write(b)
}

func (f *File) WriteAt(b []byte, off int64) (int, error) {
	return f.w.WriteAt(b, off)
}

func (f *File) WriteString(s string) (int, error) {
	return f.w.WriteString(s)
}

func (f *File) WriteTo(w io.Writer) (int64, error) {
	return f.w.WriteTo(w)
}

// Close unconditionally closes the file and renames to the original
// filename.
func (f *File) Close() error {
	return errors.Join(f.File.Close(), f.w.Close(), f.rename())
}

// CloseWithError closes the file and conditionally renames to the
// original filename based on the error argument:
//
//   - nil: file is renamed
//   - non-nil: the temporary file is deleted, the source file closed and
//     the error returned
func (f *File) CloseWithError(err error) error {
	if err != nil {
		return errors.Join(err, f.File.Close(), f.w.Close(), f.remove())
	}
	return f.Close()
}

func (f *File) rename() error {
	if f.w == os.Stdout {
		return nil
	}
	return os.Rename(f.w.Name(), f.name)
}

func (f *File) remove() error {
	if f.w == os.Stdout {
		return nil
	}
	return os.Remove(f.File.Name())
}
