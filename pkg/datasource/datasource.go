// Package datasource provides a WASM-safe random-access view over APK bytes.
// It deliberately avoids os.File-specific APIs and works with any io.ReaderAt.
package datasource

import (
	"errors"
	"fmt"
	"io"
)

// DataSource is a random-access, sliceable view of APK bytes.
type DataSource interface {
	Size() int64
	ReadAt(p []byte, off int64) (int, error)
	Slice(off, length int64) DataSource
}

// Bytes is an in-memory DataSource.
type Bytes struct {
	b   []byte
	off int64
	n   int64
}

func NewBytes(b []byte) *Bytes { return &Bytes{b: b, off: 0, n: int64(len(b))} }

func (s *Bytes) Size() int64 { return s.n }

func (s *Bytes) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off > s.n {
		return 0, fmt.Errorf("datasource: read off=%d out of bounds (size=%d)", off, s.n)
	}
	avail := s.n - off
	if int64(len(p)) > avail {
		n := copy(p, s.b[s.off+off:s.off+s.n])
		return n, io.EOF
	}
	n := copy(p, s.b[s.off+off:s.off+off+int64(len(p))])
	return n, nil
}

func (s *Bytes) Slice(off, length int64) DataSource {
	if off < 0 || length < 0 || off+length > s.n {
		panic(fmt.Sprintf("datasource: slice out of range off=%d len=%d size=%d", off, length, s.n))
	}
	return &Bytes{b: s.b, off: s.off + off, n: length}
}

// FullBytes returns the underlying byte slice for in-memory sources.
// Returns ErrNotInMemory if the source is not memory-backed (e.g. a Reader-based one).
func (s *Bytes) FullBytes() []byte { return s.b[s.off : s.off+s.n] }

// ReaderAt wraps any io.ReaderAt with a known size.
type ReaderAt struct {
	r   io.ReaderAt
	off int64
	n   int64
}

func NewReaderAt(r io.ReaderAt, size int64) *ReaderAt {
	return &ReaderAt{r: r, off: 0, n: size}
}

func (s *ReaderAt) Size() int64 { return s.n }

func (s *ReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off > s.n {
		return 0, fmt.Errorf("datasource: read off=%d out of bounds (size=%d)", off, s.n)
	}
	avail := s.n - off
	read := int64(len(p))
	if read > avail {
		read = avail
	}
	n, err := s.r.ReadAt(p[:read], s.off+off)
	if err == nil && read < int64(len(p)) {
		err = io.EOF
	}
	return n, err
}

func (s *ReaderAt) Slice(off, length int64) DataSource {
	if off < 0 || length < 0 || off+length > s.n {
		panic(fmt.Sprintf("datasource: slice out of range off=%d len=%d size=%d", off, length, s.n))
	}
	return &ReaderAt{r: s.r, off: s.off + off, n: length}
}

// ReadAll loads the entire DataSource into a byte slice.
func ReadAll(ds DataSource) ([]byte, error) {
	if ds.Size() > (1 << 31) {
		return nil, errors.New("datasource: too large to read all")
	}
	buf := make([]byte, ds.Size())
	_, err := ds.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf, nil
}
