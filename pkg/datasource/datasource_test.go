package datasource

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestBytesReadAt(t *testing.T) {
	b := NewBytes([]byte("Hello, world!"))
	if b.Size() != 13 {
		t.Errorf("size: %d", b.Size())
	}
	out := make([]byte, 5)
	n, err := b.ReadAt(out, 7)
	if err != nil || n != 5 || string(out) != "world" {
		t.Errorf("ReadAt: n=%d err=%v out=%q", n, err, out)
	}
}

func TestBytesSlice(t *testing.T) {
	b := NewBytes([]byte("abcdefghij"))
	s := b.Slice(2, 5).(*Bytes)
	if s.Size() != 5 {
		t.Errorf("slice size: %d", s.Size())
	}
	got, _ := ReadAll(s)
	if string(got) != "cdefg" {
		t.Errorf("slice content: %q", got)
	}
}

func TestBytesSliceOutOfRange(t *testing.T) {
	b := NewBytes([]byte("abc"))
	defer func() { _ = recover() }()
	b.Slice(2, 10) // should panic
	t.Error("expected panic for out-of-range slice")
}

func TestBytesReadAtEOF(t *testing.T) {
	b := NewBytes([]byte("ab"))
	out := make([]byte, 4)
	n, err := b.ReadAt(out, 0)
	if !errors.Is(err, io.EOF) || n != 2 {
		t.Errorf("expected EOF after 2 bytes, got n=%d err=%v", n, err)
	}
}

type strReaderAt struct{ s string }

func (r *strReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.s)) {
		return 0, io.EOF
	}
	n := copy(p, r.s[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func TestReaderAt(t *testing.T) {
	r := NewReaderAt(&strReaderAt{s: "abcdefgh"}, 8)
	out := make([]byte, 3)
	r.ReadAt(out, 4)
	if string(out) != "efg" {
		t.Errorf("read: %q", out)
	}
	got, _ := ReadAll(r.Slice(2, 4))
	if string(got) != "cdef" {
		t.Errorf("slice: %q", got)
	}
}

func TestReadAll(t *testing.T) {
	b := NewBytes(bytes.Repeat([]byte{0x01}, 1024))
	all, err := ReadAll(b)
	if err != nil || len(all) != 1024 {
		t.Errorf("readall: n=%d err=%v", len(all), err)
	}
	if !bytes.Equal(all, bytes.Repeat([]byte{0x01}, 1024)) {
		t.Error("content mismatch")
	}
}

func TestReadAllRejectsHugeSource(t *testing.T) {
	// fake a too-large size
	b := &Bytes{b: []byte{1, 2, 3}, off: 0, n: 1 << 32}
	_, err := ReadAll(b)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("expected too-large err, got %v", err)
	}
}
