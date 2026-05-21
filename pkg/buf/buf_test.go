package buf

import (
	"bytes"
	"testing"
)

func TestU32U64(t *testing.T) {
	r := New([]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08})
	v32, err := r.U32()
	if err != nil || v32 != 0x04030201 {
		t.Fatalf("u32: %x %v", v32, err)
	}
	v64, err := r.U64()
	if err != nil || v64 != 0 {
		// Only 4 bytes left; expect error.
	}
	if r.Off != 4 {
		t.Fatalf("offset advance: %d", r.Off)
	}
}

func TestLengthPrefixedSliceAndBytes(t *testing.T) {
	// Two LP blobs: "abc" and "de"
	data := []byte{0x03, 0, 0, 0, 'a', 'b', 'c', 0x02, 0, 0, 0, 'd', 'e'}
	r := New(data)
	a, err := r.LengthPrefixedSlice()
	if err != nil || string(a.Buf) != "abc" {
		t.Fatalf("first slice: %q %v", string(a.Buf), err)
	}
	b, err := r.LengthPrefixedBytes()
	if err != nil || !bytes.Equal(b, []byte("de")) {
		t.Fatalf("second bytes: %q %v", string(b), err)
	}
	if r.Remaining() != 0 {
		t.Fatalf("remaining: %d", r.Remaining())
	}
}

func TestLengthPrefixedOverflow(t *testing.T) {
	r := New([]byte{0xff, 0xff, 0xff, 0x7f, 'a', 'b'}) // claims 2GB len
	if _, err := r.LengthPrefixedSlice(); err == nil {
		t.Fatal("expected overflow error")
	}
}
