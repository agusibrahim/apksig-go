// Package buf provides length-prefixed slice utilities used throughout the
// APK Signing Block format. Java apksig calls these via ByteBuffer; we reuse a
// stateful Reader for the same effect.
package buf

import (
	"encoding/binary"
	"fmt"
)

// Reader walks a little-endian byte slice, consuming length-prefixed regions.
type Reader struct {
	Buf []byte
	Off int
}

func New(b []byte) *Reader { return &Reader{Buf: b} }

func (r *Reader) Remaining() int { return len(r.Buf) - r.Off }

func (r *Reader) U32() (uint32, error) {
	if r.Off+4 > len(r.Buf) {
		return 0, fmt.Errorf("u32 underflow at %d", r.Off)
	}
	v := binary.LittleEndian.Uint32(r.Buf[r.Off : r.Off+4])
	r.Off += 4
	return v, nil
}

func (r *Reader) U64() (uint64, error) {
	if r.Off+8 > len(r.Buf) {
		return 0, fmt.Errorf("u64 underflow at %d", r.Off)
	}
	v := binary.LittleEndian.Uint64(r.Buf[r.Off : r.Off+8])
	r.Off += 8
	return v, nil
}

// LengthPrefixedSlice returns a sub-Reader of length read from a uint32 prefix.
func (r *Reader) LengthPrefixedSlice() (*Reader, error) {
	n, err := r.U32()
	if err != nil {
		return nil, err
	}
	if int(n) > r.Remaining() {
		return nil, fmt.Errorf("length-prefixed slice overflow: want %d have %d", n, r.Remaining())
	}
	sub := r.Buf[r.Off : r.Off+int(n)]
	r.Off += int(n)
	return &Reader{Buf: sub}, nil
}

// LengthPrefixedBytes reads a uint32 length and returns the raw bytes.
func (r *Reader) LengthPrefixedBytes() ([]byte, error) {
	sub, err := r.LengthPrefixedSlice()
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(sub.Buf))
	copy(out, sub.Buf)
	return out, nil
}
