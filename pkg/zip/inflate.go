package zip

import (
	"bytes"
	"compress/flate"
	"io"
)

func inflate(raw []byte, expectedSize int) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(raw))
	defer r.Close()
	if expectedSize > 0 {
		out := make([]byte, expectedSize)
		_, err := io.ReadFull(r, out)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return nil, err
		}
		return out, nil
	}
	return io.ReadAll(r)
}
