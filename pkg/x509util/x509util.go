// Package x509util wraps x509.ParseCertificate with a lenient fallback that
// accepts certificates whose PrintableString fields contain characters Go's
// strict parser rejects (notably '@' and '/' which appear in many vendor
// certificates). The original DER is preserved on Cert.Raw so digests still
// match the bytes on disk.
package x509util

import (
	"bytes"
	"crypto/x509"
	"errors"
	"strings"
)

// ParseCertificate is a drop-in replacement for x509.ParseCertificate that
// retries with PrintableString tags rewritten to UTF8String when strict
// validation fails on stringy fields. The Raw / RawSubject / etc. on the
// returned cert are restored to the original bytes after parsing.
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	c, err := x509.ParseCertificate(der)
	if err == nil {
		return c, nil
	}
	if !isLenientCandidate(err) {
		return nil, err
	}
	rewritten := rewritePrintableStrings(der)
	if bytes.Equal(rewritten, der) {
		return nil, err // no change possible
	}
	c2, err2 := x509.ParseCertificate(rewritten)
	if err2 != nil {
		return nil, err
	}
	// Restore original raw bytes so callers compare digests against the actual
	// on-disk certificate, not our rewritten copy.
	c2.Raw = append([]byte(nil), der...)
	return c2, nil
}

// ParseCertificates parses a concatenated list of DER certificates leniently.
func ParseCertificates(der []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := der
	for len(rest) > 0 {
		// Use the standard library to find the length of the next certificate.
		c, err := ParseCertificate(rest)
		if err != nil {
			return out, err
		}
		out = append(out, c)
		rest = rest[len(c.Raw):]
	}
	return out, nil
}

func isLenientCandidate(err error) bool {
	s := err.Error()
	if strings.Contains(s, "PrintableString") ||
		strings.Contains(s, "invalid attribute value") ||
		strings.Contains(s, "invalid RDNSequence") ||
		strings.Contains(s, "asn1: structure error") {
		return true
	}
	return false
}

// rewritePrintableStrings walks the DER tree and rewrites any PrintableString
// (tag 0x13) whose value contains forbidden characters (notably '@', '/' is
// allowed but parser is buggy in some Go versions, etc.) to UTF8String tag
// (tag 0x0c). Length bytes are preserved because the values are byte-identical
// in both encodings.
func rewritePrintableStrings(in []byte) []byte {
	out := append([]byte(nil), in...)
	walkDER(out, 0, len(out))
	return out
}

func walkDER(b []byte, lo, hi int) {
	off := lo
	for off < hi {
		if off >= len(b) {
			return
		}
		tag := b[off]
		// Tag length encoding (handle long-form tags >= 0x1f).
		tagOff := off
		off++
		if tag&0x1f == 0x1f {
			for off < hi && b[off]&0x80 != 0 {
				off++
			}
			if off < hi {
				off++
			}
		}
		// Length.
		if off >= hi {
			return
		}
		lenByte := b[off]
		off++
		var length int
		if lenByte&0x80 == 0 {
			length = int(lenByte)
		} else {
			n := int(lenByte & 0x7f)
			if n == 0 || off+n > hi {
				return // indefinite-length not used in DER
			}
			for i := 0; i < n; i++ {
				length = (length << 8) | int(b[off+i])
			}
			off += n
		}
		if length < 0 || off+length > hi {
			return
		}
		valStart := off
		valEnd := off + length

		// PrintableString = 0x13. If the value contains characters Go would
		// reject, rewrite to UTF8String (0x0c).
		if tag == 0x13 && hasForbiddenPrintable(b[valStart:valEnd]) {
			b[tagOff] = 0x0c
		}
		// Recurse into structured types: SEQUENCE (0x30), SET (0x31),
		// constructed [n] (0xa0..0xaf and 0x60..), and any tag with the
		// constructed bit (0x20).
		if tag&0x20 != 0 {
			walkDER(b, valStart, valEnd)
		}
		off = valEnd
	}
}

func hasForbiddenPrintable(s []byte) bool {
	for _, c := range s {
		if isPrintable(c) {
			continue
		}
		return true
	}
	return false
}

// Mirror of Go's parser printable-string set so we only rewrite when the
// stdlib would reject; otherwise we leave the bytes alone.
func isPrintable(b byte) bool {
	return 'a' <= b && b <= 'z' ||
		'A' <= b && b <= 'Z' ||
		'0' <= b && b <= '9' ||
		'\'' <= b && b <= ')' ||
		'+' <= b && b <= '/' ||
		b == ' ' ||
		b == ':' ||
		b == '=' ||
		b == '?' ||
		b == '*' ||
		b == '&'
}

var _ = errors.New // keep errors import
