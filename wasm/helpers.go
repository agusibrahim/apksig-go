//go:build js && wasm

package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func certsToAny(certs []*x509.Certificate) []interface{} {
	out := make([]interface{}, len(certs))
	for i, c := range certs {
		out[i] = map[string]interface{}{
			"subject":   c.Subject.String(),
			"issuer":    c.Issuer.String(),
			"sha256":    sha256Hex(c.Raw),
			"keyAlg":    c.PublicKeyAlgorithm.String(),
			"notBefore": c.NotBefore.Format("2006-01-02"),
			"notAfter":  c.NotAfter.Format("2006-01-02"),
		}
	}
	return out
}
