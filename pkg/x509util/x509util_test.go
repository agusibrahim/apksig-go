package x509util

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// makeCertWithCN creates a cert with a UTF8String CN containing forbidden
// PrintableString chars (e.g. "@"). Then transforms it back into a
// PrintableString-tagged cert to provoke Go's strict parser.
func makeStrictlyInvalidCert(t *testing.T) []byte {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "AndroidTeam/emailAddress=mobile@huawei.com",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	// Replace UTF8String tag (0x0c) of the CN with PrintableString tag (0x13)
	// so Go's strict parser will reject it.
	for i := 0; i < len(der)-3; i++ {
		if der[i] == 0x0c &&
			i+1 < len(der) &&
			bytes.Contains(der[i:i+50], []byte("AndroidTeam")) {
			der[i] = 0x13
			break
		}
	}
	return der
}

func TestParseCertificate_Lenient(t *testing.T) {
	der := makeStrictlyInvalidCert(t)
	// Strict parser should fail.
	if _, err := x509.ParseCertificate(der); err == nil {
		t.Skip("test cert is not actually invalid for strict parser; skipping")
	}
	// Lenient parser must accept it.
	c, err := ParseCertificate(der)
	if err != nil {
		t.Fatalf("lenient ParseCertificate: %v", err)
	}
	if c.Subject.CommonName == "" {
		t.Error("expected CN in parsed cert")
	}
	// Raw bytes preserved (digests must still match the on-disk DER).
	if !bytes.Equal(c.Raw, der) {
		t.Error("Raw bytes were rewritten; digests would no longer match")
	}
}

func TestParseCertificate_Valid(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ok"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	c, err := ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if c.Subject.CommonName != "ok" {
		t.Errorf("CN: %q", c.Subject.CommonName)
	}
}

func TestRewritePrintableStrings_Idempotent(t *testing.T) {
	// Plain ASCII PrintableString (no forbidden chars) stays untouched.
	in := []byte{0x13, 0x05, 'h', 'e', 'l', 'l', 'o'}
	out := rewritePrintableStrings(in)
	if !bytes.Equal(out, in) {
		t.Errorf("untouched bytes were modified")
	}
}

func TestRewritePrintableStrings_FlipsForbidden(t *testing.T) {
	// PrintableString with '@' should be rewritten to UTF8String (0x0c).
	in := []byte{0x13, 0x05, 'a', '@', 'b', 'c', 'd'}
	out := rewritePrintableStrings(in)
	if out[0] != 0x0c {
		t.Errorf("tag not flipped: %#x", out[0])
	}
	if !bytes.Equal(out[1:], in[1:]) {
		t.Errorf("payload was modified")
	}
}
