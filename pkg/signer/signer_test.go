package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/agusibrahim/apksig-go/pkg/algo"
)

// makeCert returns a self-signed cert for a given private key.
func makeCert(t *testing.T, key any) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	var der []byte
	var err error
	switch k := key.(type) {
	case *rsa.PrivateKey:
		der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	case *ecdsa.PrivateKey:
		der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	}
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

func TestSignerPayloadV2_RSA(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := makeCert(t, key)
	a, _ := algo.ByID(algo.SigRSAPKCS1SHA256)
	cfg := &SignerConfig{
		PrivateKey: key,
		Certs:      []*x509.Certificate{cert},
		Algorithms: []algo.Algorithm{a},
	}
	digests := map[algo.ContentDigest][]byte{
		algo.ChunkedSHA256: make([]byte, 32),
	}
	payload, err := SignerPayloadV2(cfg, digests)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) < 100 {
		t.Errorf("payload too small: %d", len(payload))
	}
}

func TestSignerPayloadV3_ECDSA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	cert := makeCert(t, key)
	a, _ := algo.ByID(algo.SigECDSASHA256)
	cfg := &SignerConfig{
		PrivateKey: key,
		Certs:      []*x509.Certificate{cert},
		Algorithms: []algo.Algorithm{a},
	}
	digests := map[algo.ContentDigest][]byte{
		algo.ChunkedSHA256: make([]byte, 32),
	}
	payload, err := SignerPayloadV3(cfg, digests, 28, 0x7fffffff)
	if err != nil {
		t.Fatal(err)
	}
	if len(payload) < 100 {
		t.Errorf("payload too small: %d", len(payload))
	}
}

func TestAssembleSigningBlock_AlignsTo4096(t *testing.T) {
	pairs := []Pair{{ID: 0x7109871a, Value: make([]byte, 1234)}}
	block := AssembleSigningBlock(pairs)
	if len(block)%4096 != 0 {
		t.Errorf("block size %d not aligned to 4096", len(block))
	}
	// Footer magic "APK Sig Block 42"
	magic := string(block[len(block)-16:])
	if magic != "APK Sig Block 42" {
		t.Errorf("bad magic: %q", magic)
	}
}

func TestSignerMissingDigest(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	cert := makeCert(t, key)
	a, _ := algo.ByID(algo.SigRSAPSSSHA512) // requires SHA-512 chunked digest
	cfg := &SignerConfig{
		PrivateKey: key, Certs: []*x509.Certificate{cert},
		Algorithms: []algo.Algorithm{a},
	}
	if _, err := SignerPayloadV2(cfg, map[algo.ContentDigest][]byte{}); err == nil {
		t.Error("expected error for missing digest")
	}
}
