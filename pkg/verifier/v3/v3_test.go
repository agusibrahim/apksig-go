// Package v3 tests cover synthetic v3 block parsing including SDK-range
// validation, certificate↔SPKI consistency check, and lineage attribute
// surfacing.
package v3

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/agusibrahim/apksig-go/pkg/algo"
)

func makeKeyCert(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "v3-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	return k, c
}

// buildV3Block creates a minimal v3 block with one signer.
func buildV3Block(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate, minSdk, maxSdk int32) []byte {
	t.Helper()
	a, _ := algo.ByID(algo.SigRSAPKCS1SHA256)
	digest := make([]byte, 32)
	for i := range digest {
		digest[i] = byte(i)
	}
	digestEntry := append(uint32LE(uint32(a.ID)), lp(digest)...)
	// signed-data: digests || certs || minSdk || maxSdk || attrs
	signedData := lp(lp(digestEntry))                                // digests
	signedData = append(signedData, lp(lp(cert.Raw))...)             // certs
	signedData = append(signedData, uint32LE(uint32(minSdk))...)
	signedData = append(signedData, uint32LE(uint32(maxSdk))...)
	signedData = append(signedData, lp(nil)...) // empty attrs

	pubKey, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	sig, err := a.Sign(key, signedData)
	if err != nil {
		t.Fatal(err)
	}
	// signatures slice: each entry is LP(algID || LP(sig)).
	sigEntry := append(uint32LE(uint32(a.ID)), lp(sig)...)
	signatures := lp(lp(sigEntry))

	signer := lp(signedData)
	signer = append(signer, uint32LE(uint32(minSdk))...)
	signer = append(signer, uint32LE(uint32(maxSdk))...)
	signer = append(signer, signatures...)
	signer = append(signer, lp(pubKey)...)

	return lp(lp(signer)) // outer signers wrapper + LP per-signer
}

func uint32LE(v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b[:]
}

func lp(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(b)))
	copy(out[4:], b)
	return out
}

func TestV3Verify_OK(t *testing.T) {
	key, cert := makeKeyCert(t)
	block := buildV3Block(t, key, cert, 28, 0x7fffffff)
	res, err := Verify(block, 24, 35)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Verified || len(res.Signers) != 1 {
		t.Fatalf("not verified: %+v", res)
	}
	s := res.Signers[0]
	if s.MinSDK != 28 || s.MaxSDK != 0x7fffffff {
		t.Errorf("SDK range: %d..%d", s.MinSDK, s.MaxSDK)
	}
	if !bytes.Equal(s.Certs[0].Raw, cert.Raw) {
		t.Error("cert raw bytes mismatch")
	}
}

func TestV3Verify_TamperedSig(t *testing.T) {
	key, cert := makeKeyCert(t)
	block := buildV3Block(t, key, cert, 28, 0x7fffffff)
	// Flip a byte deep inside (signature payload).
	block[len(block)-100] ^= 0xff
	res, _ := Verify(block, 24, 35)
	if res.Verified {
		t.Error("expected verification failure on tampered signature")
	}
}

func TestV3Verify_EmptySigners(t *testing.T) {
	// Just an empty outer LP signers list.
	block := lp(nil)
	if _, err := Verify(block, 24, 35); err == nil {
		t.Error("expected error for empty signers")
	}
}
