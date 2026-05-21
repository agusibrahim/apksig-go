// Package v2 tests synthesise a minimal v2 block to exercise the verifier
// independent of the rest of the apksig pipeline.
package v2

import (
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
		Subject:      pkix.Name{CommonName: "v2"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	c, _ := x509.ParseCertificate(der)
	return k, c
}

func buildV2Block(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate) []byte {
	t.Helper()
	a, _ := algo.ByID(algo.SigRSAPKCS1SHA256)
	digest := make([]byte, 32)
	digestEntry := append(u32(uint32(a.ID)), lp(digest)...)
	signedData := lp(lp(digestEntry)) // digests slice = outer LP, each entry = LP(algId||LP(dg))
	signedData = append(signedData, lp(lp(cert.Raw))...)
	signedData = append(signedData, lp(nil)...) // empty attrs

	pubKey, _ := x509.MarshalPKIXPublicKey(cert.PublicKey)
	sig, _ := a.Sign(key, signedData)
	// signatures slice: each entry is LP(algID || LP(sig)).
	sigEntry := append(u32(uint32(a.ID)), lp(sig)...)
	signatures := lp(lp(sigEntry))

	signer := lp(signedData)
	signer = append(signer, signatures...)
	signer = append(signer, lp(pubKey)...)

	return lp(lp(signer))
}

func u32(v uint32) []byte {
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

func TestV2Verify_OK(t *testing.T) {
	key, cert := makeKeyCert(t)
	block := buildV2Block(t, key, cert)
	res, err := Verify(block, 24, 35)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified || len(res.Signers) != 1 {
		t.Errorf("not verified: %+v", res)
	}
}

func TestV2Verify_NoSigners(t *testing.T) {
	if _, err := Verify(lp(nil), 24, 35); err == nil {
		t.Error("expected error on empty signers")
	}
}
