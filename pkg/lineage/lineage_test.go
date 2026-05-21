package lineage

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"

	"github.com/agusibrahim/apksig-go/pkg/algo"
)

// makeCert produces a self-signed certificate using the given key.
func makeCert(t *testing.T, key *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// buildLineage builds a synthetic 2-node lineage (cert A → cert B) using ECDSA
// SHA-256 throughout. We use this to test the decoder end-to-end.
func buildLineage(t *testing.T) []byte {
	t.Helper()
	keyA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	keyB, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certA := makeCert(t, keyA, "A")
	certB := makeCert(t, keyB, "B")

	algECDSA, _ := algo.ByID(algo.SigECDSASHA256)

	// Node 1: cert = A, signedSigAlg = sigAlg used by A to sign next (B's
	// signed-data). For node 1, no signature is verified (lastCert == nil).
	signedDataA := make([]byte, 0)
	signedDataA = appendLP(signedDataA, certA.Raw)
	signedDataA = appendU32(signedDataA, uint32(algECDSA.ID))
	node1 := make([]byte, 0)
	node1 = appendLP(node1, signedDataA)
	node1 = appendU32(node1, 0x10) // flags: PAST_CERT_AUTH (arbitrary)
	node1 = appendU32(node1, uint32(algECDSA.ID))
	node1 = appendLP(node1, []byte{}) // empty sig for first node

	// Node 2: cert = B, signedSigAlg = the alg with which A signed B's
	// signedData (must equal lastSigAlg = ECDSA-SHA256).
	signedDataB := make([]byte, 0)
	signedDataB = appendLP(signedDataB, certB.Raw)
	signedDataB = appendU32(signedDataB, uint32(algECDSA.ID))
	// Sign signedDataB with keyA to prove rotation A → B.
	sig, err := algECDSA.Sign(keyA, signedDataB)
	if err != nil {
		t.Fatal(err)
	}
	node2 := make([]byte, 0)
	node2 = appendLP(node2, signedDataB)
	node2 = appendU32(node2, 0x18)
	node2 = appendU32(node2, uint32(algECDSA.ID))
	node2 = appendLP(node2, sig)

	// Lineage payload: u32 version + LP-prefixed nodes.
	payload := make([]byte, 0)
	payload = appendU32(payload, 1)
	payload = appendLP(payload, node1)
	payload = appendLP(payload, node2)
	return payload
}

func appendU32(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}

func appendLP(b, v []byte) []byte {
	b = appendU32(b, uint32(len(v)))
	return append(b, v...)
}

func TestLineageDecodeRaw(t *testing.T) {
	payload := buildLineage(t)
	lin, err := DecodeRaw(payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(lin.Nodes) != 2 {
		t.Fatalf("nodes: got %d, want 2", len(lin.Nodes))
	}
	if lin.Original().Subject.CommonName != "A" {
		t.Errorf("original CN: %s", lin.Original().Subject.CommonName)
	}
	if lin.Latest().Subject.CommonName != "B" {
		t.Errorf("latest CN: %s", lin.Latest().Subject.CommonName)
	}
	if !lin.FlagSet(0x10) {
		t.Errorf("expected flag 0x10 on latest node")
	}
}

func TestLineageDecodeWithMagic(t *testing.T) {
	payload := buildLineage(t)
	full := make([]byte, 0)
	full = appendU32(full, Magic)
	full = appendU32(full, Version)
	full = appendLP(full, payload)
	lin, err := Decode(full)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(lin.Nodes) != 2 {
		t.Fatalf("nodes: got %d, want 2", len(lin.Nodes))
	}
}

func TestLineageRejectsTampering(t *testing.T) {
	payload := buildLineage(t)
	// Flip a byte inside the second node's signed-data → rotation sig fails.
	for i := range payload {
		if payload[i] != 0 {
			payload[i] ^= 0xff
			break
		}
	}
	if _, err := DecodeRaw(payload); err == nil {
		t.Fatal("expected verification failure after tampering")
	}
}
