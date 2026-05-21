package apkwriter

import (
	"archive/zip"
	"bytes"
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
	"github.com/agusibrahim/apksig-go/pkg/apkverifier"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
	"github.com/agusibrahim/apksig-go/pkg/signer"
)

// makeUnsignedAPK builds an in-memory unsigned APK fixture.
func makeUnsignedAPK(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"classes.dex":         bytes.Repeat([]byte{0x42}, 1024),
		"resources.arsc":      bytes.Repeat([]byte{0x10}, 256),
	} {
		fw, _ := w.Create(name)
		fw.Write(content)
	}
	w.Close()
	return buf.Bytes()
}

// makeKeyAndCert builds a self-signed cert + private key for testing.
func makeKeyAndCert(t *testing.T, useECDSA bool) (interface{}, *x509.Certificate) {
	t.Helper()
	var priv interface{}
	var pub interface{}
	if useECDSA {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		priv, pub = k, &k.PublicKey
	} else {
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		priv, pub = k, &k.PublicKey
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "Test", Organization: []string{"apksig-go"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return priv, cert
}

func TestRoundTrip_V2_RSA(t *testing.T) {
	apk := makeUnsignedAPK(t)
	priv, cert := makeKeyAndCert(t, false)
	a, _ := algo.ByID(algo.SigRSAPKCS1SHA256)
	cfg := &signer.SignerConfig{
		PrivateKey: priv, Certs: []*x509.Certificate{cert},
		Algorithms: []algo.Algorithm{a},
	}
	w := &SignedAPKWriter{
		Src:     datasource.NewBytes(apk),
		Signers: []*signer.SignerConfig{cfg},
	}
	var out bytes.Buffer
	if err := w.Write(&out); err != nil {
		t.Fatalf("Write: %v", err)
	}
	res, err := apkverifier.Verify(datasource.NewBytes(out.Bytes()), 24, 35)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.V2Verified {
		t.Errorf("v2 should verify; errors=%v", res.Errors)
	}
}

func TestRoundTrip_V3_ECDSA(t *testing.T) {
	apk := makeUnsignedAPK(t)
	priv, cert := makeKeyAndCert(t, true)
	a, _ := algo.ByID(algo.SigECDSASHA256)
	cfg := &signer.SignerConfig{
		PrivateKey: priv, Certs: []*x509.Certificate{cert},
		Algorithms: []algo.Algorithm{a},
	}
	w := &SignedAPKWriter{
		Src: datasource.NewBytes(apk), Signers: []*signer.SignerConfig{cfg},
		V3MinSdk: 28, V3MaxSdk: 0x7fffffff,
	}
	var out bytes.Buffer
	if err := w.Write(&out); err != nil {
		t.Fatal(err)
	}
	res, _ := apkverifier.Verify(datasource.NewBytes(out.Bytes()), 24, 35)
	if !res.V2Verified || !res.V3Verified {
		t.Errorf("v2=%v v3=%v errors=%v", res.V2Verified, res.V3Verified, res.Errors)
	}
}

func TestRoundTrip_V31_DualBlock(t *testing.T) {
	apk := makeUnsignedAPK(t)
	priv, cert := makeKeyAndCert(t, false)
	a, _ := algo.ByID(algo.SigRSAPKCS1SHA256)
	cfg := &signer.SignerConfig{
		PrivateKey: priv, Certs: []*x509.Certificate{cert},
		Algorithms: []algo.Algorithm{a},
	}
	w := &SignedAPKWriter{
		Src: datasource.NewBytes(apk), Signers: []*signer.SignerConfig{cfg},
		V3MinSdk: 28, V3MaxSdk: 0x7fffffff,
		V31MinSdk: 33, V31MaxSdk: 0x7fffffff,
	}
	var out bytes.Buffer
	if err := w.Write(&out); err != nil {
		t.Fatal(err)
	}
	res, _ := apkverifier.Verify(datasource.NewBytes(out.Bytes()), 24, 35)
	if !res.V2Verified || !res.V3Verified || !res.V31Verified {
		t.Errorf("v2=%v v3=%v v3.1=%v", res.V2Verified, res.V3Verified, res.V31Verified)
	}
	// v3 max should be capped at v3.1 min - 1.
	if len(res.V3.Signers) > 0 && res.V3.Signers[0].MaxSDK != 32 {
		t.Errorf("expected v3 maxSdk=32, got %d", res.V3.Signers[0].MaxSDK)
	}
}

// TestSignerCertSurvivesRoundTrip ensures the certificate digest in the signed
// APK matches the input cert byte-for-byte (no rewriting).
func TestSignerCertSurvivesRoundTrip(t *testing.T) {
	apk := makeUnsignedAPK(t)
	priv, cert := makeKeyAndCert(t, false)
	a, _ := algo.ByID(algo.SigRSAPKCS1SHA256)
	cfg := &signer.SignerConfig{
		PrivateKey: priv, Certs: []*x509.Certificate{cert},
		Algorithms: []algo.Algorithm{a},
	}
	w := &SignedAPKWriter{Src: datasource.NewBytes(apk), Signers: []*signer.SignerConfig{cfg}}
	var out bytes.Buffer
	w.Write(&out)
	res, _ := apkverifier.Verify(datasource.NewBytes(out.Bytes()), 24, 35)
	if len(res.SignerCerts) == 0 {
		t.Fatal("no signer certs returned")
	}
	if !bytes.Equal(res.SignerCerts[0], cert.Raw) {
		t.Errorf("cert bytes differ; raw mismatch len got=%d want=%d",
			len(res.SignerCerts[0]), len(cert.Raw))
	}
}
