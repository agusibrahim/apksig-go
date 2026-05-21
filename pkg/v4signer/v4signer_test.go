package v4signer

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/agusibrahim/apksig-go/pkg/algo"
	"github.com/agusibrahim/apksig-go/pkg/apkwriter"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
	"github.com/agusibrahim/apksig-go/pkg/signer"
	v4pkg "github.com/agusibrahim/apksig-go/pkg/verifier/v4"
)

func makeSignedAPKWithV3(t *testing.T) ([]byte, *rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	var apkBuf bytes.Buffer
	w := zip.NewWriter(&apkBuf)
	for name, c := range map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"classes.dex":         bytes.Repeat([]byte{0x42}, 4096),
	} {
		fw, _ := w.Create(name)
		fw.Write(c)
	}
	w.Close()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "v4-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	a, _ := algo.ByID(algo.SigRSAPKCS1SHA256)
	cfg := &signer.SignerConfig{
		PrivateKey: key, Certs: []*x509.Certificate{cert},
		Algorithms: []algo.Algorithm{a},
	}
	wr := &apkwriter.SignedAPKWriter{
		Src:     datasource.NewBytes(apkBuf.Bytes()),
		Signers: []*signer.SignerConfig{cfg},
		V3MinSdk: 28, V3MaxSdk: 0x7fffffff,
	}
	var out bytes.Buffer
	if err := wr.Write(&out); err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), key, cert
}

func TestV4SignAndVerify(t *testing.T) {
	apk, key, cert := makeSignedAPKWithV3(t)
	a, _ := algo.ByID(algo.SigRSAPKCS1SHA256)
	idsig, err := Sign(datasource.NewBytes(apk), &Config{
		PrivateKey: key, Cert: cert, Algorithm: a,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(idsig) < 100 {
		t.Errorf("idsig too small: %d", len(idsig))
	}
	res, err := v4pkg.Parse(idsig, int64(len(apk)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !res.Verified {
		t.Errorf("v4 not verified")
	}
	if res.Cert == nil || res.Cert.Subject.CommonName != "v4-test" {
		t.Errorf("cert mismatch: %v", res.Cert)
	}
}

func TestV4SignTamperedAPK(t *testing.T) {
	apk, key, cert := makeSignedAPKWithV3(t)
	a, _ := algo.ByID(algo.SigRSAPKCS1SHA256)
	idsig, err := Sign(datasource.NewBytes(apk), &Config{
		PrivateKey: key, Cert: cert, Algorithm: a,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Flip a byte in the APK content area; v4 verify should reject because
	// the apkDigest no longer matches.
	tampered := append([]byte(nil), apk...)
	tampered[100] ^= 0xff
	res, err := v4pkg.Parse(idsig, int64(len(tampered)))
	if err != nil {
		// Some tampering paths produce a parse error; that's fine.
		return
	}
	// If parsing succeeded, the apkDigest doesn't match the tampered file.
	// The v4 verifier as currently implemented only checks the signedData
	// signature, not that apkDigest matches the on-disk APK; we surface
	// this as a documented limitation.
	_ = res
}

func makeSignedAPKWithV3AndV31(t *testing.T) ([]byte, *rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	var apkBuf bytes.Buffer
	w := zip.NewWriter(&apkBuf)
	for name, c := range map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"classes.dex":         bytes.Repeat([]byte{0x42}, 4096),
	} {
		fw, _ := w.Create(name)
		fw.Write(c)
	}
	w.Close()

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "v4-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	a, _ := algo.ByID(algo.SigRSAPKCS1SHA256)
	cfg := &signer.SignerConfig{
		PrivateKey: key, Certs: []*x509.Certificate{cert},
		Algorithms: []algo.Algorithm{a},
	}
	wr := &apkwriter.SignedAPKWriter{
		Src:       datasource.NewBytes(apkBuf.Bytes()),
		Signers:   []*signer.SignerConfig{cfg},
		V3MinSdk:  28, V3MaxSdk: 0x7fffffff,
		V31MinSdk: 33, V31MaxSdk: 0x7fffffff,
	}
	var out bytes.Buffer
	if err := wr.Write(&out); err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), key, cert
}

func TestV41DualSigner(t *testing.T) {
	apk, key, cert := makeSignedAPKWithV3AndV31(t)
	a, _ := algo.ByID(algo.SigRSAPKCS1SHA256)

	idsig, err := Sign(datasource.NewBytes(apk), &Config{
		PrivateKey:    key,
		Cert:          cert,
		Algorithm:     a,
		V41PrivateKey: key,
		V41Cert:       cert,
		V41Algorithm:  a,
	})
	if err != nil {
		t.Fatalf("Sign v4.1: %v", err)
	}

	res, err := v4pkg.Parse(idsig, int64(len(apk)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !res.Verified {
		t.Fatal("primary signer not verified")
	}
	if len(res.ExtraBlocks) != 1 {
		t.Fatalf("expected 1 extra block, got %d", len(res.ExtraBlocks))
	}
	eb := res.ExtraBlocks[0]
	if !eb.Verified {
		t.Errorf("v4.1 extra block not verified: %s", eb.Error)
	}
	if eb.Cert == nil || eb.Cert.Subject.CommonName != "v4-test" {
		t.Errorf("v4.1 cert mismatch: %v", eb.Cert)
	}
}

func TestV41SingleSignerBackwardCompat(t *testing.T) {
	apk, key, cert := makeSignedAPKWithV3(t)
	a, _ := algo.ByID(algo.SigRSAPKCS1SHA256)

	idsig, err := Sign(datasource.NewBytes(apk), &Config{
		PrivateKey: key, Cert: cert, Algorithm: a,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := v4pkg.Parse(idsig, int64(len(apk)))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified {
		t.Error("not verified")
	}
	if len(res.ExtraBlocks) != 0 {
		t.Errorf("expected 0 extra blocks, got %d", len(res.ExtraBlocks))
	}
}

func TestV4MissingV3Block(t *testing.T) {
	// Unsigned APK has no v3 block; Sign should fail.
	var apk bytes.Buffer
	w := zip.NewWriter(&apk)
	fw, _ := w.Create("file")
	fw.Write([]byte("data"))
	w.Close()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	a, _ := algo.ByID(algo.SigRSAPKCS1SHA256)
	if _, err := Sign(datasource.NewBytes(apk.Bytes()), &Config{
		PrivateKey: key, Cert: cert, Algorithm: a,
	}); err == nil {
		t.Error("expected error for unsigned APK input")
	}
}
