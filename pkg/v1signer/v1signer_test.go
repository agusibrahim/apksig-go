package v1signer

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/agusibrahim/apksig-go/pkg/datasource"
	v1pkg "github.com/agusibrahim/apksig-go/pkg/verifier/v1"
	zippkg "github.com/agusibrahim/apksig-go/pkg/zip"
)

func makeTestAPK(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range map[string][]byte{
		"AndroidManifest.xml":     []byte("<manifest/>"),
		"classes.dex":             bytes.Repeat([]byte{0x42}, 4096),
		"res/values/strings.xml":  []byte("<resources><string name=\"app_name\">Test</string></resources>"),
	} {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func makeRSACreds(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "v1-test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func makeECDSACreds(t *testing.T) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "v1-test-ec"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

func testV1RoundTrip(t *testing.T, priv interface{}, cert *x509.Certificate) {
	apkBytes := makeTestAPK(t)
	ds := datasource.NewBytes(apkBytes)

	eocd, err := zippkg.FindEOCD(ds)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := zippkg.ParseCD(ds, eocd)
	if err != nil {
		t.Fatal(err)
	}

	out, err := Sign(ds, entries, &SignerConfig{
		PrivateKey: priv,
		Cert:       cert,
		Name:       "CERT",
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Build a new APK with v1 signature files injected
	var signed bytes.Buffer
	zr, err := zip.NewReader(bytes.NewReader(apkBytes), int64(len(apkBytes)))
	if err != nil {
		t.Fatal(err)
	}
	ww := zip.NewWriter(&signed)
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		w, err := ww.Create(f.Name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(w, rc); err != nil {
			t.Fatal(err)
		}
		rc.Close()
	}
	for name, data := range map[string][]byte{
		"META-INF/MANIFEST.MF":          out.Manifest,
		"META-INF/CERT.SF":              out.SF,
		"META-INF/CERT" + out.Extension: out.PKCS7,
	} {
		w, err := ww.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := ww.Close(); err != nil {
		t.Fatal(err)
	}

	// Verify with the existing v1 verifier
	signedBytes := signed.Bytes()
	signedDS := datasource.NewBytes(signedBytes)
	signedEOCD, err := zippkg.FindEOCD(signedDS)
	if err != nil {
		t.Fatal(err)
	}
	signedEntries, err := zippkg.ParseCD(signedDS, signedEOCD)
	if err != nil {
		t.Fatal(err)
	}

	res, err := v1pkg.Verify(signedDS, signedEntries)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.Verified {
		t.Errorf("v1 not verified. Errors: %v", res.Errors)
		for _, s := range res.Signers {
			t.Errorf("  signer %s: verified=%v errors=%v", s.SFFile, s.Verified, s.Errors)
		}
	}
}

func TestV1SignRSA(t *testing.T) {
	key, cert := makeRSACreds(t)
	testV1RoundTrip(t, key, cert)
}

func TestV1SignECDSA(t *testing.T) {
	key, cert := makeECDSACreds(t)
	testV1RoundTrip(t, key, cert)
}

func TestV1ManifestFormat(t *testing.T) {
	apkBytes := makeTestAPK(t)
	ds := datasource.NewBytes(apkBytes)
	eocd, err := zippkg.FindEOCD(ds)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := zippkg.ParseCD(ds, eocd)
	if err != nil {
		t.Fatal(err)
	}

	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)

	out, err := Sign(ds, entries, &SignerConfig{PrivateKey: key, Cert: cert})
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(out.Manifest, []byte("Manifest-Version: 1.0\r\n")) {
		t.Error("manifest missing version header")
	}
	if !bytes.Contains(out.Manifest, []byte("SHA-256-Digest: ")) {
		t.Error("manifest missing digest entries")
	}
	if !bytes.Contains(out.SF, []byte("SHA-256-Digest-Manifest: ")) {
		t.Error("SF missing whole-manifest digest")
	}
	if out.Extension != ".RSA" {
		t.Errorf("expected .RSA extension, got %s", out.Extension)
	}
}
