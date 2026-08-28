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
	zippkg "github.com/agusibrahim/apksig-go/pkg/zip"
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

func TestAlign_VerifiesAfterSigning(t *testing.T) {
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
		Align:   true,
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
		t.Errorf("v2 should verify after alignment; errors=%v", res.Errors)
	}
}

func TestAlign_DataOffsetAlignment(t *testing.T) {
	// Create an APK with entries that will need alignment padding
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	// Short name (will likely need padding to align)
	fw, _ := w.Create("a")
	fw.Write([]byte("hello"))
	// Another entry with different name length
	fw2, _ := w.Create("ab")
	fw2.Write([]byte("world"))
	w.Close()

	apk := buf.Bytes()
	priv, cert := makeKeyAndCert(t, false)
	a, _ := algo.ByID(algo.SigRSAPKCS1SHA256)
	cfg := &signer.SignerConfig{
		PrivateKey: priv, Certs: []*x509.Certificate{cert},
		Algorithms: []algo.Algorithm{a},
	}
	wr := &SignedAPKWriter{
		Src:     datasource.NewBytes(apk),
		Signers: []*signer.SignerConfig{cfg},
		Align:   true,
	}
	var out bytes.Buffer
	if err := wr.Write(&out); err != nil {
		t.Fatal(err)
	}
	res, err := apkverifier.Verify(datasource.NewBytes(out.Bytes()), 24, 35)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.V2Verified {
		t.Errorf("v2 should verify; errors=%v", res.Errors)
	}
}

func TestAlign_NativeLibrary16K(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	// Short stored name so 4-byte padding is likely, which used to shift
	// a later .so off its page boundary when only 4-byte alignment was applied.
	h1 := &zip.FileHeader{Name: "a", Method: zip.Store}
	w1, err := zw.CreateHeader(h1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w1.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	h2 := &zip.FileHeader{Name: "lib/arm64-v8a/libfoo.so", Method: zip.Store}
	w2, err := zw.CreateHeader(h2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w2.Write(bytes.Repeat([]byte{0x7f, 'E', 'L', 'F'}, 64)); err != nil {
		t.Fatal(err)
	}
	h3 := &zip.FileHeader{Name: "res/raw.bin", Method: zip.Store}
	w3, err := zw.CreateHeader(h3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w3.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	fw, err := zw.Create("classes.dex")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(bytes.Repeat([]byte{0x42}, 256)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	apk := buf.Bytes()
	unsignedOff := entryDataOffsets(t, apk)
	if unsignedOff["lib/arm64-v8a/libfoo.so"]%16384 == 0 {
		t.Log("unsigned .so happened to already be 16KiB aligned; test still checks signed output")
	}

	priv, cert := makeKeyAndCert(t, false)
	a, _ := algo.ByID(algo.SigRSAPKCS1SHA256)
	cfg := &signer.SignerConfig{
		PrivateKey: priv, Certs: []*x509.Certificate{cert},
		Algorithms: []algo.Algorithm{a},
	}
	wr := &SignedAPKWriter{
		Src:     datasource.NewBytes(apk),
		Signers: []*signer.SignerConfig{cfg},
		Align:   true,
	}
	var out bytes.Buffer
	if err := wr.Write(&out); err != nil {
		t.Fatal(err)
	}
	signed := out.Bytes()
	res, err := apkverifier.Verify(datasource.NewBytes(signed), 24, 35)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.V2Verified {
		t.Fatalf("v2 should verify; errors=%v", res.Errors)
	}
	if !res.Aligned4KB {
		t.Errorf("expected 4KB .so alignment; misaligned=%v", res.MisalignedFiles)
	}
	if !res.Aligned16KB {
		t.Errorf("expected 16KB .so alignment; misaligned=%v", res.Misaligned16KB)
	}

	off := entryDataOffsets(t, signed)
	soOff := off["lib/arm64-v8a/libfoo.so"]
	if soOff%16384 != 0 {
		t.Errorf("libfoo.so data offset %d is not 16KiB aligned", soOff)
	}
	if off["a"]%4 != 0 {
		t.Errorf("stored 'a' data offset %d is not 4-byte aligned", off["a"])
	}
	if off["res/raw.bin"]%4 != 0 {
		t.Errorf("stored res/raw.bin data offset %d is not 4-byte aligned", off["res/raw.bin"])
	}
}

func entryDataOffsets(t *testing.T, apk []byte) map[string]int64 {
	t.Helper()
	ds := datasource.NewBytes(apk)
	eocd, err := zippkg.FindEOCD(ds)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := zippkg.ParseCD(ds, eocd)
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]int64, len(entries))
	for i := range entries {
		off, err := zippkg.EntryDataOffset(ds, &entries[i])
		if err != nil {
			t.Fatalf("offset %s: %v", entries[i].Name, err)
		}
		out[entries[i].Name] = off
	}
	return out
}
