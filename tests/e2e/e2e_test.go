// Package e2e contains end-to-end integration tests that exercise the full
// sign+verify pipeline against real APK fixtures, optionally cross-checking
// against the upstream apksigner reference tool when it is available.
//
// Tests in this package use the `_test` package suffix so they can only call
// exported identifiers from apksig packages — same as a real downstream user.
package e2e_test

import (
	"archive/zip"
	"bytes"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agusibrahim/apksig-go/pkg/algo"
	"github.com/agusibrahim/apksig-go/pkg/apkverifier"
	"github.com/agusibrahim/apksig-go/pkg/apkwriter"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
	"github.com/agusibrahim/apksig-go/pkg/signer"
	"github.com/agusibrahim/apksig-go/pkg/v4signer"
	v4pkg "github.com/agusibrahim/apksig-go/pkg/verifier/v4"
)

// makeUnsignedAPK builds an in-memory unsigned APK fixture.
func makeUnsignedAPK(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, content := range map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"classes.dex":         bytes.Repeat([]byte{0x42}, 4096),
		"resources.arsc":      bytes.Repeat([]byte{0x10}, 1024),
	} {
		fw, _ := w.Create(name)
		fw.Write(content)
	}
	w.Close()
	return buf.Bytes()
}

func makeRSAKeyAndCert(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"apksig-go-test"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	cert, _ := x509.ParseCertificate(der)
	return k, cert
}

// TestEndToEnd_SignAndVerify covers v2+v3 signing then full verification.
func TestEndToEnd_SignAndVerify(t *testing.T) {
	apk := makeUnsignedAPK(t)
	priv, cert := makeRSAKeyAndCert(t, "e2e-rsa")
	a, _ := algo.ByID(algo.SigRSAPKCS1SHA256)
	cfg := &signer.SignerConfig{
		PrivateKey: priv, Certs: []*x509.Certificate{cert},
		Algorithms: []algo.Algorithm{a},
	}
	w := &apkwriter.SignedAPKWriter{
		Src: datasource.NewBytes(apk), Signers: []*signer.SignerConfig{cfg},
		V3MinSdk: 28, V3MaxSdk: 0x7fffffff,
	}
	var out bytes.Buffer
	if err := w.Write(&out); err != nil {
		t.Fatalf("Write: %v", err)
	}
	res, err := apkverifier.Verify(datasource.NewBytes(out.Bytes()), 24, 35)
	if err != nil {
		t.Fatal(err)
	}
	if !res.V2Verified || !res.V3Verified {
		t.Fatalf("v2=%v v3=%v errs=%v", res.V2Verified, res.V3Verified, res.Errors)
	}
}

// TestEndToEnd_V31AndV4 covers the full set of signing schemes plus the v4
// .idsig file.
func TestEndToEnd_V31AndV4(t *testing.T) {
	apk := makeUnsignedAPK(t)
	priv, cert := makeRSAKeyAndCert(t, "e2e-v31")
	a, _ := algo.ByID(algo.SigRSAPKCS1SHA256)
	cfg := &signer.SignerConfig{
		PrivateKey: priv, Certs: []*x509.Certificate{cert},
		Algorithms: []algo.Algorithm{a},
	}
	w := &apkwriter.SignedAPKWriter{
		Src: datasource.NewBytes(apk), Signers: []*signer.SignerConfig{cfg},
		V3MinSdk: 28, V3MaxSdk: 0x7fffffff,
		V31MinSdk: 33, V31MaxSdk: 0x7fffffff,
	}
	var out bytes.Buffer
	if err := w.Write(&out); err != nil {
		t.Fatal(err)
	}
	res, err := apkverifier.Verify(datasource.NewBytes(out.Bytes()), 24, 35)
	if err != nil {
		t.Fatal(err)
	}
	if !res.V2Verified || !res.V3Verified || !res.V31Verified {
		t.Fatalf("v2=%v v3=%v v3.1=%v errs=%v",
			res.V2Verified, res.V3Verified, res.V31Verified, res.Errors)
	}
	idsig, err := v4signer.Sign(datasource.NewBytes(out.Bytes()), &v4signer.Config{
		PrivateKey: priv, Cert: cert, Algorithm: a,
	})
	if err != nil {
		t.Fatalf("v4 Sign: %v", err)
	}
	v4res, err := v4pkg.Parse(idsig, int64(out.Len()))
	if err != nil {
		t.Fatalf("v4 Parse: %v", err)
	}
	if !v4res.Verified {
		t.Errorf("v4 not verified")
	}
}

// TestEndToEnd_TamperDetection ensures that flipping bytes in the signed APK
// causes verification to fail.
func TestEndToEnd_TamperDetection(t *testing.T) {
	apk := makeUnsignedAPK(t)
	priv, cert := makeRSAKeyAndCert(t, "e2e-tamper")
	a, _ := algo.ByID(algo.SigRSAPKCS1SHA256)
	cfg := &signer.SignerConfig{
		PrivateKey: priv, Certs: []*x509.Certificate{cert},
		Algorithms: []algo.Algorithm{a},
	}
	w := &apkwriter.SignedAPKWriter{
		Src: datasource.NewBytes(apk), Signers: []*signer.SignerConfig{cfg},
	}
	var out bytes.Buffer
	w.Write(&out)
	signed := out.Bytes()
	// Flip a byte inside the entry data area (well before the signing block).
	signed[100] ^= 0xff

	res, err := apkverifier.Verify(datasource.NewBytes(signed), 24, 35)
	if err != nil {
		t.Fatal(err)
	}
	if res.V2Verified {
		t.Error("expected v2 verification to fail on tampered APK")
	}
}

// TestCrossValidate_Apksigner runs both verifiers against any real APK in
// testdata/apk/ and checks that they agree on pass/fail. Skipped if the
// upstream apksigner CLI is not available (apksigner is part of the Android
// SDK).
func TestCrossValidate_Apksigner(t *testing.T) {
	apksigner, err := exec.LookPath("apksigner")
	if err != nil {
		t.Skip("apksigner CLI not in PATH; skipping cross-validation")
	}
	matches, _ := filepath.Glob("../../testdata/apk/*.apk")
	if len(matches) == 0 {
		t.Skip("no testdata/apk/*.apk fixtures")
	}
	for _, apkPath := range matches {
		apkPath := apkPath
		t.Run(filepath.Base(apkPath), func(t *testing.T) {
			ourVerify := func() bool {
				f, err := os.Open(apkPath)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				st, _ := f.Stat()
				ds := datasource.NewReaderAt(f, st.Size())
				res, err := apkverifier.Verify(ds, 24, 35)
				if err != nil {
					return false
				}
				return res.Verified
			}()
			cmd := exec.Command(apksigner, "verify", apkPath)
			out, _ := cmd.CombinedOutput()
			refVerify := cmd.ProcessState.ExitCode() == 0

			if ourVerify != refVerify {
				t.Errorf("disagree: ours=%v apksigner=%v\nref output:\n%s",
					ourVerify, refVerify, string(out))
			}
		})
	}
}

// Helper: skip test if a dependency is unavailable.
func skipIfMissing(t *testing.T, cmd string) {
	t.Helper()
	if _, err := exec.LookPath(cmd); err != nil {
		t.Skipf("%s not in PATH; skipping", cmd)
	}
}

func init() {
	// Silence unused-helper warning when no test calls skipIfMissing yet.
	_ = skipIfMissing
	_ = strings.Fields
}
