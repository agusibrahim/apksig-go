package keystore

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"os"
	"path/filepath"
	"testing"
)

const (
	testStorePass = "test123"
	testJKSAlias  = "testkey"
	testP12Alias  = "testkey"
	keytoolAlias  = "keytoolkey"
)

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "keystore", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return data
}

func TestDetect(t *testing.T) {
	cases := []struct {
		file string
		want Format
	}{
		{"test.jks", FormatJKS},
		{"test.p12", FormatPKCS12},
		{"test-keytool.p12", FormatPKCS12},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			data := loadFixture(t, tc.file)
			if got := Detect(data); got != tc.want {
				t.Fatalf("Detect(%s) = %s, want %s", tc.file, got, tc.want)
			}
		})
	}
}

func TestDetectGarbage(t *testing.T) {
	if got := Detect([]byte{1, 2, 3}); got != FormatUnknown {
		t.Fatalf("short input: got %s, want unknown", got)
	}
	if got := Detect([]byte("hello world")); got != FormatUnknown {
		t.Fatalf("ascii input: got %s, want unknown", got)
	}
}

func TestLoadJKS(t *testing.T) {
	data := loadFixture(t, "test.jks")
	entry, err := Load(data, LoadOpts{StorePass: testStorePass})
	if err != nil {
		t.Fatalf("Load JKS: %v", err)
	}
	if _, ok := entry.PrivateKey.(*rsa.PrivateKey); !ok {
		t.Fatalf("expected RSA private key, got %T", entry.PrivateKey)
	}
	if entry.Cert == nil {
		t.Fatal("missing leaf cert")
	}
	if entry.Cert.Subject.CommonName != "Test" {
		t.Fatalf("unexpected CN %q", entry.Cert.Subject.CommonName)
	}
}

func TestLoadJKS_WrongPassword(t *testing.T) {
	data := loadFixture(t, "test.jks")
	if _, err := Load(data, LoadOpts{StorePass: "wrong"}); err == nil {
		t.Fatal("expected error with wrong password")
	}
}

func TestLoadJKS_AliasFilter(t *testing.T) {
	data := loadFixture(t, "test.jks")
	entry, err := Load(data, LoadOpts{StorePass: testStorePass, Alias: testJKSAlias})
	if err != nil {
		t.Fatalf("Load JKS with alias: %v", err)
	}
	if entry.Cert.Subject.CommonName != "Test" {
		t.Fatalf("unexpected CN %q", entry.Cert.Subject.CommonName)
	}
}

func TestLoadJKS_UnknownAlias(t *testing.T) {
	data := loadFixture(t, "test.jks")
	if _, err := Load(data, LoadOpts{StorePass: testStorePass, Alias: "nope"}); err == nil {
		t.Fatal("expected error for unknown alias")
	}
}

func TestLoadPKCS12_Openssl(t *testing.T) {
	data := loadFixture(t, "test.p12")
	entry, err := Load(data, LoadOpts{StorePass: testStorePass})
	if err != nil {
		t.Fatalf("Load p12: %v", err)
	}
	switch entry.PrivateKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
	default:
		t.Fatalf("unexpected key type %T", entry.PrivateKey)
	}
	if entry.Cert.Subject.CommonName != "Test" {
		t.Fatalf("unexpected CN %q", entry.Cert.Subject.CommonName)
	}
}

func TestLoadPKCS12_Keytool(t *testing.T) {
	data := loadFixture(t, "test-keytool.p12")
	entry, err := Load(data, LoadOpts{StorePass: testStorePass})
	if err != nil {
		t.Fatalf("Load keytool p12: %v", err)
	}
	if entry.Cert.Subject.CommonName != "Keytool Test" {
		t.Fatalf("unexpected CN %q", entry.Cert.Subject.CommonName)
	}
}

func TestLoadPKCS12_WrongPassword(t *testing.T) {
	data := loadFixture(t, "test.p12")
	if _, err := Load(data, LoadOpts{StorePass: "wrong"}); err == nil {
		t.Fatal("expected error with wrong password")
	}
}

func TestLoadUnknownFormat(t *testing.T) {
	if _, err := Load([]byte("hello world this is not a keystore"), LoadOpts{}); err == nil {
		t.Fatal("expected error for unknown format")
	}
}
