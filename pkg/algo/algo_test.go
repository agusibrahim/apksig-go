package algo

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestSignVerifyRoundTrip_RSA_PKCS1(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	a, _ := ByID(SigRSAPKCS1SHA256)
	msg := []byte("payload")
	sig, err := a.Sign(key, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(&key.PublicKey, msg, sig); err != nil {
		t.Errorf("verify roundtrip: %v", err)
	}
}

func TestSignVerifyRoundTrip_RSA_PSS(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	a, _ := ByID(SigRSAPSSSHA256)
	msg := []byte("hello world")
	sig, err := a.Sign(key, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(&key.PublicKey, msg, sig); err != nil {
		t.Errorf("PSS verify: %v", err)
	}
}

func TestSignVerifyRoundTrip_ECDSA(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	a, _ := ByID(SigECDSASHA256)
	msg := []byte("ecdsa-payload")
	sig, err := a.Sign(key, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(&key.PublicKey, msg, sig); err != nil {
		t.Errorf("ECDSA verify: %v", err)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	a, _ := ByID(SigRSAPKCS1SHA256)
	sig, _ := a.Sign(key, []byte("orig"))
	sig[0] ^= 0xff
	if err := a.Verify(&key.PublicKey, []byte("orig"), sig); err == nil {
		t.Error("expected verify failure on tampered signature")
	}
}

func TestVerifyRejectsTamperedMessage(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	a, _ := ByID(SigRSAPKCS1SHA256)
	sig, _ := a.Sign(key, []byte("orig"))
	if err := a.Verify(&key.PublicKey, []byte("modified"), sig); err == nil {
		t.Error("expected verify failure on modified message")
	}
}

func TestPickAlgorithm(t *testing.T) {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	if a, err := PickAlgorithm(rsaKey); err != nil || a.ID != SigRSAPKCS1SHA256 {
		t.Errorf("RSA pick: alg=%#x err=%v", a.ID, err)
	}
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if a, err := PickAlgorithm(ecKey); err != nil || a.ID != SigECDSASHA256 {
		t.Errorf("ECDSA pick: alg=%#x err=%v", a.ID, err)
	}
}

func TestByIDLookup(t *testing.T) {
	for _, id := range []SigID{
		SigRSAPSSSHA256, SigRSAPSSSHA512, SigRSAPKCS1SHA256, SigRSAPKCS1SHA512,
		SigECDSASHA256, SigECDSASHA512, SigDSASHA256,
		SigVerityRSAPKCS1SHA256, SigVerityECDSASHA256,
	} {
		if _, ok := ByID(id); !ok {
			t.Errorf("missing alg id %#x in ByID", id)
		}
	}
	if _, ok := ByID(0xdeadbeef); ok {
		t.Error("unexpected hit for bogus alg id")
	}
}

func TestContentDigestSizes(t *testing.T) {
	if ChunkedSHA256.Size() != 32 || ChunkedSHA512.Size() != 64 {
		t.Errorf("chunked sizes wrong")
	}
	if VerityChunkedSHA256.Hash() == nil {
		t.Error("verity hash factory nil")
	}
}
