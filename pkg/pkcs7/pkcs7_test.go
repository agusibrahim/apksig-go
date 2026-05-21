package pkcs7

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// buildPKCS7 produces a synthetic PKCS#7 SignedData blob containing one
// certificate and one SignerInfo, signed with the supplied key.
//
// We don't build a fully spec-compliant blob (we'd need an OCTET STRING for
// the EncapContentInfo, etc.); just enough to exercise Parse() field
// extraction.
func buildPKCS7(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate, sig []byte) []byte {
	t.Helper()
	type algorithmIdentifier struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	type issuerAndSerial struct {
		Issuer       asn1.RawValue
		SerialNumber *big.Int
	}
	type signerInfo struct {
		Version              int
		IssuerAndSerial      issuerAndSerial
		DigestAlgorithm      algorithmIdentifier
		AuthAttrs            asn1.RawValue `asn1:"optional,tag:0"`
		DigestEncryptionAlgo algorithmIdentifier
		EncryptedDigest      []byte
		UnauthAttrs          asn1.RawValue `asn1:"optional,tag:1"`
	}
	type encapContentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
	}
	type signedData struct {
		Version          int
		DigestAlgorithms []asn1.RawValue `asn1:"set"`
		ContentInfo      encapContentInfo
		Certificates     asn1.RawValue `asn1:"optional,tag:0"`
		SignerInfos      []signerInfo  `asn1:"set"`
	}
	type contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
	}

	oidSHA256 := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidRSA := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

	digestAlg := algorithmIdentifier{Algorithm: oidSHA256}
	digestAlgRaw, err := asn1.Marshal(digestAlg)
	if err != nil {
		t.Fatal(err)
	}

	si := signerInfo{
		Version: 1,
		IssuerAndSerial: issuerAndSerial{
			Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
			SerialNumber: cert.SerialNumber,
		},
		DigestAlgorithm:      digestAlg,
		DigestEncryptionAlgo: algorithmIdentifier{Algorithm: oidRSA},
		EncryptedDigest:      sig,
	}

	sd := signedData{
		Version:          1,
		DigestAlgorithms: []asn1.RawValue{{FullBytes: digestAlgRaw}},
		ContentInfo:      encapContentInfo{ContentType: oidData},
		Certificates:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: cert.Raw},
		SignerInfos:      []signerInfo{si},
	}
	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatal(err)
	}
	ci := contentInfo{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: sdBytes},
	}
	full, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatal(err)
	}
	return full
}

func TestPKCS7Parse(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test-signer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	blob := buildPKCS7(t, key, cert, []byte("fake-sig"))

	sd, err := Parse(blob)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(sd.Certificates) != 1 {
		t.Fatalf("certs: %d", len(sd.Certificates))
	}
	if sd.Certificates[0].SerialNumber.Cmp(big.NewInt(42)) != 0 {
		t.Errorf("serial: %s", sd.Certificates[0].SerialNumber)
	}
	if len(sd.SignerInfos) != 1 {
		t.Fatalf("signer infos: %d", len(sd.SignerInfos))
	}
	if string(sd.SignerInfos[0].Signature) != "fake-sig" {
		t.Errorf("sig: %q", sd.SignerInfos[0].Signature)
	}
	c := sd.FindSignerCert(sd.SignerInfos[0])
	if c == nil {
		t.Error("FindSignerCert returned nil")
	} else if c.Subject.CommonName != "test-signer" {
		t.Errorf("found cert CN: %s", c.Subject.CommonName)
	}
}

func TestPKCS7ParseRejectsNonSignedData(t *testing.T) {
	// A trivial Data ContentInfo, not SignedData.
	type contentInfo struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
	}
	oidData := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	full, _ := asn1.Marshal(contentInfo{ContentType: oidData})
	if _, err := Parse(full); err == nil {
		t.Error("expected error for non-SignedData ContentInfo")
	}
}
