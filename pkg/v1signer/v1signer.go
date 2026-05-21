// Package v1signer creates JAR-signed (APK Signature Scheme v1) META-INF files.
//
// It produces three files that get injected into the APK's ZIP:
//
//	META-INF/MANIFEST.MF       — per-entry SHA-256 digests
//	META-INF/<signer>.SF       — signed digests of MANIFEST.MF sections
//	META-INF/<signer>.RSA/.EC  — PKCS#7 SignedData over the .SF bytes
package v1signer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"

	"github.com/agusibrahim/apksig-go/pkg/datasource"
	zippkg "github.com/agusibrahim/apksig-go/pkg/zip"
)

// Output holds the three v1 signature files to be added to the APK ZIP.
type Output struct {
	Manifest  []byte // META-INF/MANIFEST.MF
	SF        []byte // META-INF/CERT.SF
	PKCS7     []byte // META-INF/CERT.RSA (or .EC / .DSA)
	Extension string // ".RSA", ".DSA", or ".EC"
}

// SignerConfig holds the key material for v1 signing.
type SignerConfig struct {
	PrivateKey crypto.PrivateKey
	Cert       *x509.Certificate
	// Name is the base name for META-INF files (default "CERT").
	Name string
}

// Sign generates the three v1 signature files for the given APK entries.
func Sign(ds datasource.DataSource, entries []zippkg.CDEntry, cfg *SignerConfig) (*Output, error) {
	manifest, entrySections, err := buildManifest(ds, entries)
	if err != nil {
		return nil, fmt.Errorf("v1signer: manifest: %w", err)
	}

	sf, err := buildSF(manifest, entrySections)
	if err != nil {
		return nil, fmt.Errorf("v1signer: SF: %w", err)
	}

	ext := extensionForKey(cfg.Cert.PublicKey)
	sigAlg := signatureAlgorithmForKey(cfg.Cert.PublicKey)

	pkcs7DER, err := buildPKCS7(sf, cfg.PrivateKey, cfg.Cert, oidSHA256, sigAlg)
	if err != nil {
		return nil, fmt.Errorf("v1signer: PKCS#7: %w", err)
	}

	return &Output{
		Manifest:  manifest,
		SF:        sf,
		PKCS7:     pkcs7DER,
		Extension: ext,
	}, nil
}

type sectionInfo struct {
	name         string
	sectionBytes []byte
}

func buildManifest(ds datasource.DataSource, entries []zippkg.CDEntry) ([]byte, []sectionInfo, error) {
	var buf []byte

	buf = append(buf, "Manifest-Version: 1.0\r\n"...)
	buf = append(buf, "Created-By: 1.0 (apksig-go)\r\n"...)
	buf = append(buf, "\r\n"...)

	var sections []sectionInfo

	for _, e := range entries {
		if strings.HasPrefix(e.Name, "META-INF/") {
			continue
		}
		if e.Name == "" || strings.HasSuffix(e.Name, "/") {
			continue
		}

		data, err := zippkg.ReadEntry(ds, &e)
		if err != nil {
			continue
		}

		h := sha256.Sum256(data)
		digest := base64.StdEncoding.EncodeToString(h[:])

		secStart := len(buf)
		appendManifestAttr(&buf, "Name", e.Name)
		appendManifestAttr(&buf, "SHA-256-Digest", digest)
		buf = append(buf, "\r\n"...)
		sections = append(sections, sectionInfo{
			name:         e.Name,
			sectionBytes: append([]byte(nil), buf[secStart:]...),
		})
	}

	return buf, sections, nil
}

func appendManifestAttr(buf *[]byte, key, value string) {
	line := key + ": " + value
	if len(line) <= 70 {
		*buf = append(*buf, line...)
		*buf = append(*buf, "\r\n"...)
		return
	}
	*buf = append(*buf, line[:70]...)
	*buf = append(*buf, "\r\n"...)
	line = line[70:]
	for len(line) > 0 {
		chunk := 69
		if len(line) < chunk {
			chunk = len(line)
		}
		*buf = append(*buf, ' ')
		*buf = append(*buf, line[:chunk]...)
		*buf = append(*buf, "\r\n"...)
		line = line[chunk:]
	}
}

func buildSF(manifest []byte, sections []sectionInfo) ([]byte, error) {
	var buf []byte

	h := sha256.Sum256(manifest)
	manifestDigest := base64.StdEncoding.EncodeToString(h[:])

	buf = append(buf, "Signature-Version: 1.0\r\n"...)
	appendManifestAttr(&buf, "SHA-256-Digest-Manifest", manifestDigest)
	buf = append(buf, "Created-By: 1.0 (apksig-go)\r\n"...)
	buf = append(buf, "\r\n"...)

	for _, sec := range sections {
		sh := sha256.Sum256(sec.sectionBytes)
		digest := base64.StdEncoding.EncodeToString(sh[:])
		appendManifestAttr(&buf, "Name", sec.name)
		appendManifestAttr(&buf, "SHA-256-Digest", digest)
		buf = append(buf, "\r\n"...)
	}

	return buf, nil
}

// --- PKCS#7 / ASN.1 ---

var (
	oidSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedDataASN1 struct {
	Version          int
	DigestAlgorithms []asn1.RawValue `asn1:"set"`
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue  `asn1:"optional,tag:0"`
	SignerInfos      []signerInfoASN1 `asn1:"set"`
}

type encapContentInfo struct {
	ContentType asn1.ObjectIdentifier
}

type signerInfoASN1 struct {
	Version              int
	IssuerAndSerialNumber issuerAndSerial
	DigestAlgorithm      algorithmIdentifier
	DigestEncryptionAlgo algorithmIdentifier
	EncryptedDigest      []byte
}

type issuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

func extensionForKey(pub interface{}) string {
	switch pub.(type) {
	case *rsa.PublicKey:
		return ".RSA"
	case *ecdsa.PublicKey:
		return ".EC"
	}
	return ".RSA"
}

func signatureAlgorithmForKey(pub interface{}) asn1.ObjectIdentifier {
	switch pub.(type) {
	case *rsa.PublicKey:
		return oidSHA256WithRSA
	case *ecdsa.PublicKey:
		return oidECDSAWithSHA256
	}
	return oidSHA256WithRSA
}

func signDigest(priv crypto.PrivateKey, hash crypto.Hash, digest []byte) ([]byte, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand.Reader, k, hash, digest)
	case *ecdsa.PrivateKey:
		return ecdsa.SignASN1(rand.Reader, k, digest)
	}
	return nil, fmt.Errorf("unsupported key type %T", priv)
}

func buildPKCS7(sfBytes []byte, priv crypto.PrivateKey, cert *x509.Certificate, digestAlg, sigAlg asn1.ObjectIdentifier) ([]byte, error) {
	h := crypto.SHA256.New()
	h.Write(sfBytes)
	digest := h.Sum(nil)

	signature, err := signDigest(priv, crypto.SHA256, digest)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	digestAlgoDER, err := asn1.Marshal(algorithmIdentifier{Algorithm: digestAlg})
	if err != nil {
		return nil, err
	}

	var certChain []byte
	certChain = append(certChain, cert.Raw...)

	sd := signedDataASN1{
		Version:          1,
		DigestAlgorithms: []asn1.RawValue{{FullBytes: digestAlgoDER}},
		EncapContentInfo: encapContentInfo{ContentType: oidData},
		Certificates: asn1.RawValue{
			Class:      2,
			Tag:        0,
			IsCompound: true,
			Bytes:      certChain,
		},
		SignerInfos: []signerInfoASN1{{
			Version: 1,
			IssuerAndSerialNumber: issuerAndSerial{
				Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
				SerialNumber: cert.SerialNumber,
			},
			DigestAlgorithm:      algorithmIdentifier{Algorithm: digestAlg},
			DigestEncryptionAlgo: algorithmIdentifier{Algorithm: sigAlg},
			EncryptedDigest:      signature,
		}},
	}

	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("marshal signedData: %w", err)
	}

	// Build contentInfo manually: SEQUENCE { OID signedData, [0] EXPLICIT { sdBytes } }
	oidDER, err := asn1.Marshal(oidSignedData)
	if err != nil {
		return nil, err
	}
	explicit := wrapExplicitTag0(sdBytes)
	seqBody := append(oidDER, explicit...)
	out := wrapSequence(seqBody)
	return out, nil
}

func wrapExplicitTag0(content []byte) []byte {
	encoded := appendLength(len(content), nil)
	result := make([]byte, 0, 1+len(encoded)+len(content))
	result = append(result, 0xa0) // context-specific, constructed, tag 0
	result = append(result, encoded...)
	result = append(result, content...)
	return result
}

func wrapSequence(content []byte) []byte {
	encoded := appendLength(len(content), nil)
	result := make([]byte, 0, 1+len(encoded)+len(content))
	result = append(result, 0x30) // SEQUENCE
	result = append(result, encoded...)
	result = append(result, content...)
	return result
}

func appendLength(length int, dst []byte) []byte {
	if length < 0x80 {
		return append(dst, byte(length))
	}
	if length < 0x100 {
		return append(dst, 0x81, byte(length))
	}
	if length < 0x10000 {
		return append(dst, 0x82, byte(length>>8), byte(length))
	}
	return append(dst, 0x83, byte(length>>16), byte(length>>8), byte(length))
}
