// Package pkcs7 parses CMS / PKCS#7 SignedData structures used by JAR
// signing (.RSA / .DSA / .EC files inside META-INF). We support DER-encoded
// signatures, which is what every modern signer produces; legacy BER-encoded
// blobs are not handled (apksig has a custom BER reader for that path).
package pkcs7

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/agusibrahim/apksig-go/pkg/x509util"
)

// OIDs we care about.
var (
	oidSignedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData                = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidRSA                 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidEC                  = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidDSA                 = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	oidSHA1                = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA224              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	oidSHA256              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512              = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidSHA1WithRSA         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSHA256WithRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidRSAPSS              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidSHA1WithDSA         = asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 3}
	oidSHA256WithDSA       = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 2}
	oidECDSAWithSHA1       = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidECDSAWithSHA256     = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384     = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512     = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
)

// SignedData is the parsed top-level PKCS#7 SignedData payload.
type SignedData struct {
	Certificates []*x509.Certificate
	SignerInfos  []SignerInfo
	// EncapContentInfo content (often absent in JAR signing — content is the
	// .SF file passed externally).
	ContentType asn1.ObjectIdentifier
	Content     []byte
}

// SignerInfo describes one signer.
type SignerInfo struct {
	Version            int
	IssuerAndSerial    issuerAndSerial
	DigestAlgorithm    asn1.ObjectIdentifier
	SignatureAlgorithm asn1.ObjectIdentifier
	Signature          []byte
}

type issuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// On-wire ASN.1 structures.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []asn1.RawValue `asn1:"set"`
	ContentInfo      encapContentInfo
	Certificates     asn1.RawValue          `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue          `asn1:"optional,tag:1"`
	SignerInfos      []signerInfoASN1       `asn1:"set"`
}

type encapContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type signerInfoASN1 struct {
	Version              int
	IssuerAndSerial      issuerAndSerial
	DigestAlgorithm      algorithmIdentifier
	AuthenticatedAttrs   asn1.RawValue `asn1:"optional,tag:0"`
	DigestEncryptionAlgo algorithmIdentifier
	EncryptedDigest      []byte
	UnauthenticatedAttrs asn1.RawValue `asn1:"optional,tag:1"`
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// Parse decodes a PKCS#7 SignedData blob.
func Parse(der []byte) (*SignedData, error) {
	var ci contentInfo
	rest, err := asn1.Unmarshal(der, &ci)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: top-level: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("pkcs7: trailing data after ContentInfo")
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("pkcs7: not SignedData (got %v)", ci.ContentType)
	}
	if len(ci.Content.Bytes) == 0 {
		return nil, errors.New("pkcs7: empty SignedData content")
	}
	var sd signedData
	rest, err = asn1.Unmarshal(ci.Content.Bytes, &sd)
	if err != nil {
		return nil, fmt.Errorf("pkcs7: signedData: %w", err)
	}
	_ = rest // some encoders include trailing zero padding; ignore
	out := &SignedData{
		ContentType: sd.ContentInfo.ContentType,
	}
	if len(sd.ContentInfo.Content.Bytes) > 0 {
		// Strip the inner OCTET STRING wrapping (Content.Bytes is the raw
		// OCTET STRING; we want its value bytes).
		var inner []byte
		_, err := asn1.Unmarshal(sd.ContentInfo.Content.FullBytes, &asn1.RawValue{})
		if err == nil {
			// Re-decode to peel off OCTET STRING.
			var raw asn1.RawValue
			if _, err := asn1.Unmarshal(sd.ContentInfo.Content.Bytes, &raw); err == nil {
				inner = raw.Bytes
			} else {
				inner = sd.ContentInfo.Content.Bytes
			}
		}
		out.Content = inner
	}
	if len(sd.Certificates.Bytes) > 0 {
		certs, err := x509util.ParseCertificates(sd.Certificates.Bytes)
		if err != nil && len(certs) == 0 {
			return nil, fmt.Errorf("pkcs7: certs: %w", err)
		}
		out.Certificates = certs
	}
	for _, si := range sd.SignerInfos {
		out.SignerInfos = append(out.SignerInfos, SignerInfo{
			Version:            si.Version,
			IssuerAndSerial:    si.IssuerAndSerial,
			DigestAlgorithm:    si.DigestAlgorithm.Algorithm,
			SignatureAlgorithm: si.DigestEncryptionAlgo.Algorithm,
			Signature:          si.EncryptedDigest,
		})
	}
	return out, nil
}

// FindSignerCert returns the first certificate matching the given signer's
// IssuerAndSerial. Returns nil if not found.
func (s *SignedData) FindSignerCert(si SignerInfo) *x509.Certificate {
	for _, c := range s.Certificates {
		if c.SerialNumber == nil || si.IssuerAndSerial.SerialNumber == nil {
			continue
		}
		if c.SerialNumber.Cmp(si.IssuerAndSerial.SerialNumber) != 0 {
			continue
		}
		// Compare encoded issuer DN.
		if string(c.RawIssuer) == string(si.IssuerAndSerial.Issuer.FullBytes) {
			return c
		}
	}
	return nil
}
