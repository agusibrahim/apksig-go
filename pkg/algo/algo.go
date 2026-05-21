// Package algo encodes the SignatureAlgorithm table from apksig (apk/v2/v3).
// Each algorithm carries its on-wire ID, content-digest algorithm, and the
// JCA-style metadata translated to crypto/* primitives.
package algo

import (
	"crypto"
	"crypto/dsa" //nolint:staticcheck // APK v2/v3 still allow DSA signatures
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

// ContentDigest enumerates per-chunk digest algorithms.
type ContentDigest int

const (
	ChunkedSHA256 ContentDigest = iota
	ChunkedSHA512
	VerityChunkedSHA256
)

func (c ContentDigest) Hash() hash.Hash {
	switch c {
	case ChunkedSHA256, VerityChunkedSHA256:
		return sha256.New()
	case ChunkedSHA512:
		return sha512.New()
	}
	return nil
}

func (c ContentDigest) Size() int {
	switch c {
	case ChunkedSHA256, VerityChunkedSHA256:
		return 32
	case ChunkedSHA512:
		return 64
	}
	return 0
}

// SigID matches V2/V3 SIGNATURE_* constants.
type SigID uint32

const (
	SigRSAPSSSHA256        SigID = 0x0101
	SigRSAPSSSHA512        SigID = 0x0102
	SigRSAPKCS1SHA256      SigID = 0x0103
	SigRSAPKCS1SHA512      SigID = 0x0104
	SigECDSASHA256         SigID = 0x0201
	SigECDSASHA512         SigID = 0x0202
	SigDSASHA256           SigID = 0x0301
	SigVerityRSAPKCS1SHA256 SigID = 0x0421
	SigVerityECDSASHA256    SigID = 0x0423
	SigVerityDSASHA256      SigID = 0x0425
)

// Algorithm describes how to compute and verify a single signature.
type Algorithm struct {
	ID            SigID
	ContentDigest ContentDigest
	HashFunc      crypto.Hash
	IsRSAPSS      bool
	IsECDSA       bool
	IsDSA         bool
	// MinSdk: minimum platform that recognizes this algorithm.
	MinSdkV3 int
	MinSdkV2 int
}

// All returns the set of supported algorithms in stable order.
func All() []Algorithm {
	return []Algorithm{
		{SigRSAPSSSHA256, ChunkedSHA256, crypto.SHA256, true, false, false, 28, 24},
		{SigRSAPSSSHA512, ChunkedSHA512, crypto.SHA512, true, false, false, 28, 24},
		{SigRSAPKCS1SHA256, ChunkedSHA256, crypto.SHA256, false, false, false, 28, 24},
		{SigRSAPKCS1SHA512, ChunkedSHA512, crypto.SHA512, false, false, false, 28, 24},
		{SigECDSASHA256, ChunkedSHA256, crypto.SHA256, false, true, false, 28, 24},
		{SigECDSASHA512, ChunkedSHA512, crypto.SHA512, false, true, false, 28, 24},
		{SigDSASHA256, ChunkedSHA256, crypto.SHA256, false, false, true, 28, 24},
		{SigVerityRSAPKCS1SHA256, VerityChunkedSHA256, crypto.SHA256, false, false, false, 28, 28},
		{SigVerityECDSASHA256, VerityChunkedSHA256, crypto.SHA256, false, true, false, 28, 28},
		{SigVerityDSASHA256, VerityChunkedSHA256, crypto.SHA256, false, false, true, 28, 28},
	}
}

// ByID looks up an Algorithm by its on-wire ID.
func ByID(id SigID) (Algorithm, bool) {
	for _, a := range All() {
		if a.ID == id {
			return a, true
		}
	}
	return Algorithm{}, false
}

// Verify performs a signature verification according to a.
func (a Algorithm) Verify(pub interface{}, signed, sig []byte) error {
	h := a.HashFunc.New()
	h.Write(signed)
	digest := h.Sum(nil)
	switch {
	case a.IsRSAPSS:
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("RSA-PSS expects *rsa.PublicKey, got %T", pub)
		}
		return rsa.VerifyPSS(rsaPub, a.HashFunc, digest, sig, &rsa.PSSOptions{
			SaltLength: a.HashFunc.Size(),
			Hash:       a.HashFunc,
		})
	case a.IsECDSA:
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("ECDSA expects *ecdsa.PublicKey, got %T", pub)
		}
		if !ecdsa.VerifyASN1(ecPub, digest, sig) {
			return errors.New("ECDSA signature mismatch")
		}
		return nil
	case a.IsDSA:
		dsaPub, ok := pub.(*dsa.PublicKey)
		if !ok {
			return fmt.Errorf("DSA expects *dsa.PublicKey, got %T", pub)
		}
		r, s, err := decodeDSASig(sig)
		if err != nil {
			return err
		}
		if !dsa.Verify(dsaPub, digest, r, s) {
			return errors.New("DSA signature mismatch")
		}
		return nil
	default: // RSA PKCS#1 v1.5
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("RSA-PKCS1 expects *rsa.PublicKey, got %T", pub)
		}
		return rsa.VerifyPKCS1v15(rsaPub, a.HashFunc, digest, sig)
	}
}

// decodeDSASig parses an ASN.1 DER sequence of two integers (r, s).
func decodeDSASig(sig []byte) (r, s *big.Int, err error) {
	var dsaSig struct {
		R, S *big.Int
	}
	rest, err := unmarshalDSAASN1(sig, &dsaSig)
	if err != nil {
		return nil, nil, err
	}
	if len(rest) != 0 {
		return nil, nil, errors.New("DSA: trailing data")
	}
	return dsaSig.R, dsaSig.S, nil
}

// Sign produces a signature over `signed` using the given private key, sized
// for this algorithm. Mirrors Verify().
func (a Algorithm) Sign(priv interface{}, signed []byte) ([]byte, error) {
	h := a.HashFunc.New()
	h.Write(signed)
	digest := h.Sum(nil)
	switch {
	case a.IsRSAPSS:
		rsaPriv, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("RSA-PSS expects *rsa.PrivateKey, got %T", priv)
		}
		return rsa.SignPSS(rand.Reader, rsaPriv, a.HashFunc, digest, &rsa.PSSOptions{
			SaltLength: a.HashFunc.Size(),
			Hash:       a.HashFunc,
		})
	case a.IsECDSA:
		ecPriv, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("ECDSA expects *ecdsa.PrivateKey, got %T", priv)
		}
		return ecdsa.SignASN1(rand.Reader, ecPriv, digest)
	case a.IsDSA:
		return nil, errors.New("DSA signing not supported")
	default: // RSA PKCS#1 v1.5
		rsaPriv, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("RSA-PKCS1 expects *rsa.PrivateKey, got %T", priv)
		}
		return rsa.SignPKCS1v15(rand.Reader, rsaPriv, a.HashFunc, digest)
	}
}

// PickAlgorithm chooses an appropriate Algorithm for the given private key
// type. Default to ChunkedSHA256 + matching key.
func PickAlgorithm(priv interface{}) (Algorithm, error) {
	switch priv.(type) {
	case *rsa.PrivateKey:
		a, _ := ByID(SigRSAPKCS1SHA256)
		return a, nil
	case *ecdsa.PrivateKey:
		a, _ := ByID(SigECDSASHA256)
		return a, nil
	}
	return Algorithm{}, fmt.Errorf("unsupported key type %T", priv)
}

// CertPublicKey extracts a typed public key from an x509 certificate.
func CertPublicKey(cert *x509.Certificate) (interface{}, error) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, *dsa.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported certificate public key %T", pub)
	}
}
