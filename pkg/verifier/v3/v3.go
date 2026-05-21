// Package v3 implements APK Signature Scheme v3 verification.
//
// Differences from v2:
//   - Each signer carries minSdkVersion / maxSdkVersion (u32 LE) twice:
//     once in the signer header, once in signed-data (must match).
//   - additional-attributes may include the SigningCertificateLineage
//     (attribute id 0x3ba06f8c) which we surface as raw bytes.
//
// Layout:
//   v3 block: signers (LP)
//   signer:   signed-data (LP) || minSdk u32 || maxSdk u32 || signatures (LP) || public_key (LP)
//   signed-data: digests (LP) || certificates (LP) || minSdk u32 || maxSdk u32 || additional-attributes (LP)
package v3

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/agusibrahim/apksig-go/pkg/algo"
	"github.com/agusibrahim/apksig-go/pkg/buf"
	"github.com/agusibrahim/apksig-go/pkg/lineage"
	"github.com/agusibrahim/apksig-go/pkg/x509util"
)

const AttrIDProofOfRotation uint32 = 0x3ba06f8c

type Result struct {
	Verified bool
	Signers  []SignerResult
	Errors   []string
	ContentDigestsToVerify map[algo.ContentDigest]struct{}
	AlgorithmDigests       map[algo.ContentDigest][]byte
}

type SignerResult struct {
	Index              int
	Verified           bool
	Errors             []string
	Certs              []*x509.Certificate
	MinSDK             int32
	MaxSDK             int32
	VerifiedAlgorithms []algo.SigID
	ContentDigests     map[algo.ContentDigest][]byte
	AdditionalAttrs    []Attribute
	LineageBytes       []byte
	Lineage            *lineage.Lineage
}

type Attribute struct {
	ID    uint32
	Value []byte
}

func Verify(blockValue []byte, minSdk, maxSdk int) (*Result, error) {
	res := &Result{
		ContentDigestsToVerify: map[algo.ContentDigest]struct{}{},
		AlgorithmDigests:       map[algo.ContentDigest][]byte{},
	}
	r := buf.New(blockValue)
	signers, err := r.LengthPrefixedSlice()
	if err != nil {
		return res, fmt.Errorf("v3: signers: %w", err)
	}
	if signers.Remaining() == 0 {
		return res, errors.New("v3: no signers")
	}
	idx := 0
	for signers.Remaining() > 0 {
		signerSlice, err := signers.LengthPrefixedSlice()
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("signer[%d] truncated", idx))
			idx++
			continue
		}
		sr, err := parseAndVerifySigner(signerSlice, idx)
		if err != nil {
			sr.Errors = append(sr.Errors, err.Error())
		}
		res.Signers = append(res.Signers, *sr)
		if sr.Verified {
			for d, dg := range sr.ContentDigests {
				res.ContentDigestsToVerify[d] = struct{}{}
				if _, ok := res.AlgorithmDigests[d]; !ok {
					res.AlgorithmDigests[d] = dg
				}
			}
		}
		idx++
	}
	allOK := len(res.Signers) > 0
	for _, s := range res.Signers {
		if !s.Verified {
			allOK = false
			break
		}
	}
	res.Verified = allOK
	return res, nil
}

func parseAndVerifySigner(signer *buf.Reader, idx int) (*SignerResult, error) {
	sr := &SignerResult{Index: idx, ContentDigests: map[algo.ContentDigest][]byte{}}
	signedDataSlice, err := signer.LengthPrefixedSlice()
	if err != nil {
		return sr, fmt.Errorf("signed-data: %w", err)
	}
	signedDataBytes := append([]byte(nil), signedDataSlice.Buf...)
	hdrMin, err := signer.U32()
	if err != nil {
		return sr, fmt.Errorf("hdr min: %w", err)
	}
	hdrMax, err := signer.U32()
	if err != nil {
		return sr, fmt.Errorf("hdr max: %w", err)
	}
	sr.MinSDK = int32(hdrMin)
	sr.MaxSDK = int32(hdrMax)
	signaturesSlice, err := signer.LengthPrefixedSlice()
	if err != nil {
		return sr, fmt.Errorf("signatures: %w", err)
	}
	publicKeyBytes, err := signer.LengthPrefixedBytes()
	if err != nil {
		return sr, fmt.Errorf("public key: %w", err)
	}
	pubKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return sr, fmt.Errorf("parse public key: %w", err)
	}

	type sigEntry struct {
		alg     algo.Algorithm
		sigBytes []byte
	}
	var sigs []sigEntry
	var sigAlgIDsFromSignatures []algo.SigID
	for signaturesSlice.Remaining() > 0 {
		entry, err := signaturesSlice.LengthPrefixedSlice()
		if err != nil {
			return sr, fmt.Errorf("signature entry: %w", err)
		}
		algID, err := entry.U32()
		if err != nil {
			return sr, fmt.Errorf("sig alg id: %w", err)
		}
		sigBytes, err := entry.LengthPrefixedBytes()
		if err != nil {
			return sr, fmt.Errorf("sig bytes: %w", err)
		}
		sigAlgIDsFromSignatures = append(sigAlgIDsFromSignatures, algo.SigID(algID))
		a, ok := algo.ByID(algo.SigID(algID))
		if !ok {
			sr.Errors = append(sr.Errors, fmt.Sprintf("unknown sig algorithm 0x%x", algID))
			continue
		}
		sigs = append(sigs, sigEntry{a, sigBytes})
	}
	if len(sigs) == 0 {
		return sr, errors.New("no supported signature algorithms")
	}
	for _, s := range sigs {
		if err := s.alg.Verify(pubKey, signedDataBytes, s.sigBytes); err != nil {
			return sr, fmt.Errorf("signature verification failed (alg 0x%x): %w", s.alg.ID, err)
		}
		sr.VerifiedAlgorithms = append(sr.VerifiedAlgorithms, s.alg.ID)
	}

	// Parse signed-data
	sd := buf.New(signedDataBytes)
	digestsSlice, err := sd.LengthPrefixedSlice()
	if err != nil {
		return sr, fmt.Errorf("digests: %w", err)
	}
	certsSlice, err := sd.LengthPrefixedSlice()
	if err != nil {
		return sr, fmt.Errorf("certificates: %w", err)
	}
	signedMin, err := sd.U32()
	if err != nil {
		return sr, fmt.Errorf("signed-data min: %w", err)
	}
	signedMax, err := sd.U32()
	if err != nil {
		return sr, fmt.Errorf("signed-data max: %w", err)
	}
	if int32(signedMin) != sr.MinSDK || int32(signedMax) != sr.MaxSDK {
		return sr, fmt.Errorf("signed-data SDK range mismatch: header=[%d,%d] signed=[%d,%d]",
			sr.MinSDK, sr.MaxSDK, int32(signedMin), int32(signedMax))
	}
	attrsSlice, err := sd.LengthPrefixedSlice()
	if err != nil {
		return sr, fmt.Errorf("attrs: %w", err)
	}

	for certsSlice.Remaining() > 0 {
		cb, err := certsSlice.LengthPrefixedBytes()
		if err != nil {
			return sr, fmt.Errorf("cert: %w", err)
		}
		c, err := x509util.ParseCertificate(cb)
		if err != nil {
			return sr, fmt.Errorf("parse cert: %w", err)
		}
		sr.Certs = append(sr.Certs, c)
	}
	if len(sr.Certs) == 0 {
		return sr, errors.New("no certificates")
	}
	mainSPKI, err := x509.MarshalPKIXPublicKey(sr.Certs[0].PublicKey)
	if err != nil {
		return sr, fmt.Errorf("marshal cert pubkey: %w", err)
	}
	if !bytes.Equal(mainSPKI, publicKeyBytes) {
		return sr, errors.New("public key mismatch between certificate and signatures record")
	}

	var sigAlgIDsFromDigests []algo.SigID
	for digestsSlice.Remaining() > 0 {
		entry, err := digestsSlice.LengthPrefixedSlice()
		if err != nil {
			return sr, fmt.Errorf("digest entry: %w", err)
		}
		algID, err := entry.U32()
		if err != nil {
			return sr, fmt.Errorf("digest alg id: %w", err)
		}
		dbytes, err := entry.LengthPrefixedBytes()
		if err != nil {
			return sr, fmt.Errorf("digest bytes: %w", err)
		}
		sigAlgIDsFromDigests = append(sigAlgIDsFromDigests, algo.SigID(algID))
		a, ok := algo.ByID(algo.SigID(algID))
		if !ok {
			continue
		}
		sr.ContentDigests[a.ContentDigest] = dbytes
	}
	if len(sigAlgIDsFromSignatures) != len(sigAlgIDsFromDigests) {
		return sr, errors.New("sig/digest algorithm count mismatch")
	}
	for i := range sigAlgIDsFromSignatures {
		if sigAlgIDsFromSignatures[i] != sigAlgIDsFromDigests[i] {
			return sr, errors.New("sig/digest algorithm order mismatch")
		}
	}

	for attrsSlice.Remaining() > 0 {
		entry, err := attrsSlice.LengthPrefixedSlice()
		if err != nil {
			return sr, fmt.Errorf("attr: %w", err)
		}
		attrID, err := entry.U32()
		if err != nil {
			return sr, fmt.Errorf("attr id: %w", err)
		}
		val := append([]byte(nil), entry.Buf[entry.Off:]...)
		sr.AdditionalAttrs = append(sr.AdditionalAttrs, Attribute{ID: attrID, Value: val})
		if attrID == AttrIDProofOfRotation {
			sr.LineageBytes = val
			if lin, err := lineage.DecodeRaw(val); err == nil {
				sr.Lineage = lin
			}
		}
	}

	sr.Verified = true
	return sr, nil
}
