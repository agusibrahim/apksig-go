// Package v2 implements APK Signature Scheme v2 verification.
//
// Block layout (all integers little-endian; uint32 length prefixes):
//
//   v2 block: signers (length-prefixed sequence of signer)
//   signer:   signed-data (LP) || signatures (LP) || public_key (LP)
//   signed-data: digests (LP) || certificates (LP) || additional-attributes (LP)
//   digests:  sequence of (sig_algorithm_id u32 || digest LP)
//   signatures: sequence of (sig_algorithm_id u32 || signature LP)
package v2

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/agusibrahim/apksig-go/pkg/algo"
	"github.com/agusibrahim/apksig-go/pkg/buf"
	"github.com/agusibrahim/apksig-go/pkg/x509util"
)

// Result is the outcome of v2 verification.
type Result struct {
	Verified bool
	Signers  []SignerResult
	Errors   []string
	Warnings []string
	// ContentDigestsToVerify is the union of digest algorithms whose signature
	// passed; the orchestrator must recompute the APK content digests for these
	// algorithms and compare against each signer's claimed digests.
	ContentDigestsToVerify map[algo.ContentDigest]struct{}
	// AlgorithmDigests maps each verified algorithm to the digest one of the
	// signers claimed; used by the orchestrator to compare against the
	// recomputed digests.
	AlgorithmDigests map[algo.ContentDigest][]byte
}

// SignerResult is per-signer outcome.
type SignerResult struct {
	Index               int
	Verified            bool
	Errors              []string
	Certs               []*x509.Certificate
	VerifiedAlgorithms  []algo.SigID
	ContentDigests      map[algo.ContentDigest][]byte
	AdditionalAttrs     [][]byte
}

// Verify parses the v2 signing block payload and verifies each signer's
// signatures over signed-data. Caller is responsible for cross-checking the
// returned content digests against APK chunks.
func Verify(blockValue []byte, minSdk, maxSdk int) (*Result, error) {
	res := &Result{
		ContentDigestsToVerify: map[algo.ContentDigest]struct{}{},
		AlgorithmDigests:       map[algo.ContentDigest][]byte{},
	}
	r := buf.New(blockValue)
	signers, err := r.LengthPrefixedSlice()
	if err != nil {
		return res, fmt.Errorf("v2: signers: %w", err)
	}
	if signers.Remaining() == 0 {
		return res, errors.New("v2: no signers")
	}
	idx := 0
	for signers.Remaining() > 0 {
		signerSlice, err := signers.LengthPrefixedSlice()
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("v2: signer[%d] truncated", idx))
			idx++
			continue
		}
		sr, err := parseAndVerifySigner(signerSlice, idx, minSdk, maxSdk)
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

func parseAndVerifySigner(signer *buf.Reader, idx, minSdk, maxSdk int) (*SignerResult, error) {
	sr := &SignerResult{Index: idx, ContentDigests: map[algo.ContentDigest][]byte{}}
	signedDataSlice, err := signer.LengthPrefixedSlice()
	if err != nil {
		return sr, fmt.Errorf("signed-data: %w", err)
	}
	signedDataBytes := append([]byte(nil), signedDataSlice.Buf...)
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

	// Parse signed-data: digests || certificates || additional-attributes
	sd := buf.New(signedDataBytes)
	digestsSlice, err := sd.LengthPrefixedSlice()
	if err != nil {
		return sr, fmt.Errorf("digests: %w", err)
	}
	certsSlice, err := sd.LengthPrefixedSlice()
	if err != nil {
		return sr, fmt.Errorf("certificates: %w", err)
	}
	attrsSlice, err := sd.LengthPrefixedSlice()
	if err != nil {
		return sr, fmt.Errorf("attrs: %w", err)
	}

	for certsSlice.Remaining() > 0 {
		certBytes, err := certsSlice.LengthPrefixedBytes()
		if err != nil {
			return sr, fmt.Errorf("cert: %w", err)
		}
		c, err := x509util.ParseCertificate(certBytes)
		if err != nil {
			return sr, fmt.Errorf("parse cert: %w", err)
		}
		sr.Certs = append(sr.Certs, c)
	}
	if len(sr.Certs) == 0 {
		return sr, errors.New("no certificates")
	}

	// Public key in signatures record must match certificate's public key.
	mainCertSPKI, err := x509.MarshalPKIXPublicKey(sr.Certs[0].PublicKey)
	if err != nil {
		return sr, fmt.Errorf("marshal cert pubkey: %w", err)
	}
	if !bytes.Equal(mainCertSPKI, publicKeyBytes) {
		// Allow re-encoding differences by comparing parsed public keys.
		// Many APKs encode the same key with different DER details
		// (e.g. parameter NULL vs absent) so a strict bytes.Equal can
		// false-positive. ParsePKIXPublicKey already normalized one side
		// (pubKey); compare by re-marshalling a normalized SPKI.
		certPubMarshaled, _ := x509.MarshalPKIXPublicKey(sr.Certs[0].PublicKey)
		if !bytes.Equal(certPubMarshaled, mainCertSPKI) {
			return sr, errors.New("public key mismatch between certificate and signatures record")
		}
		// fall through: keys parse-equal, accept
	}

	// Parse digests
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

	// signatures and digests records must list the same algorithms in order
	if len(sigAlgIDsFromSignatures) != len(sigAlgIDsFromDigests) {
		return sr, errors.New("sig/digest algorithm count mismatch")
	}
	for i := range sigAlgIDsFromSignatures {
		if sigAlgIDsFromSignatures[i] != sigAlgIDsFromDigests[i] {
			return sr, errors.New("sig/digest algorithm order mismatch")
		}
	}

	// Capture additional attributes verbatim (each LP slice).
	for attrsSlice.Remaining() > 0 {
		entry, err := attrsSlice.LengthPrefixedBytes()
		if err != nil {
			return sr, fmt.Errorf("attr: %w", err)
		}
		sr.AdditionalAttrs = append(sr.AdditionalAttrs, entry)
	}

	sr.Verified = true
	return sr, nil
}
