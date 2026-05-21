// Package v1 implements JAR signing (APK Signature Scheme v1) verification.
//
// v1 layout inside META-INF/:
//   MANIFEST.MF        — main attributes + per-entry SHA-256-Digest
//   <signer>.SF        — signed copy of MANIFEST.MF digests
//   <signer>.RSA/.DSA/.EC — PKCS#7 SignedData over the .SF bytes
//
// Verification:
//   1. For each .SF, find the matching .RSA/.DSA/.EC, parse PKCS#7,
//      verify the signature over the .SF bytes using the embedded cert.
//   2. The .SF either contains a digest of the entire MANIFEST.MF
//      (X-Android-APK-Signed / -Digest-Manifest) and/or per-entry digests
//      that must match the per-entry digests in MANIFEST.MF.
//   3. Each per-entry digest in MANIFEST.MF must match the actual digest of
//      the corresponding ZIP entry's uncompressed data.
package v1

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SHA-1 is allowed for legacy v1
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"

	"github.com/agusibrahim/apksig-go/pkg/datasource"
	"github.com/agusibrahim/apksig-go/pkg/jarmanifest"
	"github.com/agusibrahim/apksig-go/pkg/pkcs7"
	zippkg "github.com/agusibrahim/apksig-go/pkg/zip"
)

// Result is the outcome of v1 verification.
type Result struct {
	Verified bool
	Signers  []SignerResult
	Errors   []string
	Warnings []string
}

// SignerResult is per-signature-file outcome.
type SignerResult struct {
	SFFile   string
	SigFile  string
	Verified bool
	Cert     *x509.Certificate
	Errors   []string
	Warnings []string
}

// Verify runs the v1 verification given the APK's parsed central directory.
func Verify(ds datasource.DataSource, entries []zippkg.CDEntry) (*Result, error) {
	res := &Result{}
	byName := map[string]*zippkg.CDEntry{}
	for i := range entries {
		byName[entries[i].Name] = &entries[i]
	}

	manifestEntry, ok := byName["META-INF/MANIFEST.MF"]
	if !ok {
		return res, errors.New("META-INF/MANIFEST.MF missing")
	}
	manifestBytes, err := zippkg.ReadEntry(ds, manifestEntry)
	if err != nil {
		return res, fmt.Errorf("read MANIFEST.MF: %w", err)
	}
	manifestSections, err := jarmanifest.ParseAll(manifestBytes)
	if err != nil {
		return res, fmt.Errorf("parse MANIFEST.MF: %w", err)
	}
	if len(manifestSections) == 0 {
		return res, errors.New("MANIFEST.MF has no sections")
	}

	// Find signature pairs: <name>.SF + <name>.{RSA,DSA,EC}
	type sigPair struct {
		sfEntry  *zippkg.CDEntry
		sigEntry *zippkg.CDEntry
	}
	var pairs []sigPair
	for _, e := range entries {
		if !strings.HasPrefix(e.Name, "META-INF/") {
			continue
		}
		if !strings.HasSuffix(e.Name, ".SF") {
			continue
		}
		base := strings.TrimSuffix(e.Name, ".SF")
		var sigEntry *zippkg.CDEntry
		for _, ext := range []string{".RSA", ".DSA", ".EC"} {
			if x, ok := byName[base+ext]; ok {
				sigEntry = x
				break
			}
		}
		if sigEntry == nil {
			continue
		}
		eCopy := e
		pairs = append(pairs, sigPair{sfEntry: &eCopy, sigEntry: sigEntry})
	}
	if len(pairs) == 0 {
		return res, errors.New("no .SF/.RSA pair found")
	}

	// Per-entry digests from MANIFEST.MF that we will verify against actual
	// ZIP entry contents. Skip the main section.
	type expectedDigest struct {
		algo crypto.Hash
		hash []byte
	}
	manifestEntryDigests := map[string][]expectedDigest{}
	for i, sec := range manifestSections {
		if i == 0 {
			continue
		}
		name := sec.Name()
		if name == "" {
			continue
		}
		for _, alg := range supportedDigestNames() {
			val := sec.Get(alg.headerName)
			if val == "" {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(val)
			if err != nil {
				continue
			}
			manifestEntryDigests[name] = append(manifestEntryDigests[name], expectedDigest{
				algo: alg.hashFunc, hash: raw,
			})
		}
	}

	// Strict check: every entry referenced by MANIFEST.MF must exist in the
	// ZIP central directory. This catches tampered APKs that removed files
	// without updating the manifest.
	for name := range manifestEntryDigests {
		if _, ok := byName[name]; !ok {
			res.Errors = append(res.Errors,
				fmt.Sprintf("entry %s referenced by MANIFEST.MF not found in APK", name))
		}
	}

	// Verify ZIP entries match the per-entry manifest digests.
	for _, e := range entries {
		if strings.HasPrefix(e.Name, "META-INF/") {
			// META-INF entries (other than MANIFEST/SF/RSA themselves) are
			// generally not protected; mismatch here would be a manifest bug
			// (already handled below by missing-entry warnings).
			continue
		}
		if e.Name == "" || strings.HasSuffix(e.Name, "/") {
			continue
		}
		expected, ok := manifestEntryDigests[e.Name]
		if !ok {
			res.Warnings = append(res.Warnings, fmt.Sprintf("entry not in manifest: %s", e.Name))
			continue
		}
		data, err := zippkg.ReadEntry(ds, &e)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("read %s: %v", e.Name, err))
			continue
		}
		for _, d := range expected {
			h := d.algo.New()
			h.Write(data)
			actual := h.Sum(nil)
			if !bytes.Equal(actual, d.hash) {
				res.Errors = append(res.Errors,
					fmt.Sprintf("digest mismatch for %s (alg %v)", e.Name, d.algo))
			}
		}
	}

	// Verify each .SF + .RSA pair.
	for _, p := range pairs {
		sr := SignerResult{SFFile: p.sfEntry.Name, SigFile: p.sigEntry.Name}
		sfBytes, err := zippkg.ReadEntry(ds, p.sfEntry)
		if err != nil {
			sr.Errors = append(sr.Errors, fmt.Sprintf("read .SF: %v", err))
			res.Signers = append(res.Signers, sr)
			continue
		}
		sigBytes, err := zippkg.ReadEntry(ds, p.sigEntry)
		if err != nil {
			sr.Errors = append(sr.Errors, fmt.Sprintf("read sig: %v", err))
			res.Signers = append(res.Signers, sr)
			continue
		}
		sd, err := pkcs7.Parse(sigBytes)
		if err != nil {
			sr.Errors = append(sr.Errors, fmt.Sprintf("parse PKCS#7: %v", err))
			res.Signers = append(res.Signers, sr)
			continue
		}
		if len(sd.SignerInfos) == 0 {
			sr.Errors = append(sr.Errors, "no SignerInfo in PKCS#7")
			res.Signers = append(res.Signers, sr)
			continue
		}
		si := sd.SignerInfos[0]
		cert := sd.FindSignerCert(si)
		if cert == nil && len(sd.Certificates) > 0 {
			cert = sd.Certificates[0]
		}
		if cert == nil {
			sr.Errors = append(sr.Errors, "signer certificate not found")
			res.Signers = append(res.Signers, sr)
			continue
		}
		sr.Cert = cert
		// Verify signature over the .SF file bytes.
		hashAlg, err := digestHashFromOID(si.DigestAlgorithm)
		if err != nil {
			sr.Errors = append(sr.Errors, err.Error())
			res.Signers = append(res.Signers, sr)
			continue
		}
		// Choose verifier based on cert's public key type. JAR signing always
		// uses the raw .SF bytes as the signed content (no authenticated
		// attributes are protected on Android).
		if err := verifySignature(cert, hashAlg, sfBytes, si.Signature); err != nil {
			sr.Errors = append(sr.Errors, fmt.Sprintf("signature: %v", err))
			res.Signers = append(res.Signers, sr)
			continue
		}

		// Verify .SF main-section digest matches MANIFEST.MF.
		sfSections, err := jarmanifest.ParseAll(sfBytes)
		if err != nil {
			sr.Errors = append(sr.Errors, fmt.Sprintf("parse .SF: %v", err))
			res.Signers = append(res.Signers, sr)
			continue
		}
		if len(sfSections) == 0 {
			sr.Errors = append(sr.Errors, ".SF has no sections")
			res.Signers = append(res.Signers, sr)
			continue
		}
		main := sfSections[0]
		// Either X-Android-APK-Signed-* whole-manifest digest, or per-entry
		// digests must match.
		if !verifyManifestDigest(main, manifestBytes) {
			// Fall back to per-entry verification: each .SF section's digest
			// of "section i of MANIFEST.MF".
			if err := verifySFPerEntry(sfSections[1:], manifestSections[1:], manifestBytes); err != nil {
				sr.Errors = append(sr.Errors, fmt.Sprintf(".SF mismatch: %v", err))
				res.Signers = append(res.Signers, sr)
				continue
			}
		}

		sr.Verified = true
		res.Signers = append(res.Signers, sr)
	}

	allOK := len(res.Signers) > 0 && len(res.Errors) == 0
	for _, s := range res.Signers {
		if !s.Verified {
			allOK = false
			break
		}
	}
	res.Verified = allOK
	return res, nil
}

type digestSpec struct {
	headerName string
	hashFunc   crypto.Hash
}

func supportedDigestNames() []digestSpec {
	return []digestSpec{
		{"SHA-256-Digest", crypto.SHA256},
		{"SHA-512-Digest", crypto.SHA512},
		{"SHA1-Digest", crypto.SHA1},
		{"SHA-1-Digest", crypto.SHA1},
	}
}

func digestHashFromOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	s := oid.String()
	switch s {
	case "1.3.14.3.2.26":
		return crypto.SHA1, nil
	case "2.16.840.1.101.3.4.2.1":
		return crypto.SHA256, nil
	case "2.16.840.1.101.3.4.2.2":
		return crypto.SHA384, nil
	case "2.16.840.1.101.3.4.2.3":
		return crypto.SHA512, nil
	// SignatureAlgorithm OIDs imply both digest and key alg.
	case "1.2.840.113549.1.1.5":
		return crypto.SHA1, nil
	case "1.2.840.113549.1.1.11":
		return crypto.SHA256, nil
	case "1.2.840.113549.1.1.12":
		return crypto.SHA384, nil
	case "1.2.840.113549.1.1.13":
		return crypto.SHA512, nil
	case "1.2.840.10045.4.1":
		return crypto.SHA1, nil
	case "1.2.840.10045.4.3.2":
		return crypto.SHA256, nil
	case "1.2.840.10045.4.3.3":
		return crypto.SHA384, nil
	case "1.2.840.10045.4.3.4":
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("unsupported digest OID %s", s)
}

func verifySignature(cert *x509.Certificate, hashAlg crypto.Hash, signed, sig []byte) error {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		h := hashAlg.New()
		h.Write(signed)
		return rsa.VerifyPKCS1v15(pub, hashAlg, h.Sum(nil), sig)
	case *ecdsa.PublicKey:
		h := hashAlg.New()
		h.Write(signed)
		if !ecdsa.VerifyASN1(pub, h.Sum(nil), sig) {
			return errors.New("ECDSA verify failed")
		}
		return nil
	}
	return fmt.Errorf("unsupported public key type %T", cert.PublicKey)
}

func verifyManifestDigest(sfMain jarmanifest.Section, manifestBytes []byte) bool {
	for _, alg := range []struct {
		key string
		fn  func() hash.Hash
	}{
		{"SHA-256-Digest-Manifest", sha256.New},
		{"SHA-512-Digest-Manifest", sha512.New},
		{"SHA1-Digest-Manifest", sha1.New},
		{"SHA-1-Digest-Manifest", sha1.New},
	} {
		val := sfMain.Get(alg.key)
		if val == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(val)
		if err != nil {
			continue
		}
		h := alg.fn()
		h.Write(manifestBytes)
		if bytes.Equal(h.Sum(nil), raw) {
			return true
		}
	}
	return false
}

func verifySFPerEntry(sfSections, manifestSections []jarmanifest.Section, manifestBytes []byte) error {
	manifestByName := map[string]jarmanifest.Section{}
	for _, s := range manifestSections {
		manifestByName[s.Name()] = s
	}
	for _, sfSec := range sfSections {
		name := sfSec.Name()
		if name == "" {
			continue
		}
		mfSec, ok := manifestByName[name]
		if !ok {
			return fmt.Errorf("manifest section missing for %s", name)
		}
		secBytes, err := jarmanifest.SectionBytes(manifestBytes, mfSec)
		if err != nil {
			return err
		}
		matched := false
		for _, alg := range []struct {
			key string
			fn  func() hash.Hash
		}{
			{"SHA-256-Digest", sha256.New},
			{"SHA-512-Digest", sha512.New},
			{"SHA1-Digest", sha1.New},
			{"SHA-1-Digest", sha1.New},
		} {
			val := sfSec.Get(alg.key)
			if val == "" {
				continue
			}
			raw, err := base64.StdEncoding.DecodeString(val)
			if err != nil {
				continue
			}
			h := alg.fn()
			h.Write(secBytes)
			if bytes.Equal(h.Sum(nil), raw) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("section digest mismatch for %s", name)
		}
	}
	return nil
}
