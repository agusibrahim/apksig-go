// Package apkverifier orchestrates v1/v2/v3 signature verification for an APK.
//
// Strategy:
//   1. Load EOCD, central directory, signing block.
//   2. Try v3.1 → v3 → v2 in order. The highest available scheme is the
//      authoritative one for the verification result on modern Android.
//   3. Recompute the chunked content digest for each algorithm claimed by the
//      verified scheme(s) and compare against the per-signer digests.
//   4. If only v1 is present, fall back to JAR signing verification.
package apkverifier

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/agusibrahim/apksig-go/pkg/algo"
	"github.com/agusibrahim/apksig-go/pkg/apksigblock"
	"github.com/agusibrahim/apksig-go/pkg/axml"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
	"github.com/agusibrahim/apksig-go/pkg/digest"
	v1pkg "github.com/agusibrahim/apksig-go/pkg/verifier/v1"
	v2pkg "github.com/agusibrahim/apksig-go/pkg/verifier/v2"
	v3pkg "github.com/agusibrahim/apksig-go/pkg/verifier/v3"
	zippkg "github.com/agusibrahim/apksig-go/pkg/zip"
)

// Result summarises verification across schemes.
type Result struct {
	Verified       bool
	V1Verified     bool
	V2Verified     bool
	V3Verified     bool
	V31Verified    bool
	HasV2Block     bool
	HasV3Block     bool
	HasV31Block    bool
	V2             *v2pkg.Result
	V3             *v3pkg.Result
	V31            *v3pkg.Result
	V1             *v1pkg.Result
	DetectedMinSdk int
	Errors         []string
	Warnings       []string
	SignerCerts    [][]byte // Encoded x509 of the apparent signer(s) (DER)

	// Alignment info for uncompressed entries.
	Aligned4KB    bool     // true if all uncompressed .so entries are 4KB-aligned
	MisalignedFiles []string // entries that failed 4KB alignment check
}

// V1Result is a placeholder kept for backwards compat with earlier scaffolding.
type V1Result = v1pkg.Result

// Verify runs the orchestrated verification on a DataSource. minSdk and maxSdk
// constrain compatibility checks; pass 0 and 0 to use sensible defaults
// (minSdk=24 for v2/v3 only, maxSdk = current).
func Verify(ds datasource.DataSource, minSdk, maxSdk int) (*Result, error) {
	if minSdk == 0 {
		minSdk = 24
	}
	if maxSdk == 0 {
		maxSdk = 35
	}
	res := &Result{}
	eocd, err := zippkg.FindEOCD(ds)
	if err != nil {
		return res, fmt.Errorf("EOCD: %w", err)
	}
	cdEntries, cdErr := zippkg.ParseCD(ds, eocd)
	if cdErr != nil {
		res.Warnings = append(res.Warnings, "CD parse: "+cdErr.Error())
	}
	block, err := apksigblock.Find(ds, eocd)
	if err != nil {
		// No signing block; v1-only path.
		res.Warnings = append(res.Warnings, "no APK Signing Block: "+err.Error())
	}
	beforeBlock := datasource.DataSource(nil)
	cd := datasource.DataSource(nil)
	var patchedEOCD []byte
	if block != nil {
		beforeBlock = ds.Slice(0, block.StartOffset)
		cd = ds.Slice(eocd.CDStartOffset, eocd.CDSize)
		patchedEOCD = append([]byte(nil), eocd.Bytes...)
		patchEOCDCDOffset(patchedEOCD, uint32(block.StartOffset))
	}

	if p := mayFindPair(block, apksigblock.IDV31Signature); p != nil {
		res.HasV31Block = true
		v31r, vErr := v3pkg.Verify(p.Value, minSdk, maxSdk)
		res.V31 = v31r
		if vErr != nil {
			res.Errors = append(res.Errors, "v3.1: "+vErr.Error())
		}
		if v31r != nil && v31r.Verified {
			if err := verifyContentDigests(beforeBlock, cd, patchedEOCD, v31r.AlgorithmDigests); err != nil {
				res.Errors = append(res.Errors, "v3.1 content digest: "+err.Error())
			} else {
				res.V31Verified = true
			}
		}
	}
	if p := mayFindPair(block, apksigblock.IDV3Signature); p != nil {
		res.HasV3Block = true
		v3r, vErr := v3pkg.Verify(p.Value, minSdk, maxSdk)
		res.V3 = v3r
		if vErr != nil {
			res.Errors = append(res.Errors, "v3: "+vErr.Error())
		}
		if v3r != nil && v3r.Verified {
			if err := verifyContentDigests(beforeBlock, cd, patchedEOCD, v3r.AlgorithmDigests); err != nil {
				res.Errors = append(res.Errors, "v3 content digest: "+err.Error())
			} else {
				res.V3Verified = true
				if len(v3r.Signers) > 0 && len(v3r.Signers[0].Certs) > 0 {
					for _, c := range v3r.Signers[0].Certs {
						res.SignerCerts = append(res.SignerCerts, c.Raw)
					}
				}
			}
		}
	}
	if p := mayFindPair(block, apksigblock.IDV2Signature); p != nil {
		res.HasV2Block = true
		v2r, vErr := v2pkg.Verify(p.Value, minSdk, maxSdk)
		res.V2 = v2r
		if vErr != nil {
			res.Errors = append(res.Errors, "v2: "+vErr.Error())
		}
		if v2r != nil && v2r.Verified {
			if err := verifyContentDigests(beforeBlock, cd, patchedEOCD, v2r.AlgorithmDigests); err != nil {
				res.Errors = append(res.Errors, "v2 content digest: "+err.Error())
			} else {
				res.V2Verified = true
				if len(res.SignerCerts) == 0 && len(v2r.Signers) > 0 {
					for _, c := range v2r.Signers[0].Certs {
						res.SignerCerts = append(res.SignerCerts, c.Raw)
					}
				}
			}
		}
	}

	res.Verified = res.V31Verified || res.V3Verified || res.V2Verified

	// v1: only attempt if no v2/v3 found (or always, for diagnostic).
	if len(cdEntries) > 0 {
		v1r, vErr := v1pkg.Verify(ds, cdEntries)
		if vErr == nil {
			res.V1 = v1r
			res.V1Verified = v1r.Verified
			if !res.Verified && res.V1Verified {
				res.Verified = true
			}
		} else {
			res.Warnings = append(res.Warnings, "v1: "+vErr.Error())
		}
	}

	// minSdk-aware rule: if the APK declares minSdk < 24 in AndroidManifest.xml
	// and the only verified scheme is v2/v3 (which Android < 7.0 cannot read),
	// the APK is effectively unverifiable on the lowest supported platform.
	// apksigner enforces this strictly; we mirror that behaviour.
	if effectiveMin := detectAPKMinSdk(ds, cdEntries); effectiveMin > 0 {
		res.DetectedMinSdk = effectiveMin
		if effectiveMin < 24 && !res.V1Verified {
			res.Verified = false
			res.Errors = append(res.Errors,
				fmt.Sprintf("APK declares minSdk=%d but has no valid v1 (JAR) signature; required for Android < 7.0",
					effectiveMin))
		}
	}

	// Check 4KB page alignment for uncompressed .so entries.
	if len(cdEntries) > 0 {
		checkAlignment(ds, cdEntries, res)
	}

	return res, nil
}

// detectAPKMinSdk returns the minSdk declared in the APK's AndroidManifest.xml
// or 0 if it could not be determined.
func detectAPKMinSdk(ds datasource.DataSource, entries []zippkg.CDEntry) int {
	for i := range entries {
		if entries[i].Name == "AndroidManifest.xml" {
			data, err := zippkg.ReadEntry(ds, &entries[i])
			if err != nil {
				return 0
			}
			min, err := axml.MinSdk(data)
			if err != nil {
				return 0
			}
			return min
		}
	}
	return 0
}

func checkAlignment(ds datasource.DataSource, entries []zippkg.CDEntry, res *Result) {
	allAligned := true
	for i := range entries {
		e := &entries[i]
		// Only check uncompressed entries with .so extension
		if e.CompressionMethod != 0 || len(e.Name) < 4 || e.Name[len(e.Name)-3:] != ".so" {
			continue
		}
		dataOff, err := zippkg.EntryDataOffset(ds, e)
		if err != nil {
			continue
		}
		if dataOff%4096 != 0 {
			allAligned = false
			res.MisalignedFiles = append(res.MisalignedFiles, e.Name)
		}
	}
	if len(res.MisalignedFiles) > 0 {
		allAligned = false
	}
	res.Aligned4KB = allAligned
}

func mayFindPair(b *apksigblock.Block, id uint32) *apksigblock.Pair {
	if b == nil {
		return nil
	}
	return b.FindPair(id)
}

func patchEOCDCDOffset(eocd []byte, off uint32) {
	if len(eocd) < 22 {
		return
	}
	// CD start offset is at bytes 16..20 (little-endian).
	eocd[16] = byte(off)
	eocd[17] = byte(off >> 8)
	eocd[18] = byte(off >> 16)
	eocd[19] = byte(off >> 24)
}

func verifyContentDigests(
	beforeBlock, cd datasource.DataSource,
	eocd []byte,
	expected map[algo.ContentDigest][]byte,
) error {
	if len(expected) == 0 {
		return errors.New("no claimed digests")
	}
	algos := make([]algo.ContentDigest, 0, len(expected))
	for a := range expected {
		algos = append(algos, a)
	}
	got, err := digest.Compute(algos, beforeBlock, cd, eocd)
	if err != nil {
		return err
	}
	for a, claim := range expected {
		actual, ok := got[a]
		if !ok {
			return fmt.Errorf("missing digest for %v", a)
		}
		if !bytes.Equal(actual, claim) {
			return fmt.Errorf("content digest mismatch for %v: got %x want %x", a, actual, claim)
		}
	}
	return nil
}
