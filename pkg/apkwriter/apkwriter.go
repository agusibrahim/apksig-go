// Package apkwriter assembles a signed APK by writing the original bytes up
// to the central directory, splicing in an APK Signing Block, then writing
// the central directory and an updated EOCD whose CD offset has been moved
// past the signing block.
package apkwriter

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/agusibrahim/apksig-go/pkg/algo"
	"github.com/agusibrahim/apksig-go/pkg/apksigblock"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
	"github.com/agusibrahim/apksig-go/pkg/digest"
	"github.com/agusibrahim/apksig-go/pkg/signer"
	zippkg "github.com/agusibrahim/apksig-go/pkg/zip"
)

var _ = errors.New

// SignedAPKWriter writes a signed APK out to w using src as the input.
//
// It will:
//   1. Compute content digests for src as if any existing signing block were
//      stripped (so re-signing is idempotent).
//   2. Build the v2 (and optionally v3) signing block payloads.
//   3. Stream original entry data + new signing block + CD + patched EOCD.
type SignedAPKWriter struct {
	Src     datasource.DataSource
	Signers []*signer.SignerConfig

	// Optional v3 SDK range; when both are zero, only v2 is written.
	V3MinSdk, V3MaxSdk int32

	// Optional v3.1 (block id 0x1b93ad61). When V31MinSdk > 0 a v3.1 pair is
	// written using the same Signers config; the v3 pair (if also requested)
	// will have its maxSdk capped at V31MinSdk-1 for compatibility.
	V31MinSdk, V31MaxSdk int32
}

// Write streams a signed APK to w.
func (sw *SignedAPKWriter) Write(w io.Writer) error {
	if len(sw.Signers) == 0 {
		return errors.New("apkwriter: no signers")
	}
	eocd, err := zippkg.FindEOCD(sw.Src)
	if err != nil {
		return fmt.Errorf("EOCD: %w", err)
	}
	// Determine where original ZIP entries end. If an APK Signing Block is
	// already present, "before block" is its start; otherwise it's the
	// stored CD offset.
	beforeEnd := eocd.CDStartOffset
	if blk, err := apksigblock.Find(sw.Src, eocd); err == nil {
		beforeEnd = blk.StartOffset
	}

	beforeBlock := sw.Src.Slice(0, beforeEnd)
	cd := sw.Src.Slice(eocd.CDStartOffset, eocd.CDSize)

	patchedEOCD := append([]byte(nil), eocd.Bytes...)
	// CD offset will be updated below once we know the signing block size.

	// Build content digests covering the algorithms we're signing under.
	algSet := map[algo.ContentDigest]struct{}{}
	for _, s := range sw.Signers {
		for _, a := range s.Algorithms {
			algSet[a.ContentDigest] = struct{}{}
		}
	}
	algos := make([]algo.ContentDigest, 0, len(algSet))
	for a := range algSet {
		algos = append(algos, a)
	}

	// First pass: compute digests with EOCD's CD offset set to beforeEnd.
	binary.LittleEndian.PutUint32(patchedEOCD[16:20], uint32(beforeEnd))
	digests, err := digest.Compute(algos, beforeBlock, cd, patchedEOCD)
	if err != nil {
		return fmt.Errorf("compute digests: %w", err)
	}

	// Build v2 + v3 pairs.
	var pairs []signer.Pair
	v2Value, err := buildSchemePair(sw.Signers, digests, false, sw.V3MinSdk, sw.V3MaxSdk)
	if err != nil {
		return err
	}
	pairs = append(pairs, signer.Pair{ID: apksigblock.IDV2Signature, Value: v2Value})

	if sw.V3MinSdk != 0 || sw.V3MaxSdk != 0 {
		v3Max := sw.V3MaxSdk
		// If v3.1 is also being written, cap v3 maxSdk at v3.1 minSdk-1.
		if sw.V31MinSdk != 0 && (v3Max == 0 || v3Max >= sw.V31MinSdk) {
			v3Max = sw.V31MinSdk - 1
		}
		v3Value, err := buildSchemePair(sw.Signers, digests, true, sw.V3MinSdk, v3Max)
		if err != nil {
			return err
		}
		pairs = append(pairs, signer.Pair{ID: apksigblock.IDV3Signature, Value: v3Value})
	}

	if sw.V31MinSdk != 0 {
		v31Value, err := buildSchemePair(sw.Signers, digests, true, sw.V31MinSdk, sw.V31MaxSdk)
		if err != nil {
			return err
		}
		pairs = append(pairs, signer.Pair{ID: apksigblock.IDV31Signature, Value: v31Value})
	}

	signingBlock := signer.AssembleSigningBlock(pairs)

	// Stream output: original bytes [0..beforeEnd) + signingBlock + CD + EOCD'
	if _, err := copyDS(w, beforeBlock); err != nil {
		return fmt.Errorf("copy entries: %w", err)
	}
	if _, err := w.Write(signingBlock); err != nil {
		return fmt.Errorf("write signing block: %w", err)
	}
	if _, err := copyDS(w, cd); err != nil {
		return fmt.Errorf("copy CD: %w", err)
	}
	// EOCD' has its CD offset = beforeEnd + len(signingBlock).
	newCDOff := uint32(beforeEnd + int64(len(signingBlock)))
	binary.LittleEndian.PutUint32(patchedEOCD[16:20], newCDOff)
	if _, err := w.Write(patchedEOCD); err != nil {
		return fmt.Errorf("write EOCD: %w", err)
	}
	return nil
}

func buildSchemePair(signers []*signer.SignerConfig, digests map[algo.ContentDigest][]byte, isV3 bool, minSdk, maxSdk int32) ([]byte, error) {
	// Each signer becomes a length-prefixed entry. The whole sequence is then
	// length-prefixed once more.
	var out []byte
	for _, s := range signers {
		var raw []byte
		var err error
		if isV3 {
			raw, err = signer.SignerPayloadV3(s, digests, minSdk, maxSdk)
		} else {
			raw, err = signer.SignerPayloadV2(s, digests)
		}
		if err != nil {
			return nil, err
		}
		// Length-prefix the per-signer payload.
		entry := make([]byte, 4+len(raw))
		binary.LittleEndian.PutUint32(entry[:4], uint32(len(raw)))
		copy(entry[4:], raw)
		out = append(out, entry...)
	}
	wrapped := make([]byte, 4+len(out))
	binary.LittleEndian.PutUint32(wrapped[:4], uint32(len(out)))
	copy(wrapped[4:], out)
	return wrapped, nil
}

func copyDS(w io.Writer, ds datasource.DataSource) (int64, error) {
	const blk = 1 << 20
	buf := make([]byte, blk)
	off := int64(0)
	for off < ds.Size() {
		n := int64(blk)
		if ds.Size()-off < n {
			n = ds.Size() - off
		}
		if _, err := ds.ReadAt(buf[:n], off); err != nil {
			return off, err
		}
		if _, err := w.Write(buf[:n]); err != nil {
			return off, err
		}
		off += n
	}
	return off, nil
}

// CertSubject is convenience for printing.
func CertSubject(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	return c.Subject.String()
}
