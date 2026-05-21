// Package apkwriter assembles a signed APK by writing the original bytes up
// to the central directory, splicing in an APK Signing Block, then writing
// the central directory and an updated EOCD whose CD offset has been moved
// past the signing block.
package apkwriter

import (
	"bytes"
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
type SignedAPKWriter struct {
	Src     datasource.DataSource
	Signers []*signer.SignerConfig

	// Optional v3 SDK range; when both are zero, only v2 is written.
	V3MinSdk, V3MaxSdk int32

	// Optional v3.1 (block id 0x1b93ad61). When V31MinSdk > 0 a v3.1 pair is
	// written using the same Signers config; the v3 pair (if also requested)
	// will have its maxSdk capped at V31MinSdk-1 for compatibility.
	V31MinSdk, V31MaxSdk int32

	// Align enables 4-byte alignment of uncompressed ZIP entries (zipalign).
	// When true, the entry region is rewritten with alignment extra fields
	// (0xd935) and CD offsets are patched accordingly.
	Align bool
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
	beforeEnd := eocd.CDStartOffset
	if blk, err := apksigblock.Find(sw.Src, eocd); err == nil {
		beforeEnd = blk.StartOffset
	}

	patchedEOCD := append([]byte(nil), eocd.Bytes...)

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

	var (
		entriesBeforeCD datasource.DataSource // aligned or raw entry region
		cdBytes         []byte                // CD bytes (possibly patched)
	)

	if sw.Align {
		entriesBeforeCD, cdBytes, err = sw.buildAligned(beforeEnd, eocd)
		if err != nil {
			return err
		}
	} else {
		entriesBeforeCD = sw.Src.Slice(0, beforeEnd)
		cdBytes, err = datasource.ReadAll(sw.Src.Slice(eocd.CDStartOffset, eocd.CDSize))
		if err != nil {
			return err
		}
	}

	cdDS := datasource.NewBytes(cdBytes)

	// Compute digests with EOCD's CD offset set to entriesBeforeCD size.
	entrySize := entriesBeforeCD.Size()
	binary.LittleEndian.PutUint32(patchedEOCD[16:20], uint32(entrySize))
	digests, err := digest.Compute(algos, entriesBeforeCD, cdDS, patchedEOCD)
	if err != nil {
		return fmt.Errorf("compute digests: %w", err)
	}

	// Build signing block pairs.
	var pairs []signer.Pair
	v2Value, err := buildSchemePair(sw.Signers, digests, false, sw.V3MinSdk, sw.V3MaxSdk)
	if err != nil {
		return err
	}
	pairs = append(pairs, signer.Pair{ID: apksigblock.IDV2Signature, Value: v2Value})

	if sw.V3MinSdk != 0 || sw.V3MaxSdk != 0 {
		v3Max := sw.V3MaxSdk
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

	// Stream output.
	if _, err := copyDS(w, entriesBeforeCD); err != nil {
		return fmt.Errorf("copy entries: %w", err)
	}
	if _, err := w.Write(signingBlock); err != nil {
		return fmt.Errorf("write signing block: %w", err)
	}
	if _, err := w.Write(cdBytes); err != nil {
		return fmt.Errorf("copy CD: %w", err)
	}
	newCDOff := uint32(entrySize + int64(len(signingBlock)))
	binary.LittleEndian.PutUint32(patchedEOCD[16:20], newCDOff)
	if _, err := w.Write(patchedEOCD); err != nil {
		return fmt.Errorf("write EOCD: %w", err)
	}
	return nil
}

// buildAligned produces an aligned entry region and patched CD bytes.
func (sw *SignedAPKWriter) buildAligned(beforeEnd int64, eocd *zippkg.EOCD) (datasource.DataSource, []byte, error) {
	entries, err := zippkg.ParseCD(sw.Src, eocd)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CD: %w", err)
	}
	plans, _, err := zippkg.ComputeAlignPlan(sw.Src, entries)
	if err != nil {
		return nil, nil, fmt.Errorf("align plan: %w", err)
	}

	var entryBuf bytes.Buffer
	newOffsets := make([]int64, len(entries))
	var outOffset int64

	for i, e := range entries {
		newOffsets[i] = outOffset
		// Determine total entry size including any data descriptor that
		// follows the compressed data when the GP flag bit 3 is set.
		ddSize, err := dataDescriptorSize(sw.Src, &entries[i], plans[i].EntryStart+plans[i].OriginalLFHSize+plans[i].DataSize)
		if err != nil {
			return nil, nil, fmt.Errorf("dd size %s: %w", e.Name, err)
		}
		if e.CompressionMethod != 0 {
			// Compressed entry: copy raw bytes verbatim (no LFH rewrite).
			entrySize := plans[i].OriginalLFHSize + plans[i].DataSize + ddSize
			n, err := copyDS(&entryBuf, sw.Src.Slice(plans[i].EntryStart, entrySize))
			if err != nil {
				return nil, nil, fmt.Errorf("copy entry %s: %w", e.Name, err)
			}
			outOffset += n
		} else {
			// Stored entry: check if data is already 4-byte aligned at the
			// output position. If so, copy verbatim to preserve page alignment
			// that may already exist for .so files.
			dataOff := outOffset + plans[i].OriginalLFHSize
			if dataOff%4 == 0 {
				entrySize := plans[i].OriginalLFHSize + plans[i].DataSize + ddSize
				n, err := copyDS(&entryBuf, sw.Src.Slice(plans[i].EntryStart, entrySize))
				if err != nil {
					return nil, nil, fmt.Errorf("copy entry %s: %w", e.Name, err)
				}
				outOffset += n
			} else {
				n, err := zippkg.WriteAlignedEntry(&entryBuf, sw.Src, &entries[i], &plans[i], outOffset)
				if err != nil {
					return nil, nil, fmt.Errorf("align entry %s: %w", e.Name, err)
				}
				outOffset += n
				if ddSize > 0 {
					ddStart := plans[i].EntryStart + plans[i].OriginalLFHSize + plans[i].DataSize
					nd, err := copyDS(&entryBuf, sw.Src.Slice(ddStart, ddSize))
					if err != nil {
						return nil, nil, fmt.Errorf("copy dd %s: %w", e.Name, err)
					}
					outOffset += nd
				}
			}
		}
	}

	// Read original CD and patch LFH offsets
	cdBytes, err := datasource.ReadAll(sw.Src.Slice(eocd.CDStartOffset, eocd.CDSize))
	if err != nil {
		return nil, nil, err
	}
	patchedCD := zippkg.PatchCDOffsets(cdBytes, entries, newOffsets)

	return datasource.NewBytes(entryBuf.Bytes()), patchedCD, nil
}

func buildSchemePair(signers []*signer.SignerConfig, digests map[algo.ContentDigest][]byte, isV3 bool, minSdk, maxSdk int32) ([]byte, error) {
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

// dataDescriptorSize returns the size in bytes of any post-data descriptor
// for an entry. When GP flag bit 3 is set, the LFH carries zero CRC/size
// fields and the actual values follow the compressed data. The descriptor is
// 12 bytes (crc32, csize, usize) and may be preceded by the optional 4-byte
// signature 0x08074b50.
func dataDescriptorSize(ds datasource.DataSource, e *zippkg.CDEntry, dataEnd int64) (int64, error) {
	if e.GeneralPurpose&0x08 == 0 {
		return 0, nil
	}
	hdr := make([]byte, 4)
	if _, err := ds.ReadAt(hdr, dataEnd); err != nil {
		return 0, err
	}
	if binary.LittleEndian.Uint32(hdr) == 0x08074b50 {
		return 16, nil
	}
	return 12, nil
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
