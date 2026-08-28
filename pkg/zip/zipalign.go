package zip

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/agusibrahim/apksig-go/pkg/datasource"
)

const (
	alignExtraID = 0xd935 // Android zipalign extra field header ID

	// Official apksigner extra layout (ApkSigner.java):
	//   uint16 header ID (0xd935)
	//   uint16 payload size
	//   payload: uint16 alignment multiple + zero padding
	// Minimum extra field size including the 4-byte header is 6 bytes.
	alignExtraMinSize = 6

	// DefaultAlignmentBytes is zipalign's alignment for uncompressed files.
	DefaultAlignmentBytes int64 = 4
	// SoPageAlignmentBytes is zipalign -P 16: page-align uncompressed .so
	// files so they can be mmap()'d on both 4KB and 16KB Android devices.
	SoPageAlignmentBytes int64 = 16384
)

// AlignPlan describes how each entry's LFH should be modified for alignment.
type AlignPlan struct {
	// OriginalLFHSize is the size of the original LFH (30 + nameLen + extraLen).
	OriginalLFHSize int64
	// DataSize is the compressed data size (copied verbatim).
	DataSize int64
	// EntryStart is the original start offset of this entry in the source.
	EntryStart int64
	// Alignment is the required data-offset multiple (1 = none).
	Alignment int64
}

// IsUncompressedNativeLib reports whether e is a STORED .so that must be
// page-aligned for extractNativeLibs=false.
func IsUncompressedNativeLib(e *CDEntry) bool {
	return e != nil && e.CompressionMethod == 0 && strings.HasSuffix(e.Name, ".so")
}

// DataAlignment returns the required data-offset alignment for an entry.
// Compressed entries return 1 (no alignment). Uncompressed .so files use
// 16KiB page alignment; other stored files use 4 bytes.
func DataAlignment(e *CDEntry) int64 {
	if e == nil || e.CompressionMethod != 0 {
		return 1
	}
	if strings.HasSuffix(e.Name, ".so") {
		return SoPageAlignmentBytes
	}
	return DefaultAlignmentBytes
}

// ComputeAlignPlan builds an alignment plan for all entries. The real extra
// field lengths are computed later by WriteAlignedEntry against the running
// output offset; the plan only records each entry's original layout.
func ComputeAlignPlan(ds datasource.DataSource, entries []CDEntry) ([]AlignPlan, error) {
	plans := make([]AlignPlan, len(entries))

	for i, e := range entries {
		hdr := make([]byte, 30)
		if _, err := ds.ReadAt(hdr, e.LFHOffset); err != nil {
			return nil, err
		}
		nameLen := int64(binary.LittleEndian.Uint16(hdr[26:28]))
		origExtraLen := int64(binary.LittleEndian.Uint16(hdr[28:30]))
		origLFHSize := 30 + nameLen + origExtraLen

		plans[i] = AlignPlan{
			OriginalLFHSize: origLFHSize,
			DataSize:        int64(e.CompressedSize),
			EntryStart:      e.LFHOffset,
			Alignment:       DataAlignment(&entries[i]),
		}
	}

	return plans, nil
}

// alignExtraLen is the extra field length needed so that
//
//	entryStart + 30 + nameLen + extraLen ≡ 0 (mod alignment)
//
// when the extra field is kept extras followed by a 0xd935 alignment field.
func alignExtraLen(entryStart, nameLen, keptExtraLen, alignment int64) int64 {
	if alignment <= 1 {
		return keptExtraLen
	}
	minExtra := keptExtraLen + alignExtraMinSize
	pad := (alignment - (entryStart+30+nameLen+minExtra)%alignment) % alignment
	return minExtra + pad
}

// WriteAlignedEntry writes a single LFH + data for an entry with alignment.
// Returns the number of bytes written.
func WriteAlignedEntry(w io.Writer, ds datasource.DataSource, e *CDEntry, plan *AlignPlan, outOffset int64) (int64, error) {
	origLFH := make([]byte, plan.OriginalLFHSize)
	if _, err := ds.ReadAt(origLFH, plan.EntryStart); err != nil {
		return 0, err
	}
	nameLen := int64(binary.LittleEndian.Uint16(origLFH[26:28]))
	origExtra := origLFH[30+nameLen : plan.OriginalLFHSize]
	kept := stripAlignmentExtra(origExtra)

	alignTo := plan.Alignment
	if alignTo == 0 {
		alignTo = DataAlignment(e)
	}

	var newExtraLen int64
	if e.CompressionMethod == 0 && alignTo > 1 {
		newExtraLen = alignExtraLen(outOffset, nameLen, int64(len(kept)), alignTo)
		if newExtraLen > 0xffff {
			return 0, fmt.Errorf("alignment extra for %s exceeds ZIP extra-field limit", e.Name)
		}
	} else {
		newExtraLen = int64(len(origExtra))
	}

	binary.LittleEndian.PutUint16(origLFH[28:30], uint16(newExtraLen))
	if _, err := w.Write(origLFH[:30]); err != nil {
		return 0, err
	}
	if _, err := w.Write(origLFH[30 : 30+nameLen]); err != nil {
		return 0, err
	}

	if e.CompressionMethod == 0 && alignTo > 1 {
		paddingSize := newExtraLen - int64(len(kept)) - alignExtraMinSize
		extra := make([]byte, newExtraLen)
		copy(extra, kept)
		off := len(kept)
		binary.LittleEndian.PutUint16(extra[off:off+2], alignExtraID)
		binary.LittleEndian.PutUint16(extra[off+2:off+4], uint16(2+paddingSize))
		binary.LittleEndian.PutUint16(extra[off+4:off+6], uint16(alignTo))
		if _, err := w.Write(extra); err != nil {
			return 0, err
		}
	} else if len(origExtra) > 0 {
		if _, err := w.Write(origExtra); err != nil {
			return 0, err
		}
	}

	dataOff := plan.EntryStart + plan.OriginalLFHSize
	dataSize := plan.DataSize
	if dataSize > 0 {
		dataSlice := ds.Slice(dataOff, dataSize)
		if _, err := copyToWriter(w, dataSlice); err != nil {
			return 0, err
		}
	}

	return 30 + nameLen + newExtraLen + dataSize, nil
}

// stripAlignmentExtra copies extra fields except the Android 0xd935 alignment
// field and the legacy all-zero padding records (header ID 0, size 0).
func stripAlignmentExtra(extra []byte) []byte {
	var out []byte
	i := 0
	for i+4 <= len(extra) {
		id := binary.LittleEndian.Uint16(extra[i : i+2])
		size := int(binary.LittleEndian.Uint16(extra[i+2 : i+4]))
		if i+4+size > len(extra) {
			break
		}
		if id == alignExtraID || (id == 0 && size == 0) {
			i += 4 + size
			continue
		}
		out = append(out, extra[i:i+4+size]...)
		i += 4 + size
	}
	return out
}

// PatchCDOffsets returns a copy of the CD bytes with updated LFH offsets.
// offsets[i] is the new LFH offset for entries[i].
func PatchCDOffsets(cdBytes []byte, entries []CDEntry, offsets []int64) []byte {
	patched := append([]byte(nil), cdBytes...)
	off := 0
	for i, e := range entries {
		lfhOffPos := off + 42
		binary.LittleEndian.PutUint32(patched[lfhOffPos:lfhOffPos+4], uint32(offsets[i]))
		off += int(e.HeaderSize)
	}
	return patched
}

func copyToWriter(w io.Writer, ds datasource.DataSource) (int64, error) {
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
