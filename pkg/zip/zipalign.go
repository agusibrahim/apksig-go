package zip

import (
	"encoding/binary"
	"io"

	"github.com/agusibrahim/apksig-go/pkg/datasource"
)

const (
	alignExtraID   = 0xd935 // Android zipalign extra field header ID
	alignExtraHdr  = 4      // 2 bytes ID + 2 bytes data size
	alignment      = 4      // 4-byte alignment for uncompressed entries
)

// AlignPlan describes how each entry's LFH should be modified for alignment.
type AlignPlan struct {
	// OriginalLFHSize is the size of the original LFH (30 + nameLen + extraLen).
	OriginalLFHSize int64
	// NewExtraLen is the new extra field length (includes alignment padding).
	NewExtraLen int64
	// DataSize is the compressed data size (copied verbatim).
	DataSize int64
	// EntryStart is the original start offset of this entry in the source.
	EntryStart int64
}

// ComputeAlignPlan builds an alignment plan for all entries.
// Returns the per-entry plans and the total byte delta (how much larger the
// aligned output will be compared to the original entry region).
func ComputeAlignPlan(ds datasource.DataSource, entries []CDEntry) ([]AlignPlan, int64, error) {
	plans := make([]AlignPlan, len(entries))
	var totalDelta int64

	for i, e := range entries {
		// Determine original entry layout
		hdr := make([]byte, 30)
		if _, err := ds.ReadAt(hdr, e.LFHOffset); err != nil {
			return nil, 0, err
		}
		nameLen := int64(binary.LittleEndian.Uint16(hdr[26:28]))
		origExtraLen := int64(binary.LittleEndian.Uint16(hdr[28:30]))
		origLFHSize := 30 + nameLen + origExtraLen

		var newExtraLen int64
		if e.CompressionMethod == 0 {
			// Stored entry: needs alignment
			// data offset = entryStart + 30 + nameLen + newExtraLen
			// We want (entryStart + 30 + nameLen + newExtraLen) % alignment == 0
			// Account for any cumulative delta from prior entries by using
			// a placeholder that will be resolved during streaming.
			// For plan computation, assume this is the first entry at its original offset.
			// The actual alignment will be computed during streaming with running offset.
			newExtraLen = alignExtraLen(e.LFHOffset, nameLen)
		} else {
			newExtraLen = origExtraLen
		}

		plans[i] = AlignPlan{
			OriginalLFHSize: origLFHSize,
			NewExtraLen:     newExtraLen,
			DataSize:        int64(e.CompressedSize),
			EntryStart:      e.LFHOffset,
		}
		totalDelta += (newExtraLen - origExtraLen)
	}

	return plans, totalDelta, nil
}

// alignExtraLen computes the extra field length needed to 4-byte align
// the data offset for an uncompressed entry.
func alignExtraLen(entryStart, nameLen int64) int64 {
	// data offset = entryStart + 30 + nameLen + extraLen
	// We want (entryStart + 30 + nameLen + extraLen) % alignment == 0
	// extraLen = (alignment - (entryStart + 30 + nameLen) % alignment) % alignment
	// But extra field must be at least alignExtraHdr (4) bytes for the header.
	pad := (alignment - (entryStart+30+nameLen+alignExtraHdr)%alignment) % alignment
	return alignExtraHdr + pad
}

// WriteAlignedEntry writes a single LFH + data for an entry with alignment.
// Returns the number of bytes written.
func WriteAlignedEntry(w io.Writer, ds datasource.DataSource, e *CDEntry, plan *AlignPlan, outOffset int64) (int64, error) {
	// Read original LFH header bytes
	origLFH := make([]byte, plan.OriginalLFHSize)
	if _, err := ds.ReadAt(origLFH, plan.EntryStart); err != nil {
		return 0, err
	}
	nameLen := int64(binary.LittleEndian.Uint16(origLFH[26:28]))

	// Compute actual alignment for the current output offset
	var newExtraLen int64
	if e.CompressionMethod == 0 {
		newExtraLen = alignExtraLen(outOffset, nameLen)
	} else {
		newExtraLen = plan.NewExtraLen
	}

	// Write LFH with patched extra field length
	binary.LittleEndian.PutUint16(origLFH[28:30], uint16(newExtraLen))
	if _, err := w.Write(origLFH[:30]); err != nil {
		return 0, err
	}
	// Write filename
	if _, err := w.Write(origLFH[30 : 30+nameLen]); err != nil {
		return 0, err
	}
	// Write alignment extra field (for stored entries) or original extra
	if e.CompressionMethod == 0 {
		paddingSize := newExtraLen - alignExtraHdr
		extra := make([]byte, newExtraLen)
		binary.LittleEndian.PutUint16(extra[0:2], alignExtraID)
		binary.LittleEndian.PutUint16(extra[2:4], uint16(paddingSize))
		// remaining bytes are zero (padding)
		if _, err := w.Write(extra); err != nil {
			return 0, err
		}
	} else {
		// Write original extra field for compressed entries
		if plan.OriginalLFHSize > 30+nameLen {
			if _, err := w.Write(origLFH[30+nameLen : plan.OriginalLFHSize]); err != nil {
				return 0, err
			}
		}
	}

	// Stream file data
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

// PatchCDOffsets returns a copy of the CD bytes with updated LFH offsets.
// offsets[i] is the new LFH offset for entries[i].
func PatchCDOffsets(cdBytes []byte, entries []CDEntry, offsets []int64) []byte {
	patched := append([]byte(nil), cdBytes...)
	off := 0
	for i, e := range entries {
		// Skip to LFH offset field at +42 within this CD entry
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
