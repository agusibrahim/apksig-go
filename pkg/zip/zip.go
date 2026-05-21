// Package zip parses ZIP/APK structural records (EOCD, Central Directory).
// We do byte-exact parsing because APK signing depends on absolute offsets.
package zip

import (
	"encoding/binary"
	"fmt"

	"github.com/agusibrahim/apksig-go/pkg/datasource"
)

const (
	eocdSignature      = 0x06054b50
	zip64LocSignature  = 0x07064b50
	zip64EocdSignature = 0x06064b50
	cdEntrySignature   = 0x02014b50
	lfhSignature       = 0x04034b50

	eocdMinSize = 22
	eocdMaxSize = eocdMinSize + 0xFFFF
)

// EOCD holds the End Of Central Directory record location and fields.
type EOCD struct {
	Offset       int64 // absolute file offset of EOCD start
	Bytes        []byte
	CDStartOffset int64
	CDSize       int64
	CDEntries    int
	CommentLen   int
}

// FindEOCD locates the End Of Central Directory record.
// It scans the last 64KB+22 bytes for the signature.
func FindEOCD(ds datasource.DataSource) (*EOCD, error) {
	size := ds.Size()
	if size < eocdMinSize {
		return nil, fmt.Errorf("file too small for EOCD: %d", size)
	}
	maxScan := int64(eocdMaxSize)
	if maxScan > size {
		maxScan = size
	}
	scanStart := size - maxScan
	buf := make([]byte, maxScan)
	if _, err := ds.ReadAt(buf, scanStart); err != nil {
		return nil, fmt.Errorf("read tail: %w", err)
	}
	// Scan from end backwards for EOCD signature.
	for i := int64(len(buf)) - eocdMinSize; i >= 0; i-- {
		if binary.LittleEndian.Uint32(buf[i:i+4]) == eocdSignature {
			commentLen := int(binary.LittleEndian.Uint16(buf[i+20 : i+22]))
			if int64(i)+int64(eocdMinSize)+int64(commentLen) == int64(len(buf)) {
				eocdStart := scanStart + i
				eocdBytes := make([]byte, eocdMinSize+commentLen)
				copy(eocdBytes, buf[i:i+int64(eocdMinSize)+int64(commentLen)])
				return &EOCD{
					Offset:        eocdStart,
					Bytes:         eocdBytes,
					CDStartOffset: int64(binary.LittleEndian.Uint32(eocdBytes[16:20])),
					CDSize:        int64(binary.LittleEndian.Uint32(eocdBytes[12:16])),
					CDEntries:     int(binary.LittleEndian.Uint16(eocdBytes[10:12])),
					CommentLen:    commentLen,
				}, nil
			}
		}
	}
	return nil, fmt.Errorf("EOCD signature not found")
}

// SetCDOffset patches the EOCD's central directory offset (used when verifying
// signed APKs whose signing block was inserted between data and CD; the EOCD's
// stored CD offset must point past the signing block, but during digest
// computation we treat the EOCD as if CD started at the signing block's start).
func (e *EOCD) SetCDOffset(off uint32) {
	binary.LittleEndian.PutUint32(e.Bytes[16:20], off)
}

// CDEntry is a parsed Central Directory entry.
type CDEntry struct {
	Name              string
	NameBytes         []byte
	CompressionMethod uint16
	CRC32             uint32
	CompressedSize    uint64
	UncompressedSize  uint64
	LFHOffset         int64
	ExtraLen          uint16
	CommentLen        uint16
	GeneralPurpose    uint16
	LastModTime       uint16
	LastModDate       uint16
	HeaderSize        int64 // size of this CD entry on disk
}

// ParseCD reads the central directory entries.
func ParseCD(ds datasource.DataSource, eocd *EOCD) ([]CDEntry, error) {
	cd := make([]byte, eocd.CDSize)
	if _, err := ds.ReadAt(cd, eocd.CDStartOffset); err != nil {
		return nil, fmt.Errorf("read CD: %w", err)
	}
	entries := make([]CDEntry, 0, eocd.CDEntries)
	off := 0
	for i := 0; i < eocd.CDEntries; i++ {
		if off+46 > len(cd) {
			return nil, fmt.Errorf("CD entry %d truncated", i)
		}
		if binary.LittleEndian.Uint32(cd[off:off+4]) != cdEntrySignature {
			return nil, fmt.Errorf("CD entry %d bad signature", i)
		}
		nameLen := int(binary.LittleEndian.Uint16(cd[off+28 : off+30]))
		extraLen := int(binary.LittleEndian.Uint16(cd[off+30 : off+32]))
		commentLen := int(binary.LittleEndian.Uint16(cd[off+32 : off+34]))
		entrySize := 46 + nameLen + extraLen + commentLen
		if off+entrySize > len(cd) {
			return nil, fmt.Errorf("CD entry %d field overflow", i)
		}
		nameBytes := append([]byte(nil), cd[off+46:off+46+nameLen]...)
		entry := CDEntry{
			Name:              string(nameBytes),
			NameBytes:         nameBytes,
			GeneralPurpose:    binary.LittleEndian.Uint16(cd[off+8 : off+10]),
			CompressionMethod: binary.LittleEndian.Uint16(cd[off+10 : off+12]),
			LastModTime:       binary.LittleEndian.Uint16(cd[off+12 : off+14]),
			LastModDate:       binary.LittleEndian.Uint16(cd[off+14 : off+16]),
			CRC32:             binary.LittleEndian.Uint32(cd[off+16 : off+20]),
			CompressedSize:    uint64(binary.LittleEndian.Uint32(cd[off+20 : off+24])),
			UncompressedSize:  uint64(binary.LittleEndian.Uint32(cd[off+24 : off+28])),
			LFHOffset:         int64(binary.LittleEndian.Uint32(cd[off+42 : off+46])),
			ExtraLen:          uint16(extraLen),
			CommentLen:        uint16(commentLen),
			HeaderSize:        int64(entrySize),
		}
		entries = append(entries, entry)
		off += entrySize
	}
	return entries, nil
}

// LocalFileHeaderSize returns the size of the LFH for a given CD entry by
// reading just enough bytes from the source to know the variable parts.
func LocalFileHeaderSize(ds datasource.DataSource, e *CDEntry) (int64, error) {
	hdr := make([]byte, 30)
	if _, err := ds.ReadAt(hdr, e.LFHOffset); err != nil {
		return 0, err
	}
	if binary.LittleEndian.Uint32(hdr[0:4]) != lfhSignature {
		return 0, fmt.Errorf("bad LFH signature at %d", e.LFHOffset)
	}
	nameLen := int64(binary.LittleEndian.Uint16(hdr[26:28]))
	extraLen := int64(binary.LittleEndian.Uint16(hdr[28:30]))
	return 30 + nameLen + extraLen, nil
}

// EntryDataOffset returns the absolute offset where the compressed file data
// for this entry begins.
func EntryDataOffset(ds datasource.DataSource, e *CDEntry) (int64, error) {
	hdrSize, err := LocalFileHeaderSize(ds, e)
	if err != nil {
		return 0, err
	}
	return e.LFHOffset + hdrSize, nil
}

// ReadEntry returns decompressed bytes for a CD entry.
// Supports stored (0) and deflate (8).
func ReadEntry(ds datasource.DataSource, e *CDEntry) ([]byte, error) {
	dataOff, err := EntryDataOffset(ds, e)
	if err != nil {
		return nil, err
	}
	raw := make([]byte, e.CompressedSize)
	if _, err := ds.ReadAt(raw, dataOff); err != nil {
		return nil, err
	}
	switch e.CompressionMethod {
	case 0:
		return raw, nil
	case 8:
		return inflate(raw, int(e.UncompressedSize))
	default:
		return nil, fmt.Errorf("unsupported compression %d for %s", e.CompressionMethod, e.Name)
	}
}
