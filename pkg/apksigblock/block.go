// Package apksigblock locates and parses the APK Signing Block, the
// container that holds v2/v3/v3.1 signature schemes and other ID-value
// pairs (e.g. source stamp, lineage). Layout per Android docs:
//
//   size of block (uint64 LE)
//   { uint64 LE pair-size, uint32 LE id, value[pair-size-4] }*
//   size of block (uint64 LE)  // duplicate
//   "APK Sig Block 42" (16 bytes magic)
//
// The block sits between the last entry's data and the central directory.
package apksigblock

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/agusibrahim/apksig-go/pkg/datasource"
	zippkg "github.com/agusibrahim/apksig-go/pkg/zip"
)

const (
	magic       = "APK Sig Block 42"
	magicLen    = 16
	footerSize  = magicLen + 8 // size_of_block (8) + magic (16) before block end
)

// Well-known IDs.
const (
	IDV2Signature       uint32 = 0x7109871a
	IDV3Signature       uint32 = 0xf05368c0
	IDV31Signature      uint32 = 0x1b93ad61
	IDV4Signature       uint32 = 0x42726577 // "wreB" (also written "Brew")
	IDSourceStampV1     uint32 = 0x2b09189e
	IDSourceStampV2     uint32 = 0x6dff800d
	IDPaddingPair       uint32 = 0x42726577
	IDDependencyInfo    uint32 = 0x504b4453
)

// Block represents the parsed APK Signing Block.
type Block struct {
	// Offset where the size_of_block prefix starts (= where the central
	// directory used to start before the block was inserted).
	StartOffset int64
	// Offset where the central directory starts (= EOCD's CD offset; equals
	// StartOffset + 8 + len(payload) + footerSize).
	CDOffset int64
	// Pairs found inside the block.
	Pairs []Pair
}

// Pair is an ID-value entry inside the block.
type Pair struct {
	ID    uint32
	Value []byte
}

// Find scans the file to locate and parse the APK Signing Block.
func Find(ds datasource.DataSource, eocd *zippkg.EOCD) (*Block, error) {
	cdOff := eocd.CDStartOffset
	if cdOff < int64(footerSize) {
		return nil, errors.New("apk signing block: central directory too close to start of file")
	}
	footer := make([]byte, footerSize)
	if _, err := ds.ReadAt(footer, cdOff-int64(footerSize)); err != nil {
		return nil, fmt.Errorf("read footer: %w", err)
	}
	if string(footer[8:]) != magic {
		return nil, errors.New("APK Signing Block magic not found")
	}
	blockSizeFooter := binary.LittleEndian.Uint64(footer[0:8])
	if blockSizeFooter < uint64(footerSize) || blockSizeFooter > uint64(cdOff)-8 {
		return nil, fmt.Errorf("APK Signing Block size invalid: %d", blockSizeFooter)
	}
	totalSize := int64(blockSizeFooter) + 8 // include the leading size field
	startOff := cdOff - totalSize
	body := make([]byte, totalSize)
	if _, err := ds.ReadAt(body, startOff); err != nil {
		return nil, fmt.Errorf("read signing block: %w", err)
	}
	if leadingSize := binary.LittleEndian.Uint64(body[0:8]); leadingSize != blockSizeFooter {
		return nil, fmt.Errorf("APK Signing Block size mismatch %d vs %d", leadingSize, blockSizeFooter)
	}
	// Parse pairs in body[8 : 8+payloadSize] where payloadSize = blockSize - footerSize.
	payload := body[8 : int64(8)+int64(blockSizeFooter)-int64(footerSize)]
	pairs, err := parsePairs(payload)
	if err != nil {
		return nil, err
	}
	return &Block{StartOffset: startOff, CDOffset: cdOff, Pairs: pairs}, nil
}

func parsePairs(payload []byte) ([]Pair, error) {
	var pairs []Pair
	off := 0
	for off < len(payload) {
		if off+8 > len(payload) {
			return nil, errors.New("signing block: truncated pair length")
		}
		pairLen := binary.LittleEndian.Uint64(payload[off : off+8])
		off += 8
		if pairLen < 4 || uint64(off)+pairLen > uint64(len(payload)) {
			return nil, fmt.Errorf("signing block: pair length out of range %d", pairLen)
		}
		id := binary.LittleEndian.Uint32(payload[off : off+4])
		valLen := int(pairLen - 4)
		val := make([]byte, valLen)
		copy(val, payload[off+4:off+4+valLen])
		pairs = append(pairs, Pair{ID: id, Value: val})
		off += int(pairLen)
	}
	return pairs, nil
}

// FindPair returns the first pair with the given ID, or nil.
func (b *Block) FindPair(id uint32) *Pair {
	for i := range b.Pairs {
		if b.Pairs[i].ID == id {
			return &b.Pairs[i]
		}
	}
	return nil
}
