// Package axml is a minimal binary AndroidManifest.xml parser. We extract the
// minSdkVersion attribute by scanning all start-element chunks for the well-
// known android:minSdkVersion resource ID (0x0101020c). This is more robust
// than name-based lookup because attribute names may not be in the string
// pool (they're in the resource map).
package axml

import (
	"encoding/binary"
	"errors"
)

const (
	chunkStringPool   = 0x001c0001
	chunkResourceMap  = 0x00080180
	chunkXMLStartElem = 0x00100102

	resIDMinSdkVersion = 0x0101020c

	dataTypeIntDec  = 0x10
	dataTypeIntHex  = 0x11
	dataTypeIntBool = 0x12
)

// MinSdk extracts minSdkVersion. Returns 1 if no uses-sdk minSdkVersion is
// declared (which matches Android's default behaviour).
func MinSdk(data []byte) (int, error) {
	if len(data) < 8 {
		return 0, errors.New("axml: too short")
	}
	if binary.LittleEndian.Uint16(data[0:2]) != 0x0003 {
		return 0, errors.New("axml: bad magic")
	}
	totalSize := binary.LittleEndian.Uint32(data[4:8])
	if int(totalSize) > len(data) {
		totalSize = uint32(len(data))
	}
	off := 8
	var resMap []uint32
	for off < int(totalSize) {
		if off+8 > len(data) {
			break
		}
		chunkType := binary.LittleEndian.Uint32(data[off : off+4])
		chunkSize := binary.LittleEndian.Uint32(data[off+4 : off+8])
		if chunkSize < 8 || off+int(chunkSize) > int(totalSize) {
			break
		}
		chunk := data[off : off+int(chunkSize)]
		switch chunkType {
		case chunkResourceMap:
			// Body of resource map is uint32 ids, header size 8 bytes.
			body := chunk[8:]
			n := len(body) / 4
			resMap = make([]uint32, n)
			for i := 0; i < n; i++ {
				resMap[i] = binary.LittleEndian.Uint32(body[i*4 : i*4+4])
			}
		case chunkXMLStartElem:
			if min, ok := scanStartElem(chunk, resMap); ok {
				return min, nil
			}
		case chunkStringPool:
			// nothing
		}
		off += int(chunkSize)
	}
	return 1, nil
}

// scanStartElem looks for an attribute with resource id 0x0101020c
// (minSdkVersion) and returns its int data.
//
// Chunk layout:
//   off 0..3   type (u16) + headerSize (u16)
//   off 4..7   chunkSize (u32)
//   off 8..11  lineNumber (u32)
//   off 12..15 commentRef (u32)
//   off 16..19 nsRef (u32)
//   off 20..23 nameRef (u32)
//   off 24..25 attrStart (u16, normally 20)
//   off 26..27 attrSize (u16, normally 20)
//   off 28..29 attrCount (u16)
//   off 30..31 idIdx (u16)
//   off 32..33 classIdx (u16)
//   off 34..35 styleIdx (u16)
//   off 36..end attributes, each (ns u32, name u32, raw u32, typedSize u16,
//                                 res0 u8, dataType u8, data u32) = 20 bytes
func scanStartElem(chunk []byte, resMap []uint32) (int, bool) {
	if len(chunk) < 36 {
		return 0, false
	}
	headerSize := int(binary.LittleEndian.Uint16(chunk[2:4]))
	if headerSize < 16 {
		headerSize = 16
	}
	attrStart := int(binary.LittleEndian.Uint16(chunk[24:26]))
	attrSize := int(binary.LittleEndian.Uint16(chunk[26:28]))
	attrCount := int(binary.LittleEndian.Uint16(chunk[28:30]))
	if attrSize == 0 {
		attrSize = 20
	}
	// attrStart is offset from end of the chunk's header (lineNumber field).
	// Generic chunk header is 8 bytes; node header bytes (line + comment) are
	// the next 8 bytes; element-specific fields begin at offset headerSize
	// (often 16). Attributes begin at headerSize + attrStart.
	base := headerSize + attrStart
	for i := 0; i < attrCount; i++ {
		o := base + i*attrSize
		if o+20 > len(chunk) {
			return 0, false
		}
		nameRef := binary.LittleEndian.Uint32(chunk[o+4 : o+8])
		dataType := chunk[o+15]
		data := binary.LittleEndian.Uint32(chunk[o+16 : o+20])
		if int(nameRef) >= len(resMap) {
			continue
		}
		if resMap[nameRef] != resIDMinSdkVersion {
			continue
		}
		switch dataType {
		case dataTypeIntDec, dataTypeIntHex, dataTypeIntBool:
			return int(int32(data)), true
		}
	}
	return 0, false
}
