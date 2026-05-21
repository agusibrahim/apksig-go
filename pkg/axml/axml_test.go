package axml

import (
	"encoding/binary"
	"testing"
)

// buildAXML synthesizes a minimal AXML manifest with a single <uses-sdk
// android:minSdkVersion=N /> element. Produces just enough structure to
// exercise the parser. Layout:
//   header (8 bytes): magic + total size
//   StringPool chunk (UTF-16): 1 string "minSdkVersion"
//   ResourceMap chunk: [0x0101020c]
//   StartElem chunk for any tag with the minSdk attribute
func buildAXML(t *testing.T, minSdk int) []byte {
	t.Helper()
	// 1. String pool with one UTF-16 string "minSdkVersion".
	str := []uint16{}
	for _, r := range "minSdkVersion" {
		str = append(str, uint16(r))
	}
	// String entry: u16 length, UTF-16 chars, u16 0 terminator.
	strBlock := make([]byte, 0)
	strBlock = append(strBlock, byte(len(str)), byte(len(str)>>8))
	for _, c := range str {
		strBlock = append(strBlock, byte(c), byte(c>>8))
	}
	strBlock = append(strBlock, 0, 0) // null terminator

	stringPool := make([]byte, 0)
	stringPool = appendU32(stringPool, 0x001c0001)               // type
	stringPool = appendU32(stringPool, 0)                         // size placeholder
	stringPool = appendU32(stringPool, 1)                         // stringCount
	stringPool = appendU32(stringPool, 0)                         // styleCount
	stringPool = appendU32(stringPool, 0)                         // flags (UTF-16)
	stringPool = appendU32(stringPool, uint32(28+4))              // stringsStart (header(28) + offsets(4*1))
	stringPool = appendU32(stringPool, 0)                         // stylesStart
	stringPool = appendU32(stringPool, 0)                         // string offset[0]
	stringPool = append(stringPool, strBlock...)
	// Pad to 4 bytes
	for len(stringPool)%4 != 0 {
		stringPool = append(stringPool, 0)
	}
	binary.LittleEndian.PutUint32(stringPool[4:8], uint32(len(stringPool)))

	// 2. ResourceMap chunk: just one resource id mapping to string 0.
	resMap := make([]byte, 0)
	resMap = appendU32(resMap, 0x00080180)
	resMap = appendU32(resMap, 12) // size = 8 hdr + 4 entry
	resMap = appendU32(resMap, 0x0101020c)

	// 3. StartElem chunk with one attribute pointing to string 0 (= "minSdkVersion").
	se := make([]byte, 0)
	se = appendU32(se, 0x00100102) // type + headerSize=16
	// headerSize is upper 16 bits of word 0; reset:
	binary.LittleEndian.PutUint16(se[2:4], 16)
	se = appendU32(se, 0)         // size placeholder
	se = appendU32(se, 1)         // lineNumber
	se = appendU32(se, 0xffffffff) // commentRef
	// Body
	se = appendU32(se, 0xffffffff) // ns ref
	se = appendU32(se, 0)          // name ref (uses-sdk would be a separate string; we don't care)
	se = append(se, 20, 0)         // attrStart u16 = 20
	se = append(se, 20, 0)         // attrSize u16 = 20
	se = append(se, 1, 0)          // attrCount u16 = 1
	se = append(se, 0, 0, 0, 0, 0, 0) // idIdx, classIdx, styleIdx
	// Attribute (20 bytes)
	se = appendU32(se, 0xffffffff) // ns
	se = appendU32(se, 0)          // name = string 0
	se = appendU32(se, 0xffffffff) // raw value
	se = append(se, 8, 0, 0, 0x10) // typedSize=8, res0=0, dataType=0x10 (int dec)
	se = appendU32(se, uint32(minSdk))
	binary.LittleEndian.PutUint32(se[4:8], uint32(len(se)))

	// Header
	out := make([]byte, 0)
	out = append(out, 0x03, 0x00, 0x08, 0x00) // magic + headerSize=8
	totalSize := 8 + len(stringPool) + len(resMap) + len(se)
	out = appendU32(out, uint32(totalSize))
	out = append(out, stringPool...)
	out = append(out, resMap...)
	out = append(out, se...)
	return out
}

func appendU32(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}

func TestMinSdk(t *testing.T) {
	for _, want := range []int{1, 19, 24, 28, 33, 35} {
		data := buildAXML(t, want)
		got, err := MinSdk(data)
		if err != nil {
			t.Errorf("MinSdk(%d): err=%v", want, err)
			continue
		}
		if got != want {
			t.Errorf("MinSdk: got %d, want %d", got, want)
		}
	}
}

func TestMinSdkBadMagic(t *testing.T) {
	if _, err := MinSdk([]byte{0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Error("expected error on bad magic")
	}
}

func TestMinSdkTooShort(t *testing.T) {
	if _, err := MinSdk([]byte{0x03}); err == nil {
		t.Error("expected error on truncated input")
	}
}

func TestMinSdkNoUsesSdk(t *testing.T) {
	// Build an AXML with no uses-sdk: should default to 1.
	axml := []byte{0x03, 0x00, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00}
	got, err := MinSdk(axml)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Errorf("default minSdk: got %d, want 1", got)
	}
}
