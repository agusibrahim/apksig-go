package apksigblock

import (
	"encoding/binary"
	"testing"

	"github.com/agusibrahim/apksig-go/pkg/datasource"
	zippkg "github.com/agusibrahim/apksig-go/pkg/zip"
)

// buildAPKWithSigningBlock returns a fake APK byte slice with a synthetic
// signing block and a minimal central directory + EOCD.
//
// Layout: <entries-data> | size_u64 | pair...| size_u64 | "APK Sig Block 42" | <CD bytes...> | <EOCD>
// We don't bother with valid CD entries; the parser only needs EOCD
// (CD offset, CD size) to find the signing block.
func buildAPKWithSigningBlock(t *testing.T) []byte {
	t.Helper()
	// Pair 1: ID 0x7109871a (v2), value = "v2-data"
	pairValue := []byte("v2-data")
	pair := make([]byte, 0)
	{
		pairLen := uint64(4 + len(pairValue))
		var sz [8]byte
		binary.LittleEndian.PutUint64(sz[:], pairLen)
		pair = append(pair, sz[:]...)
		var id [4]byte
		binary.LittleEndian.PutUint32(id[:], 0x7109871a)
		pair = append(pair, id[:]...)
		pair = append(pair, pairValue...)
	}
	// Block: total = 8 (leadSize) + body + 8 (trailSize) + 16 (magic)
	body := pair
	totalSize := uint64(len(body) + 8 + 16)
	blk := make([]byte, 0)
	var sz [8]byte
	binary.LittleEndian.PutUint64(sz[:], totalSize)
	blk = append(blk, sz[:]...)
	blk = append(blk, body...)
	blk = append(blk, sz[:]...)
	blk = append(blk, []byte("APK Sig Block 42")...)

	// Fake entry data + minimal CD (empty) + EOCD.
	entries := []byte("fake-entry-data")
	cd := []byte{} // empty CD, 0 entries
	apk := append([]byte{}, entries...)
	apk = append(apk, blk...)
	apk = append(apk, cd...)

	// EOCD: 22 bytes minimum.
	eocd := make([]byte, 22)
	binary.LittleEndian.PutUint32(eocd[0:4], 0x06054b50) // signature
	binary.LittleEndian.PutUint32(eocd[16:20], uint32(len(entries)+len(blk)))
	apk = append(apk, eocd...)
	return apk
}

func TestFindSigningBlock(t *testing.T) {
	apk := buildAPKWithSigningBlock(t)
	ds := datasource.NewBytes(apk)
	eocd, err := zippkg.FindEOCD(ds)
	if err != nil {
		t.Fatalf("EOCD: %v", err)
	}
	block, err := Find(ds, eocd)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if len(block.Pairs) != 1 {
		t.Fatalf("pairs: %d", len(block.Pairs))
	}
	if block.Pairs[0].ID != 0x7109871a {
		t.Errorf("pair id: %#x", block.Pairs[0].ID)
	}
	if string(block.Pairs[0].Value) != "v2-data" {
		t.Errorf("pair value: %q", block.Pairs[0].Value)
	}
	if p := block.FindPair(0x7109871a); p == nil {
		t.Error("FindPair returned nil")
	}
	if p := block.FindPair(0xdeadbeef); p != nil {
		t.Error("FindPair returned non-nil for missing id")
	}
}

func TestFindRejectsMissingMagic(t *testing.T) {
	// Build an APK without the signing block magic.
	apk := []byte("fake-data-with-nothing-special")
	eocd := make([]byte, 22)
	binary.LittleEndian.PutUint32(eocd[0:4], 0x06054b50)
	binary.LittleEndian.PutUint32(eocd[16:20], uint32(len(apk)))
	apk = append(apk, eocd...)
	ds := datasource.NewBytes(apk)
	e, _ := zippkg.FindEOCD(ds)
	if _, err := Find(ds, e); err == nil {
		t.Error("expected error when magic absent")
	}
}
