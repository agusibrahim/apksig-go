package digest

import (
	"crypto/sha256"
	"testing"

	"github.com/agusibrahim/apksig-go/pkg/algo"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
)

func TestComputeChunkedSHA256SinglePartial(t *testing.T) {
	// Data smaller than one chunk; verify the prefix + length scheme matches
	// hand-computed values.
	data := []byte("hello world")
	cd := []byte("CD")
	eocd := []byte("EOCD")

	// Each input is a single short chunk -> 3 chunks total.
	got, err := Compute(
		[]algo.ContentDigest{algo.ChunkedSHA256},
		datasource.NewBytes(data),
		datasource.NewBytes(cd),
		eocd,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Recompute manually.
	chunkDigest := func(b []byte) [32]byte {
		buf := append([]byte{0xa5, byte(len(b)), 0, 0, 0}, b...)
		return sha256.Sum256(buf)
	}
	d1 := chunkDigest(data)
	d2 := chunkDigest(cd)
	d3 := chunkDigest(eocd)
	top := append([]byte{0x5a, 3, 0, 0, 0}, d1[:]...)
	top = append(top, d2[:]...)
	top = append(top, d3[:]...)
	want := sha256.Sum256(top)

	if string(got[algo.ChunkedSHA256]) != string(want[:]) {
		t.Fatalf("digest mismatch:\n got %x\nwant %x", got[algo.ChunkedSHA256], want[:])
	}
}
