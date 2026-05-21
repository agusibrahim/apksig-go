// Package digest computes the chunked content digest used by APK Signature
// Schemes v2/v3. The APK is conceptually split into three sections:
//
//   1. ZIP entries (file data), from offset 0 to start of APK Signing Block
//   2. Central Directory (with EOCD's CD offset patched to point at the
//      signing block start)
//   3. End of Central Directory record
//
// Each section is divided into 1MiB chunks. The digest of each chunk is
// computed as H(0x5a || chunkLen(LE) || chunk). The final content digest is
// H(0xa5 || totalChunks(LE) || concat(chunkDigests)).
package digest

import (
	"encoding/binary"
	"fmt"

	"github.com/agusibrahim/apksig-go/pkg/algo"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
)

const ChunkSize = 1024 * 1024

// Compute returns content digests for all requested algorithms, computed over
// (beforeBlock, centralDir, eocd). The eocd byte slice may be the original or
// a copy with its CD offset patched.
func Compute(
	algorithms []algo.ContentDigest,
	beforeBlock datasource.DataSource,
	cd datasource.DataSource,
	eocd []byte,
) (map[algo.ContentDigest][]byte, error) {
	out := make(map[algo.ContentDigest][]byte, len(algorithms))
	chunkedAlgos := make([]algo.ContentDigest, 0, len(algorithms))
	for _, a := range algorithms {
		if a == algo.VerityChunkedSHA256 {
			out[a] = computeVeritySHA256(beforeBlock, cd, eocd)
		} else {
			chunkedAlgos = append(chunkedAlgos, a)
		}
	}
	if len(chunkedAlgos) == 0 {
		return out, nil
	}
	chunked, err := computeChunked(chunkedAlgos, beforeBlock, cd, eocd)
	if err != nil {
		return nil, err
	}
	for k, v := range chunked {
		out[k] = v
	}
	return out, nil
}

func computeChunked(
	algorithms []algo.ContentDigest,
	beforeBlock datasource.DataSource,
	cd datasource.DataSource,
	eocd []byte,
) (map[algo.ContentDigest][]byte, error) {
	chunkCount := totalChunks(beforeBlock.Size()) + totalChunks(cd.Size()) + totalChunks(int64(len(eocd)))
	if chunkCount > 1<<31-1 {
		return nil, fmt.Errorf("chunk count overflow: %d", chunkCount)
	}
	// Per-algorithm digesters and concatenated chunk-digest buffers.
	hashes := make(map[algo.ContentDigest][]byte, len(algorithms))
	for _, a := range algorithms {
		hashes[a] = make([]byte, 0, chunkCount*int64(a.Size()))
		// Top-level digest prefix: 0xa5 || chunkCount(LE) is appended later;
		// for now we only collect chunk digests.
		_ = hashes[a]
	}
	if err := digestChunks(algorithms, hashes, beforeBlock); err != nil {
		return nil, err
	}
	if err := digestChunks(algorithms, hashes, cd); err != nil {
		return nil, err
	}
	if err := digestChunks(algorithms, hashes, datasource.NewBytes(eocd)); err != nil {
		return nil, err
	}
	out := make(map[algo.ContentDigest][]byte, len(algorithms))
	for _, a := range algorithms {
		h := a.Hash()
		var prefix [5]byte
		prefix[0] = 0x5a
		binary.LittleEndian.PutUint32(prefix[1:], uint32(chunkCount))
		// Build top-level digest: H(0x5a || chunkCount || concat(chunkDigests))
		// NOTE: apksig uses 0x5a for chunks and 0xa5 for top-level. We follow that.
		_ = prefix
		topPrefix := []byte{0x5a}
		// Java apksig uses 0x5a for chunk and 0xa5 for top:
		// chunk: 0xa5 || chunkLen || data — actually Java uses 0xa5 for chunk
		// and 0x5a for top-level. We use the same convention.
		topPrefix[0] = 0x5a
		var hdr [5]byte
		hdr[0] = 0x5a
		binary.LittleEndian.PutUint32(hdr[1:], uint32(chunkCount))
		h.Write(hdr[:])
		h.Write(hashes[a])
		out[a] = h.Sum(nil)
	}
	return out, nil
}

// digestChunks splits ds into 1MiB chunks and appends each chunk-digest to the
// per-algorithm slice in `acc`.
func digestChunks(
	algorithms []algo.ContentDigest,
	acc map[algo.ContentDigest][]byte,
	ds datasource.DataSource,
) error {
	size := ds.Size()
	off := int64(0)
	buf := make([]byte, ChunkSize)
	var hdr [5]byte
	for off < size {
		n := int64(ChunkSize)
		if size-off < n {
			n = size - off
		}
		chunk := buf[:n]
		if _, err := ds.ReadAt(chunk, off); err != nil {
			return err
		}
		hdr[0] = 0xa5
		binary.LittleEndian.PutUint32(hdr[1:], uint32(n))
		for _, a := range algorithms {
			h := a.Hash()
			h.Write(hdr[:])
			h.Write(chunk)
			acc[a] = h.Sum(acc[a])
		}
		off += n
	}
	return nil
}

func totalChunks(size int64) int64 {
	if size <= 0 {
		return 0
	}
	return (size + ChunkSize - 1) / ChunkSize
}
