// Package digest verity helpers. APK verity uses 4 KiB pages, an 8-byte
// zero salt prepended to each digest input, and emits the per-algo digest
// as rootHash (32 bytes) || totalSize (8 bytes LE).
package digest

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/agusibrahim/apksig-go/pkg/datasource"
)

const verityChunk = 4096

var veritySalt = make([]byte, 8) // 8 zero bytes per apksig

// VeritySaltedRootHash computes the verity root hash over a single byte
// stream using the supplied salt (0 length means no salt). This is the form
// used in .idsig files (the salt is configurable per-file there, while inside
// the v2/v3 APK signing block apksig hard-codes an 8-byte zero salt).
func VeritySaltedRootHash(data []byte, salt []byte) []byte {
	saltedHashWith := func(b []byte) []byte {
		h := sha256.New()
		h.Write(salt)
		h.Write(b)
		return h.Sum(nil)
	}
	// Leaf level
	leaves := make([]byte, 0)
	for off := 0; off < len(data); off += verityChunk {
		end := off + verityChunk
		var page [verityChunk]byte
		if end > len(data) {
			copy(page[:], data[off:])
		} else {
			copy(page[:], data[off:end])
		}
		leaves = append(leaves, saltedHashWith(page[:])...)
	}
	if len(leaves) == 0 {
		// Empty input edge case.
		var page [verityChunk]byte
		return saltedHashWith(page[:])
	}
	level := leaves
	for {
		if len(level) <= 32 {
			break
		}
		if len(level) <= verityChunk {
			page := make([]byte, verityChunk)
			copy(page, level)
			level = saltedHashWith(page)
			break
		}
		next := make([]byte, 0)
		for off := 0; off < len(level); off += verityChunk {
			end := off + verityChunk
			page := make([]byte, verityChunk)
			if end > len(level) {
				copy(page, level[off:])
			} else {
				copy(page, level[off:end])
			}
			next = append(next, saltedHashWith(page)...)
		}
		level = next
	}
	if len(level) >= 32 {
		return level[:32]
	}
	page := make([]byte, verityChunk)
	copy(page, level)
	return saltedHashWith(page)
}

// computeVeritySHA256 returns the 40-byte verity content digest:
//   sha256-root(verityTree(salt || page)) || totalSize(uint64 LE)
func computeVeritySHA256(
	beforeBlock, cd datasource.DataSource,
	eocd []byte,
) []byte {
	total := beforeBlock.Size() + cd.Size() + int64(len(eocd))
	leaves := computeVerityLeafHashes(beforeBlock, cd, eocd)
	level := leaves
	for {
		if len(level) <= 32 {
			break
		}
		if len(level) <= verityChunk {
			page := make([]byte, verityChunk)
			copy(page, level)
			level = saltedHash(page)
			break
		}
		level = buildLevel(level)
	}
	out := make([]byte, 40)
	if len(level) >= 32 {
		copy(out, level[:32])
	} else {
		// Single short level — pad to 4 KiB and hash.
		page := make([]byte, verityChunk)
		copy(page, level)
		h := saltedHash(page)
		copy(out, h)
	}
	binary.LittleEndian.PutUint64(out[32:], uint64(total))
	return out
}

// saltedHash returns SHA-256(salt || data).
func saltedHash(data []byte) []byte {
	h := sha256.New()
	h.Write(veritySalt)
	h.Write(data)
	return h.Sum(nil)
}

// computeVerityLeafHashes returns concatenated SHA-256 hashes (32 bytes each)
// of each 4 KiB page of the file. The last page is zero-padded.
func computeVerityLeafHashes(
	beforeBlock, cd datasource.DataSource,
	eocd []byte,
) []byte {
	out := make([]byte, 0)
	var page [verityChunk]byte
	pageLen := 0

	flushPage := func() {
		// Zero-pad if partial.
		for i := pageLen; i < verityChunk; i++ {
			page[i] = 0
		}
		h := saltedHash(page[:])
		out = append(out, h...)
		pageLen = 0
	}

	feed := func(b []byte) {
		for len(b) > 0 {
			n := verityChunk - pageLen
			if n > len(b) {
				n = len(b)
			}
			copy(page[pageLen:pageLen+n], b[:n])
			pageLen += n
			b = b[n:]
			if pageLen == verityChunk {
				h := saltedHash(page[:])
				out = append(out, h...)
				pageLen = 0
			}
		}
	}

	feedDS := func(ds datasource.DataSource) {
		size := ds.Size()
		off := int64(0)
		tmp := make([]byte, verityChunk)
		for off < size {
			n := int64(verityChunk)
			if size-off < n {
				n = size - off
			}
			if _, err := ds.ReadAt(tmp[:n], off); err != nil {
				return
			}
			feed(tmp[:n])
			off += n
		}
	}

	feedDS(beforeBlock)
	feedDS(cd)
	feed(eocd)
	if pageLen > 0 {
		flushPage()
	}
	return out
}

// buildLevel groups the given level (concatenation of 32-byte hashes) into
// 4 KiB pages (zero-padded) and hashes each page to produce the next level.
func buildLevel(in []byte) []byte {
	out := make([]byte, 0)
	for off := 0; off < len(in); off += verityChunk {
		end := off + verityChunk
		if end > len(in) {
			end = len(in)
		}
		page := make([]byte, verityChunk)
		copy(page, in[off:end])
		out = append(out, saltedHash(page)...)
	}
	return out
}
