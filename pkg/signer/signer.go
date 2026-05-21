// Package signer builds the v2/v3 APK Signing Block payload for one or more
// signers. It does NOT touch the APK file directly; the caller (apkwriter)
// composes the final on-disk layout.
package signer

import (
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/agusibrahim/apksig-go/pkg/algo"
)

// SignerConfig describes one signer's keys and chosen algorithms.
type SignerConfig struct {
	PrivateKey crypto.PrivateKey
	Certs      []*x509.Certificate
	Algorithms []algo.Algorithm // signature algorithms to use; first cert is the signing cert
}

// SignerPayloadV2 returns the per-signer payload (no outer LP wrapping the
// list of signers). Caller is expected to length-prefix this and concatenate
// multiple signers' payloads.
func SignerPayloadV2(cfg *SignerConfig, contentDigests map[algo.ContentDigest][]byte) ([]byte, error) {
	signedData, err := buildSignedData(cfg, contentDigests, false, 0, 0)
	if err != nil {
		return nil, err
	}
	return buildSigner(cfg, signedData, false, 0, 0)
}

// SignerPayloadV3 mirrors SignerPayloadV2 with v3 fields.
func SignerPayloadV3(cfg *SignerConfig, contentDigests map[algo.ContentDigest][]byte, minSdk, maxSdk int32) ([]byte, error) {
	signedData, err := buildSignedData(cfg, contentDigests, true, minSdk, maxSdk)
	if err != nil {
		return nil, err
	}
	return buildSigner(cfg, signedData, true, minSdk, maxSdk)
}

// V2Block builds the value of the APK Signing Scheme v2 ID-value pair.
// Layout (LE u32 length-prefixed):
//
//   signers (LP)
//     signer (LP)
//       signed-data (LP) =
//         digests (LP) [ for each algo: (algId u32, digest LP) ]
//         certificates (LP) [ for each cert: cert LP ]
//         additional-attrs (LP)  -- empty for now
//       signatures (LP) [ for each algo: (algId u32, signature LP) ]
//       public_key (LP) -- DER-encoded SubjectPublicKeyInfo
func V2Block(cfg *SignerConfig, contentDigests map[algo.ContentDigest][]byte) ([]byte, error) {
	signedData, err := buildSignedData(cfg, contentDigests, false, 0, 0)
	if err != nil {
		return nil, err
	}
	signer, err := buildSigner(cfg, signedData, false, 0, 0)
	if err != nil {
		return nil, err
	}
	// outer signers wrapper
	out := lpUint32(signer)
	return out, nil
}

// V3Block builds the v3 ID-value pair.
// Differs from v2 by adding minSdk/maxSdk in both the signer header and inside
// signed-data.
func V3Block(cfg *SignerConfig, contentDigests map[algo.ContentDigest][]byte, minSdk, maxSdk int32) ([]byte, error) {
	signedData, err := buildSignedData(cfg, contentDigests, true, minSdk, maxSdk)
	if err != nil {
		return nil, err
	}
	signer, err := buildSigner(cfg, signedData, true, minSdk, maxSdk)
	if err != nil {
		return nil, err
	}
	return lpUint32(signer), nil
}

func buildSignedData(cfg *SignerConfig, digests map[algo.ContentDigest][]byte, isV3 bool, minSdk, maxSdk int32) ([]byte, error) {
	// digests block
	var d []byte
	for _, alg := range cfg.Algorithms {
		dg, ok := digests[alg.ContentDigest]
		if !ok {
			return nil, fmt.Errorf("missing digest for algorithm %v", alg.ID)
		}
		entry := append(uint32LE(uint32(alg.ID)), lpUint32(dg)...)
		d = append(d, lpUint32(entry)...)
	}
	digestsBlock := lpUint32(d)

	// certificates block
	var c []byte
	for _, cert := range cfg.Certs {
		c = append(c, lpUint32(cert.Raw)...)
	}
	certsBlock := lpUint32(c)

	// additional attributes (empty for v2; for v3 we still leave empty)
	attrsBlock := lpUint32(nil)

	out := append([]byte{}, digestsBlock...)
	out = append(out, certsBlock...)
	if isV3 {
		out = append(out, uint32LE(uint32(minSdk))...)
		out = append(out, uint32LE(uint32(maxSdk))...)
	}
	out = append(out, attrsBlock...)
	return out, nil
}

func buildSigner(cfg *SignerConfig, signedData []byte, isV3 bool, minSdk, maxSdk int32) ([]byte, error) {
	if len(cfg.Certs) == 0 {
		return nil, errors.New("no certs")
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(cfg.Certs[0].PublicKey)
	if err != nil {
		return nil, err
	}

	// signatures block: sign signedData with each algorithm.
	var s []byte
	for _, alg := range cfg.Algorithms {
		sig, err := alg.Sign(cfg.PrivateKey, signedData)
		if err != nil {
			return nil, fmt.Errorf("sign %v: %w", alg.ID, err)
		}
		entry := append(uint32LE(uint32(alg.ID)), lpUint32(sig)...)
		s = append(s, lpUint32(entry)...)
	}
	signaturesBlock := lpUint32(s)

	out := append([]byte{}, lpUint32(signedData)...)
	if isV3 {
		out = append(out, uint32LE(uint32(minSdk))...)
		out = append(out, uint32LE(uint32(maxSdk))...)
	}
	out = append(out, signaturesBlock...)
	out = append(out, lpUint32(pubKeyBytes)...)
	return out, nil
}

// AssembleSigningBlock takes one or more (id, value) pairs and returns the
// full APK Signing Block bytes ready to splice into a ZIP file. Output:
//
//   total_size (uint64 LE)
//   { uint64 LE pair_size, uint32 LE id, value }*
//   total_size (uint64 LE) -- duplicate
//   "APK Sig Block 42" (16 bytes)
//
// The result is padded so that the entire block (including its 8-byte leading
// size prefix) is a multiple of 4096 bytes. Padding is delivered as a final
// padding pair (block id 0x42726577) whose value is zero-filled.
func AssembleSigningBlock(pairs []Pair) []byte {
	const magicLen = 16
	// Each pair contributes 8 (size_u64) + 4 (id_u32) + len(value).
	bodyLen := 0
	for _, p := range pairs {
		bodyLen += 8 + 4 + len(p.Value)
	}
	// Total assembled size (with leading size prefix and trailing footer):
	totalWithLead := func(blen int) int { return 8 + blen + 8 + magicLen }

	// Find smallest pad bytes (added inside a padding pair) such that
	// totalWithLead(bodyLen + 12 + pad) is a multiple of 4096.
	const padHeader = 12 // 8 (size) + 4 (id)
	pad := 0
	for {
		total := totalWithLead(bodyLen + padHeader + pad)
		if total%4096 == 0 {
			break
		}
		pad++
		if pad > 4096 {
			break // safety
		}
	}

	body := make([]byte, 0, bodyLen+padHeader+pad)
	for _, p := range pairs {
		var sz [8]byte
		binary.LittleEndian.PutUint64(sz[:], uint64(4+len(p.Value)))
		body = append(body, sz[:]...)
		body = append(body, uint32LE(p.ID)...)
		body = append(body, p.Value...)
	}
	// Append padding pair.
	{
		padVal := make([]byte, pad)
		var sz [8]byte
		binary.LittleEndian.PutUint64(sz[:], uint64(4+len(padVal)))
		body = append(body, sz[:]...)
		body = append(body, uint32LE(0x42726577)...)
		body = append(body, padVal...)
	}

	totalSize := uint64(len(body) + 8 + magicLen) // body + trailing size + magic
	out := make([]byte, 0, 8+len(body)+8+magicLen)
	var sz [8]byte
	binary.LittleEndian.PutUint64(sz[:], totalSize)
	out = append(out, sz[:]...)
	out = append(out, body...)
	out = append(out, sz[:]...)
	out = append(out, []byte("APK Sig Block 42")...)
	return out
}

// Pair is a (ID, value) entry inside the APK Signing Block.
type Pair struct {
	ID    uint32
	Value []byte
}

func uint32LE(v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b[:]
}

func lpUint32(b []byte) []byte {
	out := make([]byte, 4+len(b))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(b)))
	copy(out[4:], b)
	return out
}
