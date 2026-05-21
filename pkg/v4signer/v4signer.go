// Package v4signer builds a .idsig file for an already-signed APK.
//
// The .idsig file does NOT modify the APK; it sits alongside it and lets the
// kernel (fs-verity) verify pages on demand at install time. Steps:
//
//  1. Locate the APK's v3 (or v2) signing block; pull out the content digest
//     for the verity-supporting algorithm of the v3 signer.
//  2. Build a verity Merkle tree over the entire APK file (4 KiB pages,
//     SHA-256, configurable salt). The root hash + salt go into HashingInfo.
//  3. Build SigningInfo: apkDigest (matches the v3 content digest), signer
//     cert + public key, signature algorithm id, signature over canonical
//     signedData built from fileSize + hashing info + signing info fields.
//  4. Concatenate version (uint32 LE = 2) + LP-prefixed hashingInfo +
//     LP-prefixed signingInfos.
package v4signer

import (
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/agusibrahim/apksig-go/pkg/algo"
	"github.com/agusibrahim/apksig-go/pkg/apksigblock"
	"github.com/agusibrahim/apksig-go/pkg/buf"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
	"github.com/agusibrahim/apksig-go/pkg/digest"
	zippkg "github.com/agusibrahim/apksig-go/pkg/zip"
)

const (
	hashAlgSHA256 uint32 = 1
	log2BlockSize byte   = 12 // 4096-byte pages
)

// Config is the v4 signing configuration. Use the same key/cert as your v3
// signer; v4 is a continuation of v3, not a separate identity.
type Config struct {
	PrivateKey crypto.PrivateKey
	Cert       *x509.Certificate
	// Algorithm to use; must be a verity-capable algorithm (sig alg id
	// 0x0421/0x0423/0x0425) or a plain SHA-256-based one whose content digest
	// the corresponding v3 block embeds.
	Algorithm algo.Algorithm
	// Optional 32-byte salt; nil/empty means no salt (matches default of
	// recent apksigner).
	Salt []byte
	// Optional override of additionalData (free-form, signed). Default empty.
	AdditionalData []byte

	// V4.1 secondary signer (key rotation / v3.1). When set, a
	// SigningInfoBlock with the given BlockID is appended after the primary
	// SigningInfo inside signingInfos. The secondary signer's apkDigest is
	// read from the v3.1 signing block.
	V41BlockID     uint32
	V41PrivateKey  crypto.PrivateKey
	V41Cert        *x509.Certificate
	V41Algorithm   algo.Algorithm
}

// Sign reads the entire APK from src and returns the .idsig file bytes.
func Sign(src datasource.DataSource, cfg *Config) ([]byte, error) {
	if cfg == nil || cfg.Cert == nil || cfg.PrivateKey == nil {
		return nil, errors.New("v4signer: missing key/cert")
	}
	if cfg.Algorithm.HashFunc == 0 {
		return nil, errors.New("v4signer: missing algorithm")
	}
	if cfg.Salt != nil && len(cfg.Salt) != 0 && len(cfg.Salt) != 8 && len(cfg.Salt) != 32 {
		return nil, fmt.Errorf("v4signer: salt length %d not supported (use 0/8/32)", len(cfg.Salt))
	}

	// 1. Locate v3 (preferred) or v2 content digest matching cfg.Algorithm.
	apkDigest, err := readContentDigest(src, cfg.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("v4signer: read APK digest: %w", err)
	}

	// 2. Build verity Merkle tree over the whole APK file. We read it into a
	// single byte slice for the tree builder.
	apkBytes, err := datasource.ReadAll(src)
	if err != nil {
		return nil, fmt.Errorf("v4signer: read APK: %w", err)
	}
	rootHash := digest.VeritySaltedRootHash(apkBytes, cfg.Salt)

	certDER := cfg.Cert.Raw
	pubKeyDER, err := x509.MarshalPKIXPublicKey(cfg.Cert.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("v4signer: marshal pubkey: %w", err)
	}

	// 3. Build canonical signedData and sign.
	salt := cfg.Salt
	if salt == nil {
		salt = []byte{}
	}
	signedData := buildSignedData(int64(len(apkBytes)), hashAlgSHA256, log2BlockSize,
		salt, rootHash, apkDigest, certDER, cfg.AdditionalData)
	sig, err := cfg.Algorithm.Sign(cfg.PrivateKey, signedData)
	if err != nil {
		return nil, fmt.Errorf("v4signer: sign: %w", err)
	}

	// 4. Encode hashingInfo + signingInfo(s)
	hashingInfo := encodeHashingInfo(hashAlgSHA256, log2BlockSize, salt, rootHash)
	signingInfo := encodeSigningInfo(apkDigest, certDER, cfg.AdditionalData, pubKeyDER, uint32(cfg.Algorithm.ID), sig)

	// Build signingInfos: primary SigningInfo raw, then optional SigningInfoBlocks.
	signingInfos := signingInfo

	if cfg.V41PrivateKey != nil && cfg.V41Cert != nil {
		v41Digest, err := readContentDigestByID(src, apksigblock.IDV31Signature, cfg.V41Algorithm)
		if err != nil {
			return nil, fmt.Errorf("v4.1: read v3.1 digest: %w", err)
		}
		v41CertDER := cfg.V41Cert.Raw
		v41PubKeyDER, err := x509.MarshalPKIXPublicKey(cfg.V41Cert.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("v4.1: marshal pubkey: %w", err)
		}
		v41SignedData := buildSignedData(int64(len(apkBytes)), hashAlgSHA256, log2BlockSize, salt, rootHash, v41Digest, v41CertDER, nil)
		v41Sig, err := cfg.V41Algorithm.Sign(cfg.V41PrivateKey, v41SignedData)
		if err != nil {
			return nil, fmt.Errorf("v4.1: sign: %w", err)
		}
		v41SigningInfo := encodeSigningInfo(v41Digest, v41CertDER, nil, v41PubKeyDER, uint32(cfg.V41Algorithm.ID), v41Sig)

		// SigningInfoBlock: blockID(u32) + LP(signingInfo)
		blockID := cfg.V41BlockID
		if blockID == 0 {
			blockID = apksigblock.IDV31Signature
		}
		var block []byte
		block = appendU32(block, blockID)
		block = appendLP(block, v41SigningInfo)
		signingInfos = append(signingInfos, block...)
	}

	out := make([]byte, 0, 4+4+len(hashingInfo)+4+len(signingInfos))
	out = appendU32(out, 2) // version (stays 2 for v4.1)
	out = appendLP(out, hashingInfo)
	out = appendLP(out, signingInfos)
	return out, nil
}

// readContentDigest returns the APK content digest carried by the v3 (or v2)
// signing block matching the requested signature algorithm.
func readContentDigest(src datasource.DataSource, a algo.Algorithm) ([]byte, error) {
	eocd, err := zippkg.FindEOCD(src)
	if err != nil {
		return nil, err
	}
	block, err := apksigblock.Find(src, eocd)
	if err != nil {
		return nil, err
	}
	tryPair := func(id uint32, isV3 bool) ([]byte, error) {
		p := block.FindPair(id)
		if p == nil {
			return nil, nil
		}
		dg, err := extractDigest(p.Value, a, isV3)
		if err != nil {
			return nil, err
		}
		return dg, nil
	}
	if dg, err := tryPair(apksigblock.IDV3Signature, true); err == nil && dg != nil {
		return dg, nil
	}
	if dg, err := tryPair(apksigblock.IDV2Signature, false); err == nil && dg != nil {
		return dg, nil
	}
	return nil, errors.New("no v3/v2 signing block content digest found for requested algorithm")
}

// readContentDigestByID reads the content digest from a specific signing block ID.
func readContentDigestByID(src datasource.DataSource, blockID uint32, a algo.Algorithm) ([]byte, error) {
	eocd, err := zippkg.FindEOCD(src)
	if err != nil {
		return nil, err
	}
	block, err := apksigblock.Find(src, eocd)
	if err != nil {
		return nil, err
	}
	p := block.FindPair(blockID)
	if p == nil {
		return nil, fmt.Errorf("no signing block pair for ID %#x", blockID)
	}
	dg, err := extractDigest(p.Value, a, true)
	if err != nil {
		return nil, err
	}
	if dg == nil {
		return nil, fmt.Errorf("no digest matching alg %#x in block %#x", uint32(a.ID), blockID)
	}
	return dg, nil
}

// extractDigest pulls the per-algorithm digest out of the first signer's
// signed-data digests block in a v2/v3 ID-value pair.
func extractDigest(blockValue []byte, a algo.Algorithm, isV3 bool) ([]byte, error) {
	r := buf.New(blockValue)
	signers, err := r.LengthPrefixedSlice()
	if err != nil {
		return nil, err
	}
	if signers.Remaining() == 0 {
		return nil, errors.New("no signers")
	}
	signer, err := signers.LengthPrefixedSlice()
	if err != nil {
		return nil, err
	}
	signedDataSlice, err := signer.LengthPrefixedSlice()
	if err != nil {
		return nil, err
	}
	sd := buf.New(signedDataSlice.Buf)
	digestsSlice, err := sd.LengthPrefixedSlice()
	if err != nil {
		return nil, err
	}
	for digestsSlice.Remaining() > 0 {
		entry, err := digestsSlice.LengthPrefixedSlice()
		if err != nil {
			return nil, err
		}
		algID, err := entry.U32()
		if err != nil {
			return nil, err
		}
		dgBytes, err := entry.LengthPrefixedBytes()
		if err != nil {
			return nil, err
		}
		if uint32(a.ID) == algID {
			return dgBytes, nil
		}
	}
	return nil, fmt.Errorf("no digest matching alg %#x", uint32(a.ID))
}

func encodeHashingInfo(hashAlg uint32, log2bs byte, salt, rootHash []byte) []byte {
	out := make([]byte, 0, 4+1+4+len(salt)+4+len(rootHash))
	out = appendU32(out, hashAlg)
	out = append(out, log2bs)
	out = appendLP(out, salt)
	out = appendLP(out, rootHash)
	return out
}

func encodeSigningInfo(apkDigest, certDER, additional, pubKey []byte, sigAlgID uint32, sig []byte) []byte {
	out := make([]byte, 0)
	out = appendLP(out, apkDigest)
	out = appendLP(out, certDER)
	out = appendLP(out, additional)
	out = appendLP(out, pubKey)
	out = appendU32(out, sigAlgID)
	out = appendLP(out, sig)
	return out
}

// buildSignedData mirrors V4Signature.getSignedData() in the Java apksig.
func buildSignedData(fileSize int64, hashAlg uint32, log2bs byte, salt, rootHash, apkDigest, certDER, additional []byte) []byte {
	size := 4 + 8 + 4 + 1 +
		4 + len(salt) +
		4 + len(rootHash) +
		4 + len(apkDigest) +
		4 + len(certDER) +
		4 + len(additional)
	out := make([]byte, 0, size)
	out = appendU32(out, uint32(size))
	out = appendU64(out, uint64(fileSize))
	out = appendU32(out, hashAlg)
	out = append(out, log2bs)
	out = appendLP(out, salt)
	out = appendLP(out, rootHash)
	out = appendLP(out, apkDigest)
	out = appendLP(out, certDER)
	out = appendLP(out, additional)
	return out
}

func appendU32(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}

func appendU64(b []byte, v uint64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], v)
	return append(b, buf[:]...)
}

func appendLP(b, v []byte) []byte {
	b = appendU32(b, uint32(len(v)))
	return append(b, v...)
}
