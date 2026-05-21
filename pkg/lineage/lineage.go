// Package lineage decodes the SigningCertificateLineage attribute (proof of
// rotation) found in v3 signers' additional-attributes.
//
// Layout (little endian):
//
//   uint32 magic = 0x3eff39d1
//   uint32 outerVersion (currently 1)
//   uint32 payloadLen
//   payload: lineage bytes
//
// lineage bytes:
//   uint32 version (1)
//   sequence of length-prefixed nodes:
//     LP signed-data:
//        LP cert DER
//        uint32 sigAlgId-of-cert
//     uint32 flags
//     uint32 sigAlgId-used-to-sign-next
//     LP signature
package lineage

import (
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/agusibrahim/apksig-go/pkg/algo"
	"github.com/agusibrahim/apksig-go/pkg/buf"
	"github.com/agusibrahim/apksig-go/pkg/x509util"
)

const (
	Magic   uint32 = 0x3eff39d1
	Version uint32 = 1
)

// Node is one entry in the rotation chain.
type Node struct {
	Cert         *x509.Certificate
	CertSigAlg   algo.SigID // sig alg the previous cert used to sign this one's signed-data
	NextSigAlg   algo.SigID // sig alg used to sign the next node
	Flags        uint32
	Signature    []byte
}

// Lineage is the parsed proof-of-rotation chain (oldest cert first).
type Lineage struct {
	Nodes []Node
}

// Decode parses an attribute value from a v3 signer's additional-attributes.
// The bytes start with the lineage MAGIC + version header.
func Decode(b []byte) (*Lineage, error) {
	r := buf.New(b)
	magic, err := r.U32()
	if err != nil {
		return nil, fmt.Errorf("magic: %w", err)
	}
	if magic != Magic {
		return nil, fmt.Errorf("bad magic 0x%08x (want 0x%08x)", magic, Magic)
	}
	outerVersion, err := r.U32()
	if err != nil {
		return nil, err
	}
	if outerVersion != Version {
		return nil, fmt.Errorf("unsupported outer version %d", outerVersion)
	}
	payload, err := r.LengthPrefixedSlice()
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	return DecodeRaw(payload.Buf)
}

// DecodeRaw decodes the lineage payload (without the magic/version header).
// Useful when the caller already stripped the outer wrapper.
func DecodeRaw(payload []byte) (*Lineage, error) {
	r := buf.New(payload)
	innerVersion, err := r.U32()
	if err != nil {
		return nil, err
	}
	if innerVersion != Version {
		return nil, fmt.Errorf("unsupported inner version %d", innerVersion)
	}
	lin := &Lineage{}
	var lastCert *x509.Certificate
	var lastSigAlg algo.SigID
	idx := 0
	for r.Remaining() > 0 {
		idx++
		nodeSlice, err := r.LengthPrefixedSlice()
		if err != nil {
			return lin, fmt.Errorf("node[%d]: %w", idx, err)
		}
		signedData, err := nodeSlice.LengthPrefixedSlice()
		if err != nil {
			return lin, fmt.Errorf("node[%d].signedData: %w", idx, err)
		}
		flags, err := nodeSlice.U32()
		if err != nil {
			return lin, fmt.Errorf("node[%d].flags: %w", idx, err)
		}
		nextAlgID, err := nodeSlice.U32()
		if err != nil {
			return lin, fmt.Errorf("node[%d].nextAlg: %w", idx, err)
		}
		sigBytes, err := nodeSlice.LengthPrefixedBytes()
		if err != nil {
			return lin, fmt.Errorf("node[%d].sig: %w", idx, err)
		}
		// Verify signedData was signed by lastCert (if any), using lastSigAlg.
		if lastCert != nil {
			a, ok := algo.ByID(lastSigAlg)
			if !ok {
				return lin, fmt.Errorf("node[%d]: unknown previous sigAlg %#x", idx, lastSigAlg)
			}
			if err := a.Verify(lastCert.PublicKey, signedData.Buf, sigBytes); err != nil {
				return lin, fmt.Errorf("node[%d]: rotation signature invalid: %w", idx, err)
			}
		}
		// Parse signedData: cert DER + uint32 sigAlgId.
		certBytes, err := signedData.LengthPrefixedBytes()
		if err != nil {
			return lin, fmt.Errorf("node[%d].cert: %w", idx, err)
		}
		signedSigAlg, err := signedData.U32()
		if err != nil {
			return lin, fmt.Errorf("node[%d].signedSigAlg: %w", idx, err)
		}
		if lastCert != nil && algo.SigID(signedSigAlg) != lastSigAlg {
			return lin, fmt.Errorf("node[%d]: signedSigAlg mismatch", idx)
		}
		cert, err := x509util.ParseCertificate(certBytes)
		if err != nil {
			return lin, fmt.Errorf("node[%d]: parse cert: %w", idx, err)
		}
		lin.Nodes = append(lin.Nodes, Node{
			Cert:       cert,
			CertSigAlg: algo.SigID(signedSigAlg),
			NextSigAlg: algo.SigID(nextAlgID),
			Flags:      flags,
			Signature:  sigBytes,
		})
		lastCert = cert
		lastSigAlg = algo.SigID(nextAlgID)
	}
	if len(lin.Nodes) == 0 {
		return nil, errors.New("empty lineage")
	}
	return lin, nil
}

// Latest returns the most recent (current) signing certificate.
func (l *Lineage) Latest() *x509.Certificate {
	if len(l.Nodes) == 0 {
		return nil
	}
	return l.Nodes[len(l.Nodes)-1].Cert
}

// Original returns the oldest certificate that started the chain.
func (l *Lineage) Original() *x509.Certificate {
	if len(l.Nodes) == 0 {
		return nil
	}
	return l.Nodes[0].Cert
}

// FlagSet returns true if the given flag bit is set on the most recent node.
//
// Common flag bits:
//   bit 0 (0x01) PAST_CERT_INSTALLED_DATA   — old cert can install updates
//   bit 1 (0x02) PAST_CERT_SHARED_USER_ID   — old cert shares uid
//   bit 2 (0x04) PAST_CERT_PERMISSION       — old cert grants signature perms
//   bit 3 (0x08) PAST_CERT_ROLLBACK         — allows rollback
//   bit 4 (0x10) PAST_CERT_AUTH             — old cert is auth provider
func (l *Lineage) FlagSet(bit uint32) bool {
	if len(l.Nodes) == 0 {
		return false
	}
	return l.Nodes[len(l.Nodes)-1].Flags&bit != 0
}

func describeSigAlg(id algo.SigID) string {
	if a, ok := algo.ByID(id); ok {
		return fmt.Sprintf("%#x", uint32(a.ID))
	}
	return fmt.Sprintf("unknown(%#x)", uint32(id))
}

var _ = binary.LittleEndian
