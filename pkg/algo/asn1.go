package algo

import "encoding/asn1"

// unmarshalDSAASN1 wraps encoding/asn1 to decode the DSA signature sequence.
func unmarshalDSAASN1(b []byte, dst interface{}) ([]byte, error) {
	return asn1.Unmarshal(b, dst)
}
