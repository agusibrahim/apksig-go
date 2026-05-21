//go:build js && wasm

package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"syscall/js"
	"time"

	"github.com/agusibrahim/apksig-go/pkg/algo"
	"github.com/agusibrahim/apksig-go/pkg/apkwriter"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
	"github.com/agusibrahim/apksig-go/pkg/signer"
	"github.com/agusibrahim/apksig-go/pkg/v4signer"
	v4pkg "github.com/agusibrahim/apksig-go/pkg/verifier/v4"
)

// sign(apkBytes, keyPEM, certPEM, opts) → { signedApk: Uint8Array, idsig: Uint8Array? }
func sign(this js.Value, args []js.Value) interface{} {
	if len(args) < 3 {
		return makeError("apksigSign requires (apkBytes, keyPEM, certPEM, opts?)")
	}
	apkBytes := jsToBytes(args[0])
	keyPEMBytes := jsToBytes(args[1])
	certPEMBytes := jsToBytes(args[2])

	opts := map[string]interface{}{}
	if len(args) >= 4 && args[3].Type() == js.TypeObject {
		opts = jsObjectToMap(args[3])
	}
	v3Enabled := getBool(opts, "v3", true)
	v31Enabled := getBool(opts, "v31", false)
	v4Enabled := getBool(opts, "v4", false)
	v3Min := getInt(opts, "v3MinSdk", 28)
	v3Max := getInt(opts, "v3MaxSdk", 0x7fffffff)
	v31Min := getInt(opts, "v31MinSdk", 33)
	v31Max := getInt(opts, "v31MaxSdk", 0x7fffffff)

	priv, err := parsePEMPrivateKey(keyPEMBytes)
	if err != nil {
		return makeError("parse key: " + err.Error())
	}
	cert, err := parsePEMCertificate(certPEMBytes)
	if err != nil {
		return makeError("parse cert: " + err.Error())
	}
	alg, err := algo.PickAlgorithm(priv)
	if err != nil {
		return makeError("pick algorithm: " + err.Error())
	}

	cfg := &signer.SignerConfig{
		PrivateKey: priv,
		Certs:      []*x509.Certificate{cert},
		Algorithms: []algo.Algorithm{alg},
	}
	src := datasource.NewBytes(apkBytes)
	w := &apkwriter.SignedAPKWriter{
		Src:     src,
		Signers: []*signer.SignerConfig{cfg},
	}
	if v3Enabled {
		w.V3MinSdk = int32(v3Min)
		w.V3MaxSdk = int32(v3Max)
	}
	if v31Enabled {
		w.V31MinSdk = int32(v31Min)
		w.V31MaxSdk = int32(v31Max)
	}

	buf := &byteBuffer{}
	if err := w.Write(buf); err != nil {
		return makeError("sign: " + err.Error())
	}

	out := map[string]interface{}{
		"signedApk": bytesToUint8Array(buf.b),
	}

	if v4Enabled {
		signedSrc := datasource.NewBytes(buf.b)
		v4cfg := &v4signer.Config{
			PrivateKey: priv,
			Cert:       cert,
			Algorithm:  alg,
		}
		if v31Enabled {
			v4cfg.V41PrivateKey = priv
			v4cfg.V41Cert = cert
			v4cfg.V41Algorithm = alg
		}
		idsig, err := v4signer.Sign(signedSrc, v4cfg)
		if err != nil {
			out["v4Error"] = err.Error()
		} else {
			out["idsig"] = bytesToUint8Array(idsig)
		}
	}
	return out
}

// verifyV4(apkBytes, idsigBytes) → result
func verifyV4(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return makeError("apksigVerifyV4 requires (apkBytes, idsigBytes)")
	}
	apkBytes := jsToBytes(args[0])
	idsig := jsToBytes(args[1])
	res, err := v4pkg.Parse(idsig, int64(len(apkBytes)))
	if err != nil {
		return makeError(err.Error())
	}
	out := map[string]interface{}{
		"verified":      res.Verified,
		"hashAlgorithm": res.HashAlgorithm,
		"log2BlockSize": int(res.Log2BlockSize),
		"saltLen":       len(res.Salt),
		"rootHash":      hexEncode(res.RawRootHash),
		"apkDigest":     hexEncode(res.APKDigest),
		"sigAlgorithm":  fmt.Sprintf("%#x", uint32(res.SignatureAlgorithm)),
	}
	if res.Cert != nil {
		out["cert"] = map[string]interface{}{
			"subject": res.Cert.Subject.String(),
			"issuer":  res.Cert.Issuer.String(),
			"sha256":  sha256Hex(res.Cert.Raw),
		}
	}
	if len(res.ExtraBlocks) > 0 {
		var blocks []interface{}
		for _, eb := range res.ExtraBlocks {
			block := map[string]interface{}{
				"blockId":  int(eb.BlockID),
				"verified": eb.Verified,
			}
			if eb.Cert != nil {
				block["cert"] = map[string]interface{}{
					"subject": eb.Cert.Subject.String(),
					"sha256":  sha256Hex(eb.Cert.Raw),
				}
			}
			if eb.Error != "" {
				block["error"] = eb.Error
			}
			blocks = append(blocks, block)
		}
		out["extraBlocks"] = blocks
	}
	return out
}

// generateKey(opts) → { keyPEM, certPEM }
// opts: { commonName: string, org: string, country: string, validityDays: int,
//         keyType: "rsa" | "ecdsa", rsaBits: int }
func generateKey(this js.Value, args []js.Value) interface{} {
	opts := map[string]interface{}{}
	if len(args) >= 1 && args[0].Type() == js.TypeObject {
		opts = jsObjectToMap(args[0])
	}
	cn := getString(opts, "commonName", "Test")
	org := getString(opts, "org", "apksig-go")
	country := getString(opts, "country", "US")
	validityDays := getInt(opts, "validityDays", 365*30) // 30 years (Android default)
	keyType := getString(opts, "keyType", "rsa")
	rsaBits := getInt(opts, "rsaBits", 2048)

	var priv crypto.PrivateKey
	var pub crypto.PublicKey
	var err error
	switch keyType {
	case "ecdsa":
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return makeError("generate ecdsa: " + e.Error())
		}
		priv = k
		pub = &k.PublicKey
	default:
		k, e := rsa.GenerateKey(rand.Reader, rsaBits)
		if e != nil {
			return makeError("generate rsa: " + e.Error())
		}
		priv = k
		pub = &k.PublicKey
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{org},
			Country:      []string{country},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Duration(validityDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return makeError("create cert: " + err.Error())
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return makeError("marshal key: " + err.Error())
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return map[string]interface{}{
		"keyPEM":  string(keyPEM),
		"certPEM": string(certPEM),
	}
}

// byteBuffer implements io.Writer over an in-memory byte slice.
type byteBuffer struct{ b []byte }

func (w *byteBuffer) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

func parsePEMPrivateKey(data []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("not a PEM file")
	}
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	}
	return nil, fmt.Errorf("unsupported PEM type %q", block.Type)
}

func parsePEMCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("not a PEM file")
	}
	return x509.ParseCertificate(block.Bytes)
}

// JS interop helpers.
func jsToBytes(v js.Value) []byte {
	n := v.Get("length").Int()
	out := make([]byte, n)
	js.CopyBytesToGo(out, v)
	return out
}

func bytesToUint8Array(b []byte) js.Value {
	arr := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(arr, b)
	return arr
}

func jsObjectToMap(o js.Value) map[string]interface{} {
	out := map[string]interface{}{}
	keys := js.Global().Get("Object").Call("keys", o)
	for i := 0; i < keys.Length(); i++ {
		k := keys.Index(i).String()
		v := o.Get(k)
		switch v.Type() {
		case js.TypeBoolean:
			out[k] = v.Bool()
		case js.TypeNumber:
			out[k] = v.Float()
		case js.TypeString:
			out[k] = v.String()
		}
	}
	return out
}

func getString(m map[string]interface{}, k, def string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return def
}

func getBool(m map[string]interface{}, k string, def bool) bool {
	if v, ok := m[k]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return def
}

func getInt(m map[string]interface{}, k string, def int) int {
	if v, ok := m[k]; ok {
		if f, ok := v.(float64); ok {
			return int(f)
		}
	}
	return def
}

func hexEncode(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hex[c>>4]
		out[i*2+1] = hex[c&0xf]
	}
	return string(out)
}
