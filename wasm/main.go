//go:build js && wasm

//go:debug x509negativeserial=1

// Package main exposes apksig verification to JavaScript via syscall/js.
//
// Usage from JS:
//   const go = new Go();
//   await WebAssembly.instantiateStreaming(fetch("apksig.wasm"), go.importObject)
//     .then(r => go.run(r.instance));
//   const result = apksigVerify(uint8Array);  // returns plain object
package main

import (
	"encoding/hex"
	"syscall/js"

	"github.com/agusibrahim/apksig-go/pkg/apkverifier"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
)

func main() {
	js.Global().Set("apksigVerify", js.FuncOf(verify))
	js.Global().Set("apksigSign", js.FuncOf(sign))
	js.Global().Set("apksigVerifyV4", js.FuncOf(verifyV4))
	js.Global().Set("apksigGenerateKey", js.FuncOf(generateKey))
	js.Global().Set("apksigVersion", "2025.05.21b")
	// Keep the Go runtime alive so the exported function stays callable.
	select {}
}

// verify(apkBytes Uint8Array, [opts {minSdk, maxSdk}]) → result object.
func verify(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return makeError("apksigVerify requires (Uint8Array)")
	}
	jsBytes := args[0]
	if jsBytes.Type() != js.TypeObject {
		return makeError("first argument must be Uint8Array")
	}
	n := jsBytes.Get("length").Int()
	buf := make([]byte, n)
	js.CopyBytesToGo(buf, jsBytes)

	minSdk, maxSdk := 24, 35
	if len(args) >= 2 && args[1].Type() == js.TypeObject {
		opts := args[1]
		if v := opts.Get("minSdk"); v.Type() == js.TypeNumber {
			minSdk = v.Int()
		}
		if v := opts.Get("maxSdk"); v.Type() == js.TypeNumber {
			maxSdk = v.Int()
		}
	}

	ds := datasource.NewBytes(buf)
	res, err := apkverifier.Verify(ds, minSdk, maxSdk)
	if err != nil {
		return makeError(err.Error())
	}
	return makeResult(res)
}

func makeError(msg string) map[string]interface{} {
	return map[string]interface{}{
		"verified": false,
		"error":    msg,
	}
}

func makeResult(r *apkverifier.Result) map[string]interface{} {
	out := map[string]interface{}{
		"verified":    r.Verified,
		"v1Verified":  r.V1Verified,
		"v2Verified":  r.V2Verified,
		"v3Verified":  r.V3Verified,
		"v31Verified": r.V31Verified,
		"hasV2Block":  r.HasV2Block,
		"hasV3Block":  r.HasV3Block,
		"hasV31Block": r.HasV31Block,
		"aligned4KB":  r.Aligned4KB,
		"errors":      stringsToAny(r.Errors),
		"warnings":    stringsToAny(r.Warnings),
	}
	if len(r.MisalignedFiles) > 0 {
		out["misalignedFiles"] = stringsToAny(r.MisalignedFiles)
	}
	var signers []interface{}
	if r.V3 != nil {
		for _, s := range r.V3.Signers {
			signers = append(signers, map[string]interface{}{
				"scheme":   "v3",
				"verified": s.Verified,
				"errors":   stringsToAny(s.Errors),
				"certs":    certsToAny(s.Certs),
				"minSdk":   int(s.MinSDK),
				"maxSdk":   int(s.MaxSDK),
			})
		}
	}
	if r.V2 != nil {
		for _, s := range r.V2.Signers {
			signers = append(signers, map[string]interface{}{
				"scheme":   "v2",
				"verified": s.Verified,
				"errors":   stringsToAny(s.Errors),
				"certs":    certsToAny(s.Certs),
			})
		}
	}
	if r.V1 != nil {
		for _, s := range r.V1.Signers {
			cert := map[string]interface{}{}
			if s.Cert != nil {
				cert = map[string]interface{}{
					"subject": s.Cert.Subject.String(),
					"issuer":  s.Cert.Issuer.String(),
					"sha256":  hex.EncodeToString(s.Cert.Raw),
				}
				cert["sha256"] = sha256Hex(s.Cert.Raw)
			}
			signers = append(signers, map[string]interface{}{
				"scheme":   "v1",
				"verified": s.Verified,
				"errors":   stringsToAny(s.Errors),
				"sfFile":   s.SFFile,
				"sigFile":  s.SigFile,
				"cert":     cert,
			})
		}
	}
	out["signers"] = signers
	return out
}

func stringsToAny(in []string) []interface{} {
	out := make([]interface{}, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}
