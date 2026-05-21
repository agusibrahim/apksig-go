# apksig-go

A pure-Go port of Android's [apksig](https://android.googlesource.com/platform/tools/apksig)
library, with a WebAssembly target so you can verify and sign APKs in the
browser without uploading anything.

[![Go Reference](https://pkg.go.dev/badge/github.com/agusibrahim/apksig-go.svg)](https://pkg.go.dev/github.com/agusibrahim/apksig-go)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/agusibrahim/apksig-go/actions/workflows/ci.yml/badge.svg)](https://github.com/agusibrahim/apksig-go/actions/workflows/ci.yml)

**Live demo (browser, runs locally via WASM):** https://agusibrahim.github.io/apksig-go/

## What it does

| Scheme | Verify | Sign |
|---|:---:|:---:|
| **v1** (JAR signing)            | ✅ | – |
| **v2** (APK Signature Scheme v2) | ✅ | ✅ |
| **v3** (APK Signature Scheme v3) | ✅ | ✅ |
| **v3.1** (key rotation, SDK ≥ 33) | ✅ | ✅ |
| **v4** (`.idsig`, fs-verity)     | ✅ | ✅ |
| **SigningCertificateLineage**    | ✅ | – |

Verified APKs signed by this library are accepted byte-for-byte by Google's
upstream `apksigner` reference tool. Verification has been cross-validated
against `apksigner` on 100+ real APKs (`tests/e2e`).

## Why

Existing options:
- **`apksigner`** — Google's reference tool, but JVM-only and not embeddable.
- **`apksig` Java lib** — same constraint.

This port has:
- **Zero external Go dependencies** — only the standard library.
- **WebAssembly support** — runs in the browser, Node.js, Cloudflare Workers,
  embedded devices.
- **CLI tools** — `apksigverify`, `apksign`, `apksigverifyv4` as drop-in
  replacements for the most common `apksigner` flows.
- **Library API** — embed in your own Go programs.

## Install

### Pre-built binaries (recommended)

Download a release tarball from the [Releases page](https://github.com/agusibrahim/apksig-go/releases)
for your OS/arch:

```sh
# Linux x86_64
curl -L https://github.com/agusibrahim/apksig-go/releases/latest/download/apksig-go_linux_amd64.tar.gz | tar xz

# macOS Apple Silicon
curl -L https://github.com/agusibrahim/apksig-go/releases/latest/download/apksig-go_darwin_arm64.tar.gz | tar xz
```

Each release also contains a pre-built WASM bundle (`apksig-go_*_wasm.tar.gz`)
ready to drop into a static site.

### From source

```sh
go install github.com/agusibrahim/apksig-go/cmd/apksigverify@latest
go install github.com/agusibrahim/apksig-go/cmd/apksign@latest
go install github.com/agusibrahim/apksig-go/cmd/apksigverifyv4@latest
```

Or as a library:

```sh
go get github.com/agusibrahim/apksig-go@latest
```

## Quick start

### Verify an APK

```sh
apksigverify -v app.apk
```

```
APK: app.apk (12426276 bytes)
Verified: true
  v3.1: present=false verified=false
  v3:   present=true  verified=true
  v2:   present=true  verified=true
  v1:   verified=true
```

### Sign an APK

```sh
# Generate a self-signed key+cert (or bring your own)
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
  -nodes -days 10950 -subj "/CN=Android Test/O=Example/C=US"

# Sign with v2 + v3 + v3.1 + v4 (.idsig)
apksign -key key.pem -cert cert.pem \
        -v3.1 -v4 \
        -in unsigned.apk -out signed.apk
```

This produces both `signed.apk` and `signed.apk.idsig`. Cross-check with
Google's `apksigner` if you have the Android SDK installed:

```sh
apksigner verify --print-certs --min-sdk-version 24 signed.apk
```

### Library usage

```go
package main

import (
    "fmt"
    "os"

    "github.com/agusibrahim/apksig-go/pkg/apkverifier"
    "github.com/agusibrahim/apksig-go/pkg/datasource"
)

func main() {
    f, _ := os.Open("app.apk")
    defer f.Close()
    st, _ := f.Stat()
    ds := datasource.NewReaderAt(f, st.Size())
    res, _ := apkverifier.Verify(ds, 24, 35)
    fmt.Printf("verified=%v v1=%v v2=%v v3=%v\n",
        res.Verified, res.V1Verified, res.V2Verified, res.V3Verified)
}
```

### Signing programmatically

```go
package main

import (
    "crypto/x509"
    "encoding/pem"
    "os"

    "github.com/agusibrahim/apksig-go/pkg/algo"
    "github.com/agusibrahim/apksig-go/pkg/apkwriter"
    "github.com/agusibrahim/apksig-go/pkg/datasource"
    "github.com/agusibrahim/apksig-go/pkg/signer"
)

func main() {
    keyPEM, _ := os.ReadFile("key.pem")
    certPEM, _ := os.ReadFile("cert.pem")

    keyBlock, _ := pem.Decode(keyPEM)
    priv, _ := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
    certBlock, _ := pem.Decode(certPEM)
    cert, _ := x509.ParseCertificate(certBlock.Bytes)

    alg, _ := algo.PickAlgorithm(priv)
    cfg := &signer.SignerConfig{
        PrivateKey: priv,
        Certs:      []*x509.Certificate{cert},
        Algorithms: []algo.Algorithm{alg},
    }

    apkBytes, _ := os.ReadFile("unsigned.apk")
    out, _ := os.Create("signed.apk")
    defer out.Close()

    w := &apkwriter.SignedAPKWriter{
        Src:       datasource.NewBytes(apkBytes),
        Signers:   []*signer.SignerConfig{cfg},
        V3MinSdk:  28,
        V3MaxSdk:  0x7fffffff,
    }
    w.Write(out)
}
```

## WebAssembly

Build:

```sh
GOOS=js GOARCH=wasm go build -o web/apksig.wasm ./wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/
```

Serve `web/` over HTTP and open `index.html`. The demo includes:

- APK verification (drag a file in, see all schemes verified locally).
- APK signing (paste a key + cert, download the signed APK).
- Key/certificate generator (RSA-2048, RSA-4096, or ECDSA P-256).
- v4 `.idsig` verification.

JavaScript API:

```js
// Verify
const result = apksigVerify(apkBytes, { minSdk: 24, maxSdk: 35 });

// Sign
const { signedApk, idsig } = apksigSign(apkBytes, keyPEM, certPEM, {
  v3: true, v31: false, v4: false,
  v3MinSdk: 28, v31MinSdk: 33,
});

// Verify v4 .idsig
const v4 = apksigVerifyV4(apkBytes, idsigBytes);

// Generate a new self-signed key + cert
const { keyPEM, certPEM } = apksigGenerateKey({
  commonName: "Android Test", org: "Example", country: "US",
  validityDays: 10950, keyType: "rsa", rsaBits: 2048,
});
```

## Architecture

```
pkg/
├── apkverifier/    # Orchestrator: tries v3.1 → v3 → v2 → v1
├── verifier/{v1,v2,v3,v4}/
├── apkwriter/      # Streams a re-signed APK
├── signer/         # Builds v2/v3/v3.1 signing block payloads
├── v4signer/       # Builds .idsig files
├── apksigblock/    # APK Signing Block parser
├── digest/         # Chunked SHA-256/512 + verity Merkle tree
├── algo/           # Signature algorithm table (RSA-PKCS1, RSA-PSS, ECDSA, DSA)
├── pkcs7/          # PKCS#7 SignedData (DER) for v1
├── jarmanifest/    # MANIFEST.MF / .SF parser
├── lineage/        # SigningCertificateLineage (proof-of-rotation)
├── x509util/       # Lenient X.509 parser (handles Huawei/legacy quirks)
├── axml/           # Binary AndroidManifest.xml parser (extract minSdkVersion)
├── zip/            # ZIP / EOCD / CD parsing
├── datasource/     # io.ReaderAt-based view abstraction (WASM-safe)
└── buf/            # Length-prefixed slice helpers

cmd/
├── apksigverify/   # CLI verifier
├── apksign/        # CLI signer (v2/v3/v3.1/v4)
├── apksigverifyv4/ # CLI for .idsig verification
├── certinfo/       # Print signer cert fingerprints
└── axmldump/       # Debug AndroidManifest.xml dump

wasm/               # syscall/js bindings (build with GOOS=js GOARCH=wasm)
web/                # HTML demo: index.html + apksig.wasm + wasm_exec.js
testdata/apk/       # Real APK fixtures for end-to-end tests
tests/e2e/          # Integration tests including apksigner cross-check
```

## Testing

```sh
go test ./...
```

The `tests/e2e/TestCrossValidate_Apksigner` test compares this port's output
against Google's reference `apksigner` if it is on `PATH` (skipped otherwise).
A cross-validation script is also provided:

```sh
./tools/cross-validate.sh /path/to/apks/
```

## Compatibility

- Go ≥ 1.21
- WASM target: any modern browser, Node.js ≥ 16
- Tested on darwin/arm64; no platform-specific code

### Quirks handled

- Certificates with **negative serial numbers** (Huawei, older vendor APKs)
  via the `//go:debug x509negativeserial=1` directive in command packages.
- Certificates with non-standard `PrintableString` characters (`@`, `/`)
  via a lenient parser in `pkg/x509util`. The original DER is preserved so
  digests still match the on-disk certificate byte-for-byte.
- `MANIFEST.MF` referencing entries missing from the ZIP — strict reject.
- minSdk-aware verification rules using `pkg/axml` to read
  `minSdkVersion` from the binary `AndroidManifest.xml`.

### Intentionally not implemented

- v1 (JAR) signing — modern Android only needs v2+. PRs welcome.
- v4.1 (dual-signer .idsig) — the kernel uses the older v4 form.
- Source stamp signing/verification.
- Re-encoding ZIP entries (the writer copies them verbatim, which preserves
  v1 integrity but does not implement `zipalign`).

## License

Apache-2.0. See [LICENSE](LICENSE).

This is a clean-room port, but the design closely follows the upstream apksig
algorithms and constants. The original Java apksig source code is also
Apache-2.0 licensed (Copyright The Android Open Source Project).
