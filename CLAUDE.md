# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common commands

```sh
# Build all CLIs
go build ./cmd/...

# Run all tests (races enabled in CI)
go test ./...
go test -race -count=1 ./...

# Single package or test
go test ./pkg/apkverifier/
go test -run TestEndToEnd_V31AndV4 ./tests/e2e/...

# Build the WASM target
GOOS=js GOARCH=wasm go build -o web/apksig.wasm ./wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/

# Cross-validate against Google's apksigner reference (Android SDK required)
./tools/cross-validate.sh /path/to/apks/

# Headless WASM smoke test under Node
node web/node-test.js testdata/apk/F-Droid.apk
```

`tests/e2e/TestCrossValidate_Apksigner` is auto-skipped if `apksigner` is not on `$PATH` — install Android build-tools to engage it.

## Architecture: how a verify or sign actually flows

This is a port of Android's apksig (Java) so the on-wire formats are fixed; the design choices are about plumbing, not protocol.

**Verification entry point:** `pkg/apkverifier/Verify(ds, minSdk, maxSdk)`. It always reads through a `datasource.DataSource` (an `io.ReaderAt` view, deliberately not `os.File`-bound, so the same code path works under WASM with `datasource.NewBytes`). Order of operations:

1. `pkg/zip` finds the EOCD by scanning the last 64 KB+22 for the signature, then parses the central directory.
2. `pkg/apksigblock` finds the APK Signing Block by reading the magic `"APK Sig Block 42"` immediately before the CD, splits it into ID-value pairs.
3. The orchestrator runs each `verifier/{v2,v3,v4}` against its pair value. Each verifier returns the *content digests it claims*; the orchestrator then re-computes those digests over the actual APK bytes and compares.
4. Content digest computation lives in `pkg/digest`. Two flavours: chunked (1 MiB pages with prefixes 0xa5 chunk / 0x5a top — see Java apksig's `ApkSigningBlockUtils.java:294-300` for the byte layout) and verity (4 KiB pages, salted SHA-256 Merkle tree, output is `rootHash || size_u64`).
5. v1 (JAR) verification happens last and is independent of the signing block: `pkg/verifier/v1` reads `META-INF/MANIFEST.MF` + `*.SF` + `*.{RSA,DSA,EC}` from the ZIP, hands the PKCS#7 blob to `pkg/pkcs7`, and walks per-entry digests.
6. minSdk-aware rule: if `pkg/axml` extracts `minSdkVersion < 24` from `AndroidManifest.xml` and v1 is not valid, the whole APK fails (Android < 7 cannot read v2+).

**Signing entry point:** `pkg/apkwriter.SignedAPKWriter.Write(io.Writer)`. The writer never re-encodes ZIP entries — it copies the original bytes verbatim from offset 0 to the start of the (existing or new) signing block, splices in a freshly assembled signing block, copies the original CD, then writes a new EOCD with the CD offset patched past the signing block. This byte-level preservation is why a re-signed APK keeps any pre-existing v1 signature working.

`pkg/signer` builds the v2/v3/v3.1 ID-value payloads. Each per-signer payload is wrapped in *two* length prefixes (one for the signer entry, one for the outer signers list) — getting that double-LP wrong was the most common bug during initial implementation; the test fixtures in `pkg/verifier/v2/v2_test.go` and `pkg/verifier/v3/v3_test.go` document the layout end-to-end. `signer.AssembleSigningBlock` adds a padding pair (id `0x42726577`) to align the total block to 4096 bytes — this alignment is required by Android.

`pkg/v4signer` writes a `.idsig` file (separate from the APK). It pulls the APK content digest out of the v3/v2 block and feeds it into a fixed canonical `signedData` shape (`buildSignedData` mirrors `V4Signature.getSignedData()` in upstream apksig). v4 does not modify the APK.

## Three quirks worth knowing before debugging cert issues

1. **Negative serial numbers**: Go 1.23+ rejects them by default. Every `cmd/*/main.go` carries `//go:debug x509negativeserial=1`. If you add a new entry point, replicate that directive.

2. **Lenient cert parsing** (`pkg/x509util`): some real-world certs (Huawei, etc.) put `@` or `/` in `PrintableString` fields, which Go strictly rejects. The helper retries by rewriting the offending tag from `0x13` (PrintableString) to `0x0c` (UTF8String) in a *copy* of the DER, then restores `Cert.Raw` to the original bytes so digests still match the on-disk APK. Never call `x509.ParseCertificate` directly inside an APK code path — use `x509util.ParseCertificate`.

3. **Verity content digest is 40 bytes, not 32**: it's `rootHash(32) || totalSize(8 LE)`. The salt is 8 zero bytes inside the v2/v3 signing block, but configurable for `.idsig` — `pkg/digest/verity.go` has `computeVeritySHA256` (signing-block path) and `VeritySaltedRootHash` (idsig path) and they are intentionally separate functions.

## WASM target

`wasm/main.go` and `wasm/sign.go` are guarded by `//go:build js && wasm` and register four globals: `apksigVerify`, `apksigSign`, `apksigVerifyV4`, `apksigGenerateKey`. They use `pkg/datasource.NewBytes` because there is no filesystem; everything goes through `[]byte`. When adding new exports, update `web/index.html` and the API section in `README.md`.

## CI/CD

Three workflows under `.github/workflows/`: `ci.yml` (matrix test 1.21–1.24), `pages.yml` (auto-deploy `web/` to GitHub Pages on push to main), `release.yml` (build 5 CLIs × 6 platforms + WASM bundle on `v*` tags). The Pages workflow rebuilds `apksig.wasm` from source — committed `web/apksig.wasm` is a convenience for local testing only and may be stale.
