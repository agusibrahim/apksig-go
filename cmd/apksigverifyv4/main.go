// apksigverifyv4 verifies an APK Signature Scheme v4 signature stored in a
// .idsig file alongside an APK. Usage:
//   apksigverifyv4 -apk app.apk -idsig app.apk.idsig

//go:debug x509negativeserial=1

package main

import (
	"flag"
	"fmt"
	"os"

	v4pkg "github.com/agusibrahim/apksig-go/pkg/verifier/v4"
)

func main() {
	apkPath := flag.String("apk", "", "APK file (used to learn its size)")
	idsigPath := flag.String("idsig", "", ".idsig signature file")
	flag.Parse()
	if *apkPath == "" || *idsigPath == "" {
		fmt.Fprintln(os.Stderr, "usage: apksigverifyv4 -apk app.apk -idsig app.apk.idsig")
		os.Exit(2)
	}
	st, err := os.Stat(*apkPath)
	if err != nil {
		fail("apk: %v", err)
	}
	idsig, err := os.ReadFile(*idsigPath)
	if err != nil {
		fail("idsig: %v", err)
	}
	res, err := v4pkg.Parse(idsig, st.Size())
	if err != nil {
		fail("verify: %v", err)
	}
	fmt.Printf("v4 verified: %v\n", res.Verified)
	fmt.Printf("  hashAlg     : %d\n", res.HashAlgorithm)
	fmt.Printf("  log2BlkSize : %d\n", res.Log2BlockSize)
	fmt.Printf("  saltLen     : %d\n", len(res.Salt))
	fmt.Printf("  rootHash    : %x\n", res.RawRootHash)
	fmt.Printf("  apkDigest   : %x\n", res.APKDigest)
	fmt.Printf("  sigAlgID    : %#x\n", res.SignatureAlgorithm)
	if res.Cert != nil {
		fmt.Printf("  cert subject: %s\n", res.Cert.Subject)
		fmt.Printf("  cert issuer : %s\n", res.Cert.Issuer)
	}
	if !res.Verified {
		os.Exit(1)
	}
}

func fail(f string, a ...any) { fmt.Fprintf(os.Stderr, "apksigverifyv4: "+f+"\n", a...); os.Exit(2) }
