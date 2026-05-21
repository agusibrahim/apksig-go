//go:debug x509negativeserial=1

package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"flag"
	"fmt"
	"os"

	"github.com/agusibrahim/apksig-go/pkg/apkverifier"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
)

func main() {
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: certinfo <apk>")
		os.Exit(2)
	}
	f, err := os.Open(flag.Arg(0))
	if err != nil {
		panic(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	ds := datasource.NewReaderAt(f, st.Size())
	res, err := apkverifier.Verify(ds, 24, 35)
	if err != nil {
		panic(err)
	}
	for i, der := range res.SignerCerts {
		s256 := sha256.Sum256(der)
		s1 := sha1.Sum(der)
		fmt.Printf("Signer #%d cert SHA-256: %x\n", i+1, s256)
		fmt.Printf("Signer #%d cert SHA-1:   %x\n", i+1, s1)
	}
}
