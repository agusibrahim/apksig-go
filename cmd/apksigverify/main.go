// apksigverify is a CLI to verify APK signatures using the apksig Go port.

//go:debug x509negativeserial=1

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/agusibrahim/apksig-go/pkg/apkverifier"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
)

func main() {
	minSdk := flag.Int("min-sdk", 24, "minimum SDK version")
	maxSdk := flag.Int("max-sdk", 35, "maximum SDK version")
	verbose := flag.Bool("v", false, "verbose")
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: apksigverify [-min-sdk N] [-max-sdk N] [-v] <apk>")
		os.Exit(2)
	}
	path := flag.Arg(0)
	f, err := os.Open(path)
	if err != nil {
		fatal("open: %v", err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		fatal("stat: %v", err)
	}
	ds := datasource.NewReaderAt(f, st.Size())
	res, err := apkverifier.Verify(ds, *minSdk, *maxSdk)
	if err != nil {
		fatal("verify: %v", err)
	}

	fmt.Printf("APK: %s (%d bytes)\n", path, st.Size())
	fmt.Printf("Verified: %v\n", res.Verified)
	fmt.Printf("  v3.1: present=%v verified=%v\n", res.HasV31Block, res.V31Verified)
	fmt.Printf("  v3:   present=%v verified=%v\n", res.HasV3Block, res.V3Verified)
	fmt.Printf("  v2:   present=%v verified=%v\n", res.HasV2Block, res.V2Verified)
	fmt.Printf("  v1:   verified=%v\n", res.V1Verified)
	fmt.Printf("  align: 4KB=%v 16KB=%v\n", res.Aligned4KB, res.Aligned16KB)
	if len(res.MisalignedFiles) > 0 {
		fmt.Printf("    misaligned .so files (4KB, %d):\n", len(res.MisalignedFiles))
		for _, f := range res.MisalignedFiles {
			fmt.Printf("      %s\n", f)
		}
	}
	if len(res.Misaligned16KB) > 0 {
		fmt.Printf("    misaligned .so files (16KB, %d):\n", len(res.Misaligned16KB))
		for _, f := range res.Misaligned16KB {
			fmt.Printf("      %s\n", f)
		}
	}
	for _, e := range res.Errors {
		fmt.Printf("ERROR: %s\n", e)
	}
	for _, w := range res.Warnings {
		fmt.Printf("WARN:  %s\n", w)
	}
	if *verbose {
		if res.V3 != nil {
			fmt.Printf("\nV3 signers: %d\n", len(res.V3.Signers))
			for _, s := range res.V3.Signers {
				fmt.Printf("  signer #%d verified=%v sdk=[%d,%d] algos=%v\n",
					s.Index, s.Verified, s.MinSDK, s.MaxSDK, s.VerifiedAlgorithms)
				for i, c := range s.Certs {
					fmt.Printf("    cert[%d]: subject=%s issuer=%s\n", i, c.Subject, c.Issuer)
				}
				if s.Lineage != nil {
					fmt.Printf("    lineage: %d node(s)\n", len(s.Lineage.Nodes))
					for i, n := range s.Lineage.Nodes {
						fmt.Printf("      node[%d] cert=%s flags=%#x\n", i, n.Cert.Subject, n.Flags)
					}
				} else if len(s.LineageBytes) > 0 {
					fmt.Printf("    lineage: %d raw bytes (decode skipped)\n", len(s.LineageBytes))
				}
				for _, e := range s.Errors {
					fmt.Printf("    err: %s\n", e)
				}
			}
		}
		if res.V2 != nil {
			fmt.Printf("\nV2 signers: %d\n", len(res.V2.Signers))
			for _, s := range res.V2.Signers {
				fmt.Printf("  signer #%d verified=%v algos=%v\n", s.Index, s.Verified, s.VerifiedAlgorithms)
				for i, c := range s.Certs {
					fmt.Printf("    cert[%d]: subject=%s issuer=%s\n", i, c.Subject, c.Issuer)
				}
				for _, e := range s.Errors {
					fmt.Printf("    err: %s\n", e)
				}
			}
		}
	}
	if !res.Verified {
		os.Exit(1)
	}
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "apksigverify: "+format+"\n", a...)
	os.Exit(2)
}
