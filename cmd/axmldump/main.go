package main

import (
	"archive/zip"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/agusibrahim/apksig-go/pkg/axml"
)

func main() {
	r, err := zip.OpenReader(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer r.Close()
	for _, f := range r.File {
		if f.Name == "AndroidManifest.xml" {
			rc, err := f.Open()
			if err != nil {
				panic(err)
			}
			data, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				panic(err)
			}
			fmt.Printf("manifest size: %d, first bytes: %x\n", len(data), data[:16])

			// Walk chunks manually
			off := 8
			for off < len(data)-8 {
				ct := binary.LittleEndian.Uint32(data[off : off+4])
				cs := binary.LittleEndian.Uint32(data[off+4 : off+8])
				fmt.Printf("chunk@%d type=%#x size=%d\n", off, ct, cs)
				if ct == 0x00100102 {
					// start element
					if int(cs) >= 36 {
						chunk := data[off : off+int(cs)]
						attrStart := binary.LittleEndian.Uint16(chunk[24:26])
						attrSize := binary.LittleEndian.Uint16(chunk[26:28])
						attrCount := binary.LittleEndian.Uint16(chunk[28:30])
						nameRef := binary.LittleEndian.Uint32(chunk[20:24])
						fmt.Printf("  startElem nameRef=%d attrStart=%d attrSize=%d attrCount=%d\n",
							nameRef, attrStart, attrSize, attrCount)
						base := 8 + int(attrStart)
						for i := 0; i < int(attrCount); i++ {
							o := base + i*int(attrSize)
							if o+20 > len(chunk) {
								break
							}
							ns := binary.LittleEndian.Uint32(chunk[o : o+4])
							nm := binary.LittleEndian.Uint32(chunk[o+4 : o+8])
							dt := chunk[o+15]
							dat := binary.LittleEndian.Uint32(chunk[o+16 : o+20])
							fmt.Printf("    attr[%d] ns=%d name=%d dataType=%#x data=%#x\n",
								i, ns, nm, dt, dat)
						}
					}
				}
				if cs < 8 {
					break
				}
				off += int(cs)
			}

			min, err := axml.MinSdk(data)
			fmt.Printf("\nMinSdk=%d err=%v\n", min, err)
			return
		}
	}
}

