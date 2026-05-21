// apksign signs an APK with a given private key + certificate, producing a
// signed APK that can be installed on Android.
//
//   apksign -key key.pem -cert cert.pem -in unsigned.apk -out signed.apk

//go:debug x509negativeserial=1

package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"os"
	"strings"

	"github.com/agusibrahim/apksig-go/pkg/algo"
	"github.com/agusibrahim/apksig-go/pkg/apksigblock"
	"github.com/agusibrahim/apksig-go/pkg/apkwriter"
	"github.com/agusibrahim/apksig-go/pkg/datasource"
	"github.com/agusibrahim/apksig-go/pkg/keystore"
	"github.com/agusibrahim/apksig-go/pkg/signer"
	"github.com/agusibrahim/apksig-go/pkg/v1signer"
	"github.com/agusibrahim/apksig-go/pkg/v4signer"
	zippkg "github.com/agusibrahim/apksig-go/pkg/zip"
)

func main() {
	keyPath := flag.String("key", "", "PEM-encoded PKCS#8 (or RSA) private key")
	certPath := flag.String("cert", "", "PEM-encoded X.509 certificate")
	ksPath := flag.String("keystore", "", "JKS or PKCS#12 keystore file (alternative to -key/-cert)")
	storePass := flag.String("storepass", "", "keystore password (use env:NAME or file:PATH to avoid shell history)")
	keyPass := flag.String("keypass", "", "key entry password (defaults to -storepass; same env:/file: prefixes)")
	alias := flag.String("alias", "", "key entry alias inside the keystore (defaults to first key entry)")
	in := flag.String("in", "", "input APK")
	out := flag.String("out", "", "output APK")
	v3 := flag.Bool("v3", true, "also write a v3 signature")
	v3Min := flag.Int("v3-min-sdk", 28, "v3 min SDK")
	v3Max := flag.Int("v3-max-sdk", 0x7fffffff, "v3 max SDK")
	v31 := flag.Bool("v3.1", false, "also write a v3.1 signature (rotation)")
	v31Min := flag.Int("v3.1-min-sdk", 33, "v3.1 min SDK")
	v31Max := flag.Int("v3.1-max-sdk", 0x7fffffff, "v3.1 max SDK")
	v4 := flag.Bool("v4", false, "also write a .idsig (v4) file alongside the output APK")
	v4Out := flag.String("v4-out", "", "v4 .idsig output path; defaults to <out>.idsig")
	v1 := flag.Bool("v1", false, "also write a v1 (JAR) signature")
	align := flag.Bool("align", false, "4-byte align uncompressed ZIP entries (zipalign)")
	flag.Parse()
	if *in == "" || *out == "" || (*ksPath == "" && (*keyPath == "" || *certPath == "")) {
		fmt.Fprintln(os.Stderr, "usage: apksign -key key.pem -cert cert.pem -in in.apk -out out.apk")
		fmt.Fprintln(os.Stderr, "   or: apksign -keystore key.jks -storepass <pass> [-alias name] -in in.apk -out out.apk")
		os.Exit(2)
	}

	var (
		priv crypto.PrivateKey
		cert *x509.Certificate
		err  error
	)
	if *ksPath != "" {
		sp, err := resolvePassword(*storePass)
		if err != nil {
			fatal("storepass: %v", err)
		}
		kp := *keyPass
		if kp == "" {
			kp = *storePass
		}
		kpv, err := resolvePassword(kp)
		if err != nil {
			fatal("keypass: %v", err)
		}
		ksData, err := os.ReadFile(*ksPath)
		if err != nil {
			fatal("read keystore: %v", err)
		}
		entry, err := keystore.Load(ksData, keystore.LoadOpts{
			StorePass: sp,
			KeyPass:   kpv,
			Alias:     *alias,
		})
		if err != nil {
			fatal("keystore: %v", err)
		}
		priv = entry.PrivateKey
		cert = entry.Cert
	} else {
		priv, err = loadPrivateKey(*keyPath)
		if err != nil {
			fatal("key: %v", err)
		}
		cert, err = loadCertificate(*certPath)
		if err != nil {
			fatal("cert: %v", err)
		}
	}

	alg, err := algo.PickAlgorithm(priv)
	if err != nil {
		fatal("pick algorithm: %v", err)
	}

	cfg := &signer.SignerConfig{
		PrivateKey: priv,
		Certs:      []*x509.Certificate{cert},
		Algorithms: []algo.Algorithm{alg},
	}

	f, err := os.Open(*in)
	if err != nil {
		fatal("open input: %v", err)
	}
	defer f.Close()
	st, _ := f.Stat()
	src := datasource.NewReaderAt(f, st.Size())

	// If v1 signing is requested, create an intermediate APK with v1 META-INF files.
	var v1Src datasource.DataSource = src
	if *v1 {
		v1Src, err = injectV1(src, priv, cert)
		if err != nil {
			fatal("v1 sign: %v", err)
		}
		fmt.Printf("v1 signature added\n")
	}

	outF, err := os.Create(*out)
	if err != nil {
		fatal("create output: %v", err)
	}
	defer outF.Close()

	w := &apkwriter.SignedAPKWriter{
		Src:     v1Src,
		Signers: []*signer.SignerConfig{cfg},
	}
	if *v3 {
		w.V3MinSdk = int32(*v3Min)
		w.V3MaxSdk = int32(*v3Max)
	}
	if *v31 {
		w.V31MinSdk = int32(*v31Min)
		w.V31MaxSdk = int32(*v31Max)
	}
	w.Align = *align
	if err := w.Write(outF); err != nil {
		fatal("write: %v", err)
	}
	fmt.Printf("signed %s -> %s (%d bytes)\n", *in, *out, fileSize(*out))

	if *v4 {
		idsigPath := *v4Out
		if idsigPath == "" {
			idsigPath = *out + ".idsig"
		}
		// Re-open the freshly written APK as a DataSource for v4 signing.
		signedF, err := os.Open(*out)
		if err != nil {
			fatal("reopen output for v4: %v", err)
		}
		defer signedF.Close()
		signedSt, _ := signedF.Stat()
		signedDS := datasource.NewReaderAt(signedF, signedSt.Size())

		v4cfg := &v4signer.Config{
			PrivateKey: priv,
			Cert:       cert,
			Algorithm:  alg,
		}
		if *v31 {
			v4cfg.V41PrivateKey = priv
			v4cfg.V41Cert = cert
			v4cfg.V41Algorithm = alg
		}
		idsig, err := v4signer.Sign(signedDS, v4cfg)
		if err != nil {
			fatal("v4 sign: %v", err)
		}
		if err := os.WriteFile(idsigPath, idsig, 0644); err != nil {
			fatal("write idsig: %v", err)
		}
		fmt.Printf("v4 signature -> %s (%d bytes)\n", idsigPath, len(idsig))
	}
}

func fileSize(p string) int64 {
	st, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return st.Size()
}

func loadPrivateKey(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("not a PEM file")
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

func loadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("not a PEM file")
	}
	return x509.ParseCertificate(block.Bytes)
}

func fatal(f string, a ...any) { fmt.Fprintf(os.Stderr, "apksign: "+f+"\n", a...); os.Exit(2) }

// resolvePassword returns the literal password unless prefixed with env: or
// file:, in which case the value is read from the environment or a file. The
// trailing newline of file content is stripped so files written by `echo`
// behave as expected. An empty input returns an empty password.
func resolvePassword(spec string) (string, error) {
	if strings.HasPrefix(spec, "env:") {
		return os.Getenv(strings.TrimPrefix(spec, "env:")), nil
	}
	if strings.HasPrefix(spec, "file:") {
		data, err := os.ReadFile(strings.TrimPrefix(spec, "file:"))
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	return spec, nil
}

func injectV1(src datasource.DataSource, priv crypto.PrivateKey, cert *x509.Certificate) (datasource.DataSource, error) {
	eocd, err := zippkg.FindEOCD(src)
	if err != nil {
		return nil, fmt.Errorf("find EOCD: %w", err)
	}
	entries, err := zippkg.ParseCD(src, eocd)
	if err != nil {
		return nil, fmt.Errorf("parse CD: %w", err)
	}

	v1out, err := v1signer.Sign(src, entries, &v1signer.SignerConfig{
		PrivateKey: priv,
		Cert:       cert,
		Name:       "CERT",
	})
	if err != nil {
		return nil, err
	}

	// Preserve original entry bytes verbatim (keeps .so page alignment).
	beforeEnd := eocd.CDStartOffset
	if blk, err := apksigblock.Find(src, eocd); err == nil {
		beforeEnd = blk.StartOffset
	}
	origEntries, err := datasource.ReadAll(src.Slice(0, beforeEnd))
	if err != nil {
		return nil, err
	}

	metaFiles := []struct {
		name string
		data []byte
	}{
		{"META-INF/MANIFEST.MF", v1out.Manifest},
		{"META-INF/CERT.SF", v1out.SF},
		{"META-INF/CERT" + v1out.Extension, v1out.PKCS7},
	}

	var metaLFH, metaCD []byte
	metaOffset := uint32(len(origEntries))
	for _, mf := range metaFiles {
		lfh, cdEntry := makeRawZipEntry(mf.name, mf.data, metaOffset)
		metaLFH = append(metaLFH, lfh...)
		metaCD = append(metaCD, cdEntry...)
		metaOffset += uint32(len(lfh))
	}

	origCD, err := datasource.ReadAll(src.Slice(eocd.CDStartOffset, eocd.CDSize))
	if err != nil {
		return nil, err
	}
	filteredCD := filterRawCD(origCD, entries, isV1SignatureFile)
	keptCount := countKept(entries, isV1SignatureFile)

	var out bytes.Buffer
	out.Write(origEntries)
	out.Write(metaLFH)
	cdOff := uint32(out.Len())
	out.Write(filteredCD)
	out.Write(metaCD)
	cdSize := uint32(out.Len()) - cdOff
	totalEntries := uint16(keptCount + len(metaFiles))

	eocdRec := make([]byte, 22)
	binary.LittleEndian.PutUint32(eocdRec[0:4], 0x06054b50)
	binary.LittleEndian.PutUint16(eocdRec[8:10], totalEntries)
	binary.LittleEndian.PutUint16(eocdRec[10:12], totalEntries)
	binary.LittleEndian.PutUint32(eocdRec[12:16], cdSize)
	binary.LittleEndian.PutUint32(eocdRec[16:20], cdOff)
	out.Write(eocdRec)

	return datasource.NewBytes(out.Bytes()), nil
}

func makeRawZipEntry(name string, data []byte, lfhOffset uint32) (lfh []byte, cdEntry []byte) {
	crc := crc32.ChecksumIEEE(data)
	nb := []byte(name)
	lfh = make([]byte, 30+len(nb)+len(data))
	binary.LittleEndian.PutUint32(lfh[0:4], 0x04034b50)
	binary.LittleEndian.PutUint16(lfh[4:6], 20)
	binary.LittleEndian.PutUint16(lfh[8:10], 0)
	binary.LittleEndian.PutUint32(lfh[14:18], crc)
	binary.LittleEndian.PutUint32(lfh[18:22], uint32(len(data)))
	binary.LittleEndian.PutUint32(lfh[22:26], uint32(len(data)))
	binary.LittleEndian.PutUint16(lfh[26:28], uint16(len(nb)))
	copy(lfh[30:], nb)
	copy(lfh[30+len(nb):], data)

	cdEntry = make([]byte, 46+len(nb))
	binary.LittleEndian.PutUint32(cdEntry[0:4], 0x02014b50)
	binary.LittleEndian.PutUint16(cdEntry[4:6], 20)
	binary.LittleEndian.PutUint16(cdEntry[6:8], 20)
	binary.LittleEndian.PutUint16(cdEntry[10:12], 0)
	binary.LittleEndian.PutUint32(cdEntry[16:20], crc)
	binary.LittleEndian.PutUint32(cdEntry[20:24], uint32(len(data)))
	binary.LittleEndian.PutUint32(cdEntry[24:28], uint32(len(data)))
	binary.LittleEndian.PutUint16(cdEntry[28:30], uint16(len(nb)))
	binary.LittleEndian.PutUint32(cdEntry[42:46], lfhOffset)
	copy(cdEntry[46:], nb)
	return
}

func filterRawCD(rawCD []byte, entries []zippkg.CDEntry, skipFn func(string) bool) []byte {
	var out []byte
	off := int64(0)
	for _, e := range entries {
		n := e.HeaderSize
		if !skipFn(e.Name) {
			out = append(out, rawCD[off:off+n]...)
		}
		off += n
	}
	return out
}

func countKept(entries []zippkg.CDEntry, skipFn func(string) bool) int {
	n := 0
	for _, e := range entries {
		if !skipFn(e.Name) {
			n++
		}
	}
	return n
}

func isV1SignatureFile(name string) bool {
	if !strings.HasPrefix(name, "META-INF/") {
		return false
	}
	if name == "META-INF/MANIFEST.MF" {
		return true
	}
	if strings.HasSuffix(name, ".SF") || strings.HasSuffix(name, ".RSA") ||
		strings.HasSuffix(name, ".DSA") || strings.HasSuffix(name, ".EC") {
		return true
	}
	return false
}