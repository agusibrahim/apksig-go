// Package keystore loads private keys and certificates from binary keystore
// formats commonly produced by Android tooling: JKS (Java KeyStore),
// JCEKS (Java Cryptography Extension KeyStore), and PKCS#12.
//
// Format is auto-detected from magic bytes; callers supply the store
// password and optionally a key password and alias.
package keystore

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"

	jks "github.com/pavlo-v-chernykh/keystore-go/v4"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Format identifies a keystore container format.
type Format int

const (
	FormatUnknown Format = iota
	FormatJKS
	FormatJCEKS
	FormatPKCS12
)

func (f Format) String() string {
	switch f {
	case FormatJKS:
		return "JKS"
	case FormatJCEKS:
		return "JCEKS"
	case FormatPKCS12:
		return "PKCS12"
	}
	return "unknown"
}

// Entry holds a private key together with its certificate chain.
type Entry struct {
	PrivateKey crypto.PrivateKey
	Cert       *x509.Certificate
	Chain      []*x509.Certificate
}

// LoadOpts controls how a keystore is opened and which entry is selected.
type LoadOpts struct {
	// StorePass unlocks the keystore container.
	StorePass string
	// KeyPass unlocks the private key entry. When empty, StorePass is used
	// as a fallback (this matches how keytool stores keys when -keypass is
	// not supplied).
	KeyPass string
	// Alias selects which entry to extract. When empty, the first entry
	// containing a private key is returned.
	Alias string
}

// Detect returns the keystore format based on the first few bytes of data.
func Detect(data []byte) Format {
	if len(data) < 4 {
		return FormatUnknown
	}
	magic := binary.BigEndian.Uint32(data[:4])
	switch magic {
	case 0xFEEDFEED:
		return FormatJKS
	case 0xCECECECE:
		return FormatJCEKS
	}
	// PKCS#12 is an ASN.1 SEQUENCE: 0x30 followed by length bytes.
	if data[0] == 0x30 && (data[1] == 0x82 || data[1] == 0x83 || data[1] == 0x84) {
		return FormatPKCS12
	}
	return FormatUnknown
}

// Load parses a keystore blob and extracts a single key entry.
func Load(data []byte, opts LoadOpts) (*Entry, error) {
	switch Detect(data) {
	case FormatJKS:
		return loadJKS(data, opts, false)
	case FormatJCEKS:
		return loadJKS(data, opts, true)
	case FormatPKCS12:
		return loadPKCS12(data, opts)
	}
	return nil, errors.New("keystore: unrecognized format (expected JKS, JCEKS, or PKCS#12)")
}

func loadJKS(data []byte, opts LoadOpts, jceks bool) (*Entry, error) {
	ks := jks.New()
	if jceks {
		// keystore-go does not support JCEKS natively; the JCEKS container
		// uses a different encryption scheme for keys but the structural
		// layout is similar enough that loading often works for the cert
		// portion. For now reject explicitly so users get a clear error.
		return nil, errors.New("keystore: JCEKS is not supported (convert to JKS or PKCS#12 with keytool -importkeystore)")
	}
	if err := ks.Load(bytes.NewReader(data), []byte(opts.StorePass)); err != nil {
		return nil, fmt.Errorf("keystore: load JKS: %w", err)
	}
	keyPass := opts.KeyPass
	if keyPass == "" {
		keyPass = opts.StorePass
	}
	alias := opts.Alias
	if alias == "" {
		for _, a := range ks.Aliases() {
			if ks.IsPrivateKeyEntry(a) {
				alias = a
				break
			}
		}
		if alias == "" {
			return nil, errors.New("keystore: no private key entry found")
		}
	} else if !ks.IsPrivateKeyEntry(alias) {
		return nil, fmt.Errorf("keystore: alias %q is not a private key entry", alias)
	}
	pke, err := ks.GetPrivateKeyEntry(alias, []byte(keyPass))
	if err != nil {
		return nil, fmt.Errorf("keystore: get key %q: %w", alias, err)
	}
	priv, err := x509.ParsePKCS8PrivateKey(pke.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("keystore: parse key %q: %w", alias, err)
	}
	if len(pke.CertificateChain) == 0 {
		return nil, fmt.Errorf("keystore: alias %q has no certificate chain", alias)
	}
	chain := make([]*x509.Certificate, 0, len(pke.CertificateChain))
	for i, c := range pke.CertificateChain {
		cert, err := x509.ParseCertificate(c.Content)
		if err != nil {
			return nil, fmt.Errorf("keystore: parse cert %d: %w", i, err)
		}
		chain = append(chain, cert)
	}
	return &Entry{PrivateKey: priv, Cert: chain[0], Chain: chain}, nil
}

func loadPKCS12(data []byte, opts LoadOpts) (*Entry, error) {
	// go-pkcs12 has separate decoders. DecodeChain returns the first
	// keypair regardless of alias; for alias filtering we use ToPEM and
	// pick by friendly name.
	if opts.Alias == "" {
		priv, cert, chain, err := pkcs12.DecodeChain(data, opts.StorePass)
		if err != nil {
			return nil, fmt.Errorf("keystore: decode PKCS#12: %w", err)
		}
		return &Entry{PrivateKey: priv, Cert: cert, Chain: prependChain(cert, chain)}, nil
	}
	// Alias-specific: decode all entries and match friendlyName.
	blocks, err := pkcs12.ToPEM(data, opts.StorePass)
	if err != nil {
		return nil, fmt.Errorf("keystore: decode PKCS#12: %w", err)
	}
	var (
		priv  crypto.PrivateKey
		cert  *x509.Certificate
		chain []*x509.Certificate
	)
	for _, b := range blocks {
		name := b.Headers["friendlyName"]
		if name != opts.Alias {
			continue
		}
		switch b.Type {
		case "PRIVATE KEY":
			if k, e := x509.ParsePKCS8PrivateKey(b.Bytes); e == nil {
				priv = k
			} else if k, e := x509.ParsePKCS1PrivateKey(b.Bytes); e == nil {
				priv = k
			} else if k, e := x509.ParseECPrivateKey(b.Bytes); e == nil {
				priv = k
			} else {
				return nil, fmt.Errorf("keystore: parse key %q: %w", opts.Alias, e)
			}
		case "RSA PRIVATE KEY":
			priv, err = x509.ParsePKCS1PrivateKey(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("keystore: parse RSA key %q: %w", opts.Alias, err)
			}
		case "EC PRIVATE KEY":
			priv, err = x509.ParseECPrivateKey(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("keystore: parse EC key %q: %w", opts.Alias, err)
			}
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(b.Bytes)
			if err != nil {
				return nil, fmt.Errorf("keystore: parse cert %q: %w", opts.Alias, err)
			}
			if cert == nil {
				cert = c
			} else {
				chain = append(chain, c)
			}
		}
	}
	if priv == nil || cert == nil {
		return nil, fmt.Errorf("keystore: alias %q not found in PKCS#12", opts.Alias)
	}
	return &Entry{PrivateKey: priv, Cert: cert, Chain: prependChain(cert, chain)}, nil
}

func prependChain(leaf *x509.Certificate, rest []*x509.Certificate) []*x509.Certificate {
	out := make([]*x509.Certificate, 0, 1+len(rest))
	out = append(out, leaf)
	out = append(out, rest...)
	return out
}
