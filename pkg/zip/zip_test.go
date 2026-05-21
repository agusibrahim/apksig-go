// Package zip tests cover EOCD discovery, central-directory parsing, and
// entry inflation against synthetic and real APK fixtures.
package zip

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"io"
	"testing"

	"github.com/agusibrahim/apksig-go/pkg/datasource"
)

// makeTestZip builds an in-memory ZIP archive with a single deflate-compressed
// entry. Returns the ZIP bytes plus the entry's expected uncompressed content.
func makeTestZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for name, data := range entries {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestFindEOCDOnEmptyArchive(t *testing.T) {
	z := makeTestZip(t, map[string][]byte{})
	ds := datasource.NewBytes(z)
	eocd, err := FindEOCD(ds)
	if err != nil {
		t.Fatalf("FindEOCD: %v", err)
	}
	if eocd.CDEntries != 0 {
		t.Errorf("entries: got %d, want 0", eocd.CDEntries)
	}
}

func TestFindEOCDWithComment(t *testing.T) {
	// archive/zip doesn't expose comment writer; build manually.
	z := makeTestZip(t, map[string][]byte{"hello.txt": []byte("hello")})
	// Append a 5-byte comment to the archive's EOCD by patching the comment
	// length and tacking bytes on the end.
	z[len(z)-2] = 0x05
	z[len(z)-1] = 0x00
	z = append(z, []byte("hello")...)
	ds := datasource.NewBytes(z)
	eocd, err := FindEOCD(ds)
	if err != nil {
		t.Fatalf("with comment: %v", err)
	}
	if eocd.CommentLen != 5 {
		t.Errorf("comment len: %d", eocd.CommentLen)
	}
}

func TestParseCD_RoundTrip(t *testing.T) {
	z := makeTestZip(t, map[string][]byte{
		"AndroidManifest.xml": []byte("<manifest/>"),
		"classes.dex":         bytes.Repeat([]byte{0x42}, 4096),
	})
	ds := datasource.NewBytes(z)
	eocd, err := FindEOCD(ds)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ParseCD(ds, eocd)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries: got %d, want 2", len(entries))
	}
	names := map[string]bool{}
	for _, e := range entries {
		names[e.Name] = true
	}
	if !names["AndroidManifest.xml"] || !names["classes.dex"] {
		t.Errorf("missing entries: %v", names)
	}
}

func TestReadEntry_Stored(t *testing.T) {
	// Build a ZIP entry stored uncompressed (CompressionMethod=0).
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	hdr := &zip.FileHeader{Name: "stored", Method: zip.Store}
	fw, _ := w.CreateHeader(hdr)
	want := []byte("uncompressed payload")
	fw.Write(want)
	w.Close()
	ds := datasource.NewBytes(buf.Bytes())
	eocd, _ := FindEOCD(ds)
	entries, _ := ParseCD(ds, eocd)
	got, err := ReadEntry(ds, &entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("mismatch: %q vs %q", got, want)
	}
}

func TestReadEntry_Deflate(t *testing.T) {
	z := makeTestZip(t, map[string][]byte{"f.txt": bytes.Repeat([]byte("ab"), 100)})
	ds := datasource.NewBytes(z)
	eocd, _ := FindEOCD(ds)
	entries, _ := ParseCD(ds, eocd)
	got, err := ReadEntry(ds, &entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if want := bytes.Repeat([]byte("ab"), 100); !bytes.Equal(got, want) {
		t.Errorf("inflate mismatch: len=%d", len(got))
	}
}

func TestSetCDOffset(t *testing.T) {
	eocd := &EOCD{Bytes: make([]byte, 22)}
	eocd.SetCDOffset(0xdeadbeef)
	got := uint32(eocd.Bytes[16]) | uint32(eocd.Bytes[17])<<8 |
		uint32(eocd.Bytes[18])<<16 | uint32(eocd.Bytes[19])<<24
	if got != 0xdeadbeef {
		t.Errorf("offset: got %#x, want 0xdeadbeef", got)
	}
}

// Sanity: our flate inflater behaves like compress/flate.
func TestInflateMatchesStdlib(t *testing.T) {
	src := []byte("Hello, APK signing!\n")
	var raw bytes.Buffer
	fw, _ := flate.NewWriter(&raw, flate.DefaultCompression)
	fw.Write(src)
	fw.Close()
	got, err := inflate(raw.Bytes(), len(src))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, src) {
		t.Errorf("mismatch: %q", got)
	}
	_ = io.EOF
}
