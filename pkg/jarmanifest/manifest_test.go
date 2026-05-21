package jarmanifest

import "testing"

func TestParseSimple(t *testing.T) {
	data := []byte(
		"Manifest-Version: 1.0\r\n" +
			"Created-By: Test\r\n" +
			"\r\n" +
			"Name: foo/bar\r\n" +
			"SHA-256-Digest: AAAA\r\n" +
			"\r\n",
	)
	secs, err := ParseAll(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(secs) != 2 {
		t.Fatalf("sections: %d", len(secs))
	}
	if got := secs[0].Get("Manifest-Version"); got != "1.0" {
		t.Errorf("main: %q", got)
	}
	if got := secs[1].Name(); got != "foo/bar" {
		t.Errorf("name: %q", got)
	}
	if got := secs[1].Get("SHA-256-Digest"); got != "AAAA" {
		t.Errorf("digest: %q", got)
	}
}

func TestContinuationLine(t *testing.T) {
	data := []byte(
		"Name: very/long/path\r\n" +
			" /that/continues\r\n" +
			"SHA-256-Digest: X\r\n\r\n",
	)
	secs, err := ParseAll(data)
	if err != nil {
		t.Fatal(err)
	}
	if got := secs[0].Name(); got != "very/long/path/that/continues" {
		t.Errorf("continuation: %q", got)
	}
}
