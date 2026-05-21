package apkverifier

import (
	"os"
	"testing"

	"github.com/agusibrahim/apksig-go/pkg/datasource"
)

const fdroidAPK = "/Users/macbook/Downloads/apksig-android-master/F-Droid.apk"

func TestFDroidVerifies(t *testing.T) {
	if _, err := os.Stat(fdroidAPK); err != nil {
		t.Skip("F-Droid.apk not available")
	}
	f, err := os.Open(fdroidAPK)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	st, _ := f.Stat()
	ds := datasource.NewReaderAt(f, st.Size())
	res, err := Verify(ds, 24, 35)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified {
		t.Fatalf("F-Droid.apk should verify; errors=%v", res.Errors)
	}
	if !res.V1Verified || !res.V2Verified || !res.V3Verified {
		t.Errorf("expected v1/v2/v3 all true, got v1=%v v2=%v v3=%v",
			res.V1Verified, res.V2Verified, res.V3Verified)
	}
	if res.V31Verified {
		t.Error("F-Droid.apk should not have a v3.1 signature")
	}
}
