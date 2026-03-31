package file

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCollectIPsFromFileDeduplicatesAndKeepsValidIPs(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "ips.txt")
	content := "1.1.1.1\ninvalid\n2.2.2.2 extra 1.1.1.1\n2001:4860:4860::8888\n999.1.1.1\n"
	if err := os.WriteFile(filePath, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	got, err := collectIPsFromFile(filePath)
	if err != nil {
		t.Fatalf("collectIPsFromFile returned error: %v", err)
	}

	want := []string{"1.1.1.1", "2.2.2.2", "2001:4860:4860::8888"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected IP list\nwant: %#v\ngot:  %#v", want, got)
	}
}
