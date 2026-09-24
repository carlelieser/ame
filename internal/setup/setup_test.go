package setup

import (
	"os"
	"path/filepath"
	"testing"
)

// testdata/sfx.bin is a fake exe stub containing a decoy 7z signature,
// followed by a real 7z archive holding cslol-manager/cslol-tools/mod-tools.exe.

func TestExtractFromSFXSkipsDecoyAndExtracts(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "mod-tools.exe")

	if err := extractFromSFX(filepath.Join("testdata", "sfx.bin"), cslolModToolsPath, dest); err != nil {
		t.Fatalf("extractFromSFX: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "fake mod-tools\n" {
		t.Fatalf("extracted %q", got)
	}
}

func TestExtractFromSFXMissingEntry(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "out")

	if err := extractFromSFX(filepath.Join("testdata", "sfx.bin"), "cslol-manager/cslol-tools/nope.exe", dest); err == nil {
		t.Fatal("expected an error for a file not in the archive")
	}
}

func TestExtractFromSFXNoArchive(t *testing.T) {
	src := filepath.Join(t.TempDir(), "plain.exe")
	if err := os.WriteFile(src, []byte("MZ just a stub"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := extractFromSFX(src, cslolModToolsPath, filepath.Join(t.TempDir(), "out")); err == nil {
		t.Fatal("expected an error for an exe with no archive")
	}
}
