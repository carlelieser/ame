package setup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hoangvu12/ame/internal/config"
)

// testdata/sfx.bin is a fake exe stub containing a decoy 7z signature,
// followed by a real 7z archive holding cslol-manager/cslol-tools/mod-tools.exe.

func TestExtractFromSFXSkipsDecoyAndExtracts(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "mod-tools.exe")

	if err := extractFromSFX(filepath.Join("testdata", "sfx.bin"), modToolsFiles[0].archivePath, dest); err != nil {
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

	if err := extractFromSFX(src, modToolsFiles[0].archivePath, filepath.Join(t.TempDir(), "out")); err == nil {
		t.Fatal("expected an error for an exe with no archive")
	}
}

// v1.14.10 installed mod-tools.exe without the cslol-dll.dll it imports; such
// an install must read as incomplete so the next start repairs it.
func TestModToolsInstalledRequiresEveryFile(t *testing.T) {
	prev := config.ToolsDir
	config.ToolsDir = t.TempDir()
	defer func() { config.ToolsDir = prev }()

	os.WriteFile(filepath.Join(config.ToolsDir, "mod-tools.exe"), []byte("exe"), 0644)
	if modToolsInstalled() {
		t.Fatal("mod-tools without cslol-dll.dll reads as installed")
	}

	os.WriteFile(filepath.Join(config.ToolsDir, "cslol-dll.dll"), []byte("dll"), 0644)
	if !modToolsInstalled() {
		t.Fatal("complete mod-tools install reads as missing")
	}
}
