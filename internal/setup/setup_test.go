package setup

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/hoangvu12/ame/internal/config"
	"github.com/ulikunitz/xz/lzma"
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

// fakeNSIS builds a minimal solid-LZMA NSIS installer holding entries.
func fakeNSIS(t *testing.T, entries ...[]byte) string {
	t.Helper()

	var raw bytes.Buffer
	for _, e := range entries {
		binary.Write(&raw, binary.LittleEndian, uint32(len(e)))
		raw.Write(e)
	}

	var classic bytes.Buffer
	w, err := lzma.NewWriter(&classic)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(raw.Bytes())
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	var exe bytes.Buffer
	exe.WriteString("MZ fake stub")
	binary.Write(&exe, binary.LittleEndian, uint32(0)) // flags
	exe.Write(nsisMagic)
	exe.Write(make([]byte, 8)) // header and total lengths
	exe.Write(classic.Bytes()[:5])
	exe.Write(classic.Bytes()[13:]) // NSIS drops the uncompressed size

	path := filepath.Join(t.TempDir(), "setup.exe")
	if err := os.WriteFile(path, exe.Bytes(), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestExtractFromNSISMatchesBySizeAndHash(t *testing.T) {
	host, dll := []byte("signed host"), []byte("signed dll!")
	decoy := []byte("unsigned dl") // same size as dll, different bytes
	files := []ltkFile{
		{"host.exe", int64(len(host)), sha256Hex(host)},
		{"hook.dll", int64(len(dll)), sha256Hex(dll)},
	}
	setup := fakeNSIS(t, []byte("installer script"), decoy, dll, host, []byte("trailing"))

	dest := t.TempDir()
	if err := extractFromNSIS(setup, files, dest); err != nil {
		t.Fatalf("extractFromNSIS: %v", err)
	}

	for name, want := range map[string][]byte{"host.exe.new": host, "hook.dll.new": dll} {
		got, err := os.ReadFile(filepath.Join(dest, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestExtractFromNSISMissingFile(t *testing.T) {
	setup := fakeNSIS(t, []byte("installer script"), []byte("something else"))
	files := []ltkFile{{"hook.dll", 4, sha256Hex([]byte("nope"))}}

	if err := extractFromNSIS(setup, files, t.TempDir()); err == nil {
		t.Fatal("expected an error for a file not in the installer")
	}
}

func TestExtractFromNSISNoHeader(t *testing.T) {
	src := filepath.Join(t.TempDir(), "plain.exe")
	if err := os.WriteFile(src, []byte("MZ just a stub"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := extractFromNSIS(src, patcherFiles, t.TempDir()); err == nil {
		t.Fatal("expected an error for an exe with no NSIS data")
	}
}

// v1.17.1 installed an unsigned patcher DLL that never attaches to the game;
// it must read as not installed so the next start replaces it.
func TestPatcherInstalledRequiresPinnedHashes(t *testing.T) {
	prev := config.ToolsDir
	config.ToolsDir = t.TempDir()
	defer func() { config.ToolsDir = prev }()

	for _, f := range patcherFiles {
		os.WriteFile(filepath.Join(config.ToolsDir, f.name), []byte("unsigned"), 0644)
	}
	if patcherInstalled() {
		t.Fatal("patcher with the wrong hashes reads as installed")
	}
}
