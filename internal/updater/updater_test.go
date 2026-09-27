package updater

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// setupCore points the core and version files at a temp dir and returns a
// launcher exe: this test binary, a real PE that carries the repo marker.
func setupCore(t *testing.T) (launcher []byte, src string) {
	t.Helper()
	dir := t.TempDir()
	CORE_FILE = filepath.Join(dir, "ame_core.exe")
	VERSION_FILE = filepath.Join(dir, "version.txt")

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	launcher, err = os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(launcher, coreRepoMarker) {
		t.Fatal("test binary does not carry the repo marker")
	}
	src = filepath.Join(dir, "ame.exe")
	if err := os.WriteFile(src, launcher, 0755); err != nil {
		t.Fatal(err)
	}
	return launcher, src
}

// writeCore installs a core made from the launcher with a distinguishing
// suffix (still a valid PE), optionally rewriting the marker to another repo.
func writeCore(t *testing.T, launcher []byte, foreign bool) {
	t.Helper()
	core := append([]byte{}, launcher...)
	if foreign {
		other := bytes.Repeat([]byte("x"), len(GITHUB_REPO))
		core = bytes.ReplaceAll(core, []byte(GITHUB_REPO), other)
	}
	core = append(core, []byte("installed-core")...)
	if err := os.WriteFile(CORE_FILE, core, 0755); err != nil {
		t.Fatal(err)
	}
}

func coreIsLauncher(t *testing.T, launcher []byte) bool {
	t.Helper()
	got, err := os.ReadFile(CORE_FILE)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(got, launcher)
}

func TestBootstrapCoreInstallsWhenMissing(t *testing.T) {
	launcher, src := setupCore(t)

	if err := BootstrapCore(src, "v1.17.0"); err != nil {
		t.Fatal(err)
	}
	if !coreIsLauncher(t, launcher) {
		t.Fatal("launcher was not installed as the core")
	}
}

func TestBootstrapCoreReplacesForeignCore(t *testing.T) {
	launcher, src := setupCore(t)
	writeCore(t, launcher, true)
	SaveVersion("v1.16.0") // newer than the launcher, but from another repo

	if err := BootstrapCore(src, "v1.14.10"); err != nil {
		t.Fatal(err)
	}
	if !coreIsLauncher(t, launcher) {
		t.Fatal("a core from another repo was kept")
	}
}

func TestBootstrapCoreKeepsNewerOwnCore(t *testing.T) {
	launcher, src := setupCore(t)
	writeCore(t, launcher, false)
	SaveVersion("v1.17.1") // auto-updated past the launcher

	if err := BootstrapCore(src, "v1.17.0"); err != nil {
		t.Fatal(err)
	}
	if coreIsLauncher(t, launcher) {
		t.Fatal("an auto-updated core was downgraded to the launcher")
	}
}

func TestBootstrapCoreReplacesOlderOwnCore(t *testing.T) {
	launcher, src := setupCore(t)
	writeCore(t, launcher, false)
	SaveVersion("v1.14.10")

	if err := BootstrapCore(src, "v1.17.0"); err != nil {
		t.Fatal(err)
	}
	if !coreIsLauncher(t, launcher) {
		t.Fatal("an older core was kept over a newer launcher")
	}
}

func TestBootstrapCoreIgnoresItself(t *testing.T) {
	launcher, _ := setupCore(t)
	writeCore(t, launcher, true)

	if err := BootstrapCore(CORE_FILE, "v1.17.0"); err != nil {
		t.Fatal(err)
	}
	if coreIsLauncher(t, launcher) {
		t.Fatal("the core was rewritten from itself")
	}
}
