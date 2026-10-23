package setup

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bodgit/sevenzip"
	"github.com/hoangvu12/ame/internal/config"
	"github.com/hoangvu12/ame/internal/modtools"
	"github.com/ulikunitz/xz/lzma"
)

var (
	PENGU_DIR  = config.PenguDir
	PLUGIN_DIR = filepath.Join(PENGU_DIR, "plugins", "ame")
)

// GetExistingPenguDir detects an existing Pengu Loader installation from the registry
// Returns the installation directory path, or empty string if not found
// Exported for use by other packages
func GetExistingPenguDir() string {
	// Query the IFEO Debugger value
	cmd := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LeagueClientUx.exe`,
		"/v", "Debugger")
	cmd.SysProcAttr = getSysProcAttr()
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	// Parse the output to extract the path
	// Format: rundll32 "C:\path\to\core.dll", #6000
	outputStr := string(output)
	if !strings.Contains(strings.ToLower(outputStr), "rundll32") {
		return ""
	}

	// Find the path between quotes
	startQuote := strings.Index(outputStr, `"`)
	if startQuote == -1 {
		return ""
	}
	endQuote := strings.Index(outputStr[startQuote+1:], `"`)
	if endQuote == -1 {
		return ""
	}

	corePath := outputStr[startQuote+1 : startQuote+1+endQuote]

	// Verify the core.dll exists
	if _, err := os.Stat(corePath); os.IsNotExist(err) {
		return ""
	}

	// Return the parent directory (Pengu installation dir)
	return filepath.Dir(corePath)
}

// IsUsingExternalPengu checks if we're using a Pengu installation outside of ame's directory
func IsUsingExternalPengu() bool {
	existingDir := GetExistingPenguDir()
	if existingDir == "" {
		return false
	}
	// Check if it's NOT in our default location
	defaultPenguDir := config.PenguDir
	return !strings.EqualFold(filepath.Clean(existingDir), filepath.Clean(defaultPenguDir))
}

// DetectAndSetPenguPaths detects existing Pengu installation and updates PENGU_DIR/PLUGIN_DIR
// Call this before SetupPlugin when you need to install plugins without full setup
func DetectAndSetPenguPaths() {
	existingDir := GetExistingPenguDir()
	if existingDir != "" {
		PENGU_DIR = existingDir
		PLUGIN_DIR = filepath.Join(PENGU_DIR, "plugins", "ame")
	} else {
		// Ensure PLUGIN_DIR is set correctly for default location
		PLUGIN_DIR = filepath.Join(PENGU_DIR, "plugins", "ame")
	}
}

// GetPluginDir returns the current plugin directory path
func GetPluginDir() string {
	return PLUGIN_DIR
}

// Config holds setup URLs
type Config struct {
	PenguURL  string
	PluginURL string
	DevSrcDir string // When non-empty, copy plugin from this local dir instead of downloading
}

// statusFail prints a failure message (success is silent)
func statusFail(name string) {
	fmt.Printf("  ! %s failed\n", name)
}

// info prints an info message
func info(message string) {
	fmt.Printf("  %s\n", message)
}

// downloadFile downloads a file from URL to destination
func downloadFile(url, dest string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %d", resp.StatusCode)
	}

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

// extractZip extracts a zip file to destination directory
func extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		fpath := filepath.Join(destDir, f.Name)

		// Prevent zip slip vulnerability
		if !strings.HasPrefix(filepath.Clean(fpath), filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("invalid file path: %s", f.Name)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return err
		}
	}

	return nil
}

// IsPenguActivated checks if Pengu Loader is activated via registry
func IsPenguActivated() bool {
	cmd := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LeagueClientUx.exe`,
		"/v", "Debugger")
	cmd.SysProcAttr = getSysProcAttr()
	err := cmd.Run()
	return err == nil
}

const ifeoKey = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LeagueClientUx.exe`

// ActivatePengu sets the IFEO Debugger registry value so PenguLoader
// injects into LeagueClientUx.exe on launch.
func ActivatePengu() error {
	coreDll := filepath.Join(PENGU_DIR, "core.dll")
	if _, err := os.Stat(coreDll); os.IsNotExist(err) {
		return fmt.Errorf("core.dll not found at %s", coreDll)
	}

	value := fmt.Sprintf(`rundll32 "%s", #6000`, coreDll)

	cmd := exec.Command("reg", "add", ifeoKey, "/v", "Debugger", "/t", "REG_SZ", "/d", value, "/f")
	cmd.SysProcAttr = getSysProcAttr()
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("reg add failed: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// DeactivatePengu removes the IFEO Debugger registry value.
func DeactivatePengu() {
	cmd := exec.Command("reg", "delete", ifeoKey, "/v", "Debugger", "/f")
	cmd.SysProcAttr = getSysProcAttr()
	cmd.Run() // ignore errors — value may already be absent
}

// createDirectories creates base directories (not Pengu-related, those are created after detection)
func createDirectories() {
	dirs := []string{config.AmeDir, config.ToolsDir, config.SkinsDir, config.ModsDir, config.OverlayDir}
	for _, dir := range dirs {
		os.MkdirAll(dir, os.ModePerm)
	}
}

// mod-tools comes from a pinned official cslol-manager release. ame only uses
// it to build overlays (mkoverlay), which doesn't break with game patches, so
// the release is pinned and each extracted file checked against its hash.
const (
	cslolRelease    = "2026-04-15-23f2308"
	cslolReleaseURL = "https://github.com/LeagueToolkit/cslol-manager/releases/download/" + cslolRelease + "/cslol-manager-windows.exe"
)

// cslolFile is one file ame installs from the cslol-manager release.
type cslolFile struct {
	archivePath string
	name        string
	sha256      string
}

// modToolsFiles are installed together: mod-tools.exe imports cslol-dll.dll
// and won't start without it, even though ame no longer injects the DLL.
var modToolsFiles = []cslolFile{
	{"cslol-manager/cslol-tools/mod-tools.exe", "mod-tools.exe", "d4e2f38086275ec51fab57034ae442bc75c1b0f00c725b78cc4cf616ce9b3d42"},
	{"cslol-manager/cslol-tools/cslol-dll.dll", "cslol-dll.dll", "ae12fb633d88cf31a080ef24ec2c08dc398ddc22fd03e5addc45950dfb2f1c28"},
}

// legacyTools were shipped by the old tools zip and are no longer used.
var legacyTools = []string{"cslol-diag.exe", "wad-extract.exe", "wad-make.exe"}

// modToolsInstalled reports whether every mod-tools file is present.
func modToolsInstalled() bool {
	for _, f := range modToolsFiles {
		if _, err := os.Stat(filepath.Join(config.ToolsDir, f.name)); err != nil {
			return false
		}
	}
	return true
}

// SetupModTools downloads mod-tools from the cslol-manager release if missing or forced.
func SetupModTools(force bool) bool {
	if !force && modToolsInstalled() {
		return true
	}

	info("Downloading mod-tools...")

	sfxPath := filepath.Join(config.AmeDir, "cslol-manager.exe")
	if err := downloadFile(cslolReleaseURL, sfxPath); err != nil {
		statusFail("mod-tools download")
		return false
	}
	defer os.Remove(sfxPath)

	os.MkdirAll(config.ToolsDir, os.ModePerm)

	// Extract and verify everything before replacing anything
	for _, f := range modToolsFiles {
		tmpPath := filepath.Join(config.ToolsDir, f.name+".new")
		defer os.Remove(tmpPath)

		if err := extractFromSFX(sfxPath, f.archivePath, tmpPath); err != nil {
			statusFail("mod-tools extract")
			return false
		}
		if sum, err := fileSHA256(tmpPath); err != nil || sum != f.sha256 {
			statusFail("mod-tools verify")
			return false
		}
	}

	for _, f := range modToolsFiles {
		dst := filepath.Join(config.ToolsDir, f.name)
		if err := os.Rename(dst+".new", dst); err != nil {
			statusFail("mod-tools setup")
			return false
		}
	}

	for _, name := range legacyTools {
		os.Remove(filepath.Join(config.ToolsDir, name))
	}

	return true
}

// sevenZipMagic starts a 7z archive. The cslol-manager release is a 7-Zip
// self-extractor: a small exe stub with the archive appended.
var sevenZipMagic = []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}

// extractFromSFX copies one file out of a 7-Zip self-extracting exe.
func extractFromSFX(sfxPath, name, dest string) error {
	f, err := os.Open(sfxPath)
	if err != nil {
		return err
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return err
	}

	// The archive follows the stub, well within the first few MB
	head := make([]byte, 8<<20)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF {
		return err
	}
	head = head[:n]

	// The magic can also occur inside the stub, so take the first offset
	// that opens as an archive
	for off := 0; ; off++ {
		i := bytes.Index(head[off:], sevenZipMagic)
		if i < 0 {
			return fmt.Errorf("no 7z archive in %s", sfxPath)
		}
		off += i

		size := st.Size() - int64(off)
		r, err := sevenzip.NewReader(io.NewSectionReader(f, int64(off), size), size)
		if err != nil {
			continue
		}

		for _, entry := range r.File {
			if entry.Name != name {
				continue
			}
			rc, err := entry.Open()
			if err != nil {
				return err
			}
			defer rc.Close()

			out, err := os.Create(dest)
			if err != nil {
				return err
			}
			if _, err := io.Copy(out, rc); err != nil {
				out.Close()
				return err
			}
			return out.Close()
		}
		return fmt.Errorf("%s not found in archive", name)
	}
}

// fileSHA256 returns the hex SHA-256 of a file.
func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// The patcher comes from a pinned official LTK Manager installer. From v1.30.0
// the hook DLL refuses to overlay unless its host was launched by
// ltk-manager.exe (VRF00000008), so later releases do not work with ame. The
// copies committed to the ltk-manager repo can't be used instead: the v1.29.1
// DLL there is unsigned and never attaches to the game.
const (
	ltkRelease    = "v1.29.1"
	ltkReleaseURL = "https://github.com/LeagueToolkit/ltk-manager/releases/download/" + ltkRelease + "/LTK.Manager_1.29.1_x64-setup.exe"
)

// ltkFile is one file ame installs from the LTK Manager installer.
type ltkFile struct {
	name   string
	size   int64
	sha256 string
}

// patcherFiles are installed together, since the host and DLL speak a
// protocol that changes between releases.
var patcherFiles = []ltkFile{
	{modtools.PatcherHostExe, 1238272, "23fa1aaeda1a0c743da44227f179084e1fb81c7cd262144a3c8604ffc49d3bc1"},
	{modtools.PatcherDLL, 770328, "3dce3ac99e55839559129e32ae9de75ddaec40f310118475248f99c61656ecf5"},
}

// patcherInstalled reports whether every patcher file matches the pinned release.
func patcherInstalled() bool {
	for _, f := range patcherFiles {
		if sum, err := fileSHA256(filepath.Join(config.ToolsDir, f.name)); err != nil || sum != f.sha256 {
			return false
		}
	}
	return true
}

// SetupPatcher installs the LTK patcher host and hook DLL from the pinned
// release, replacing any copy from another release. An existing copy is kept
// when the download fails.
func SetupPatcher() bool {
	if patcherInstalled() {
		return true
	}

	installed := true
	for _, f := range patcherFiles {
		if _, err := os.Stat(filepath.Join(config.ToolsDir, f.name)); err != nil {
			installed = false
		}
	}

	info("Downloading patcher " + ltkRelease + "...")

	setupPath := filepath.Join(config.AmeDir, "ltk-manager-setup.exe")
	defer os.Remove(setupPath)
	for _, f := range patcherFiles {
		defer os.Remove(filepath.Join(config.ToolsDir, f.name+".new"))
	}

	// Extract and verify everything before replacing anything, so a failure
	// never leaves a host and DLL from different releases.
	if err := downloadFile(ltkReleaseURL, setupPath); err != nil {
		if installed {
			return true
		}
		statusFail("patcher download")
		return false
	}
	if err := extractFromNSIS(setupPath, patcherFiles, config.ToolsDir); err != nil {
		if installed {
			return true
		}
		statusFail("patcher extract")
		return false
	}

	for _, f := range patcherFiles {
		dst := filepath.Join(config.ToolsDir, f.name)
		if err := os.Rename(dst+".new", dst); err != nil {
			// The host is still running from a previous session; retry next start
			return installed
		}
	}

	// Older versions tracked the release here; the hashes replace it
	os.Remove(filepath.Join(config.ToolsDir, "ltk-patcher.version"))
	return true
}

// nsisMagic follows the 4-byte flags of an NSIS installer's first header.
var nsisMagic = []byte("\xef\xbe\xad\xdeNullsoftInst")

// extractFromNSIS writes each of files found in an NSIS installer to
// destDir/<name>.new. The installer must be built with solid LZMA, which
// stores every file as a 4-byte length followed by its bytes in one stream.
// A file is matched by its size and SHA-256, as NSIS keeps no names there.
func extractFromNSIS(setupPath string, files []ltkFile, destDir string) error {
	data, err := os.ReadFile(setupPath)
	if err != nil {
		return err
	}

	sig := bytes.Index(data, nsisMagic)
	if sig < 4 {
		return fmt.Errorf("no NSIS header in %s", setupPath)
	}
	// flags, magic, header length and total length come before the data
	stream := data[sig-4+28:]
	if len(stream) < 5 {
		return fmt.Errorf("truncated NSIS data in %s", setupPath)
	}

	// NSIS writes LZMA properties and dictionary size without the classic
	// header's uncompressed size, so mark the size as unknown
	header := append(append([]byte{}, stream[:5]...), bytes.Repeat([]byte{0xFF}, 8)...)
	lr, err := lzma.NewReader(io.MultiReader(bytes.NewReader(header), bytes.NewReader(stream[5:])))
	if err != nil {
		return err
	}
	r := bufio.NewReader(lr)

	remaining := len(files)
	found := make([]bool, len(files))
	for remaining > 0 {
		var n uint32
		if err := binary.Read(r, binary.LittleEndian, &n); err != nil {
			return fmt.Errorf("%d patcher files not found in installer: %w", remaining, err)
		}
		if n&0x80000000 != 0 {
			return fmt.Errorf("installer is not solid LZMA")
		}

		match := -1
		for i, f := range files {
			if !found[i] && f.size == int64(n) {
				match = i
			}
		}
		if match < 0 {
			if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
				return err
			}
			continue
		}

		buf := make([]byte, n)
		if _, err := io.ReadFull(r, buf); err != nil {
			return err
		}
		sum := sha256.Sum256(buf)
		if hex.EncodeToString(sum[:]) != files[match].sha256 {
			continue
		}
		if err := os.WriteFile(filepath.Join(destDir, files[match].name+".new"), buf, 0644); err != nil {
			return err
		}
		found[match] = true
		remaining--
	}
	return nil
}

// setupPenguLoader detects existing installation or downloads Pengu Loader.
// Returns (ok, freshInstall).
func setupPenguLoader(penguURL string) (bool, bool) {
	// Check for existing Pengu installation via registry
	existingDir := GetExistingPenguDir()
	if existingDir != "" {
		PENGU_DIR = existingDir
		PLUGIN_DIR = filepath.Join(PENGU_DIR, "plugins", "ame")
		return true, false
	}

	// Check if we already downloaded Pengu to our directory
	penguExe := filepath.Join(PENGU_DIR, "Pengu Loader.exe")
	if _, err := os.Stat(penguExe); err == nil {
		PLUGIN_DIR = filepath.Join(PENGU_DIR, "plugins", "ame")
		return true, false
	}

	// Fresh download needed
	os.MkdirAll(PENGU_DIR, os.ModePerm)
	info("Downloading Pengu Loader...")
	zipPath := filepath.Join(config.AmeDir, "pengu.zip")

	if err := downloadFile(penguURL, zipPath); err != nil {
		statusFail("Pengu Loader download")
		return false, false
	}

	if err := extractZip(zipPath, PENGU_DIR); err != nil {
		statusFail("Pengu Loader setup")
		return false, false
	}

	os.Remove(zipPath)
	PLUGIN_DIR = filepath.Join(PENGU_DIR, "plugins", "ame")
	return true, true
}

// SetupPluginFromLocal copies plugin source files from a local directory
func SetupPluginFromLocal(srcDir string) bool {
	os.RemoveAll(PLUGIN_DIR)
	os.MkdirAll(PLUGIN_DIR, os.ModePerm)

	if err := copyPluginDir(srcDir); err != nil {
		statusFail("Plugin setup")
		return false
	}

	return true
}

func copyPluginDir(srcDir string) error {
	return filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		dstPath := filepath.Join(PLUGIN_DIR, rel)
		if d.IsDir() {
			return os.MkdirAll(dstPath, os.ModePerm)
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dstPath, data, 0644)
	})
}

// SetupPlugin downloads and extracts plugin zip (exported for use after updates)
func SetupPlugin(pluginZipURL string) bool {
	info("Downloading plugin...")
	zipPath := filepath.Join(config.AmeDir, "plugin.zip")

	if err := downloadFile(pluginZipURL, zipPath); err != nil {
		statusFail("Plugin download")
		return false
	}

	os.RemoveAll(PLUGIN_DIR)
	os.MkdirAll(PLUGIN_DIR, os.ModePerm)

	if err := extractZip(zipPath, PLUGIN_DIR); err != nil {
		statusFail("Plugin setup")
		return false
	}

	os.Remove(zipPath)
	return true
}

// checkPenguActivation activates Pengu via registry.
// Returns true if activation succeeded or was already active.
func checkPenguActivation() bool {
	if IsPenguActivated() {
		return true
	}

	if err := ActivatePengu(); err != nil {
		statusFail("Pengu activation")
		return false
	}

	return true
}

// RunSetup runs the full setup process (version can be passed for display)
func RunSetup(config Config) bool {
	// Create directories
	createDirectories()

	// Setup mod-tools
	if !SetupModTools(false) {
		return false
	}

	// Setup the patcher that injects the overlay into the game
	if !SetupPatcher() {
		return false
	}

	// Setup Pengu Loader
	ok, freshInstall := setupPenguLoader(config.PenguURL)
	if !ok {
		return false
	}

	// Setup plugin
	if config.DevSrcDir != "" {
		if !SetupPluginFromLocal(config.DevSrcDir) {
			return false
		}
	} else {
		if !SetupPlugin(config.PluginURL) {
			return false
		}
	}

	// Only auto-activate on fresh install
	if freshInstall {
		checkPenguActivation()
	}

	return true
}
