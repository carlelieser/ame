package modtools

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hoangvu12/ame/internal/config"
	"github.com/hoangvu12/ame/internal/display"
)

// hookedStatus is the overlay status once the hook DLL is serving the overlay.
const hookedStatus = "waiting"

// overlayStatus tracks the latest injection state reported by the patcher host.
var overlayStatus string
var overlayStatusMu sync.Mutex

func setOverlayStatus(s string) {
	overlayStatusMu.Lock()
	overlayStatus = s
	overlayStatusMu.Unlock()
}

// IsHooked returns true if the patcher has already installed the hook.
func IsHooked() bool {
	overlayStatusMu.Lock()
	defer overlayStatusMu.Unlock()
	return overlayStatus == hookedStatus
}

// WaitForHook blocks until the patcher reports the hook is installed
// or the timeout expires.
func WaitForHook(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		overlayStatusMu.Lock()
		status := overlayStatus
		overlayStatusMu.Unlock()
		if status == hookedStatus {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// hostMu guards the patcher host process and whether an overlay is armed.
var hostMu sync.Mutex

// hostProcess is the long-lived patcher host. It keeps scanning for the game
// between matches: the hook DLL only overlays when it attaches as the game
// starts, so the host must already be waiting when League launches.
var hostProcess *exec.Cmd

// armed is true while an overlay built by ame is meant to be in the game.
var armed bool

// KillModTools disarms the overlay and kills any running mod-tools. The
// patcher host keeps running; see StopPatcher.
func KillModTools() {
	hostMu.Lock()
	armed = false
	hostMu.Unlock()

	cmd := exec.Command("taskkill", "/F", "/IM", "mod-tools.exe")
	cmd.SysProcAttr = getSysProcAttr()
	cmd.Run()
}

// StopPatcher shuts the patcher host down, for exit, restart and uninstall.
func StopPatcher() {
	hostMu.Lock()
	cmd, stdin := hostProcess, stdinPipe
	hostProcess, stdinPipe, armed = nil, nil, false
	hostMu.Unlock()

	// First try to gracefully stop the session; closing stdin tells the host to exit
	if stdin != nil {
		sendCommand(stdin, "stop")
		stdin.Close()
	}

	if cmd != nil && cmd.Process != nil {
		done := make(chan struct{})
		go func() {
			cmd.Wait()
			close(done)
		}()

		select {
		case <-done:
			// Process exited gracefully
		case <-time.After(2 * time.Second):
			// Force kill if still running
			cmd.Process.Kill()
		}
	}

	// Then force kill any host left over from a previous ame
	kill := exec.Command("taskkill", "/F", "/IM", PatcherHostExe)
	kill.SysProcAttr = getSysProcAttr()
	kill.Run()
}

// RunMkOverlay runs mod-tools mkoverlay command
func RunMkOverlay(modsDir, overlayDir, gameDir, modName string) (bool, int) {
	modTools := filepath.Join(config.ToolsDir, "mod-tools.exe")

	if _, err := os.Stat(modTools); os.IsNotExist(err) {
		return false, 1
	}

	cmd := exec.Command(modTools, "mkoverlay", modsDir, overlayDir,
		fmt.Sprintf("--game:%s", gameDir),
		fmt.Sprintf("--mods:%s", modName),
		"--noTFT", "--ignoreConflict")
	cmd.Dir = config.ToolsDir

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return false, exitErr.ExitCode()
		}
		return false, 1
	}

	return true, 0
}

// PatcherHostExe and PatcherDLL are LTK Manager's injection host and the hook
// DLL it injects into the game. They replaced mod-tools runoverlay, whose
// cslol-dll stopped hooking the game after patch 16.19.
const (
	PatcherHostExe = "ltk_patcher_host.exe"
	PatcherDLL     = "ltk_patcher_dll.dll"
)

// Hook flags sent with "config flags". optOutAHv1 downgrades a failed
// anti-skinhack WAD scan (status c0000229) from aborting the overlay to a
// warning; without it the DLL refuses every skin ame builds.
const optOutAHv1 = 4

// logLevelInfo is the DLL's numeric info log level for "config loglevel".
const logLevelInfo = 0x10

// stdinPipe holds the host's command pipe (to send "stop" and shut it down)
var stdinPipe io.WriteCloser

// sendCommand writes one line to the host's stdin.
func sendCommand(w io.Writer, line string) error {
	_, err := io.WriteString(w, line+"\n")
	return err
}

// StartPatcher starts the patcher host if it isn't running. The host waits
// for the game and injects the hook DLL, which serves files from overlayDir.
func StartPatcher(overlayDir string) error {
	hostMu.Lock()
	defer hostMu.Unlock()

	if hostProcess != nil {
		return nil
	}

	host := filepath.Join(config.ToolsDir, PatcherHostExe)
	if _, err := os.Stat(host); os.IsNotExist(err) {
		return fmt.Errorf("%s not found", PatcherHostExe)
	}

	// A host left over from a previous ame would inject a second DLL
	kill := exec.Command("taskkill", "/F", "/IM", PatcherHostExe)
	kill.SysProcAttr = getSysProcAttr()
	kill.Run()

	cmd := exec.Command(host)
	cmd.Dir = config.ToolsDir
	cmd.SysProcAttr = getHiddenSysProcAttr()

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdout pipe: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("failed to create stderr pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	// The host reads loglevel, flags, then prefix before start.
	prefix := overlayDir
	if !strings.HasSuffix(prefix, string(os.PathSeparator)) {
		prefix += string(os.PathSeparator)
	}
	for _, line := range []string{
		fmt.Sprintf("config loglevel %d", logLevelInfo),
		fmt.Sprintf("config flags %d", optOutAHv1),
		"config prefix " + prefix,
		"start scan",
	} {
		if err := sendCommand(stdin, line); err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			return fmt.Errorf("failed to configure patcher: %v", err)
		}
	}

	hostProcess = cmd
	stdinPipe = stdin
	setOverlayStatus("")

	logFile, _ := os.Create(filepath.Join(config.AmeDir, "patcher.log"))

	// Read host events and track the injection state
	go func() {
		if logFile != nil {
			defer logFile.Close()
		}
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			if logFile != nil {
				fmt.Fprintln(logFile, line)
			}
			handleHostLine(line)
		}
	}()
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
		}
	}()

	// Monitor process exit; the next StartPatcher respawns it
	go func() {
		cmd.Wait()
		hostMu.Lock()
		if hostProcess == cmd {
			hostProcess = nil
			stdinPipe = nil
		}
		hostMu.Unlock()
		setOverlayStatus("")
	}()

	return nil
}

// RunOverlay arms the overlay built in overlayDir, starting the patcher host
// if it isn't already waiting for the game.
func RunOverlay(overlayDir string) error {
	if err := StartPatcher(overlayDir); err != nil {
		return err
	}
	hostMu.Lock()
	armed = true
	hostMu.Unlock()
	return nil
}

// handleHostLine tracks "status <ts> <state> <msg>" events from the host and
// surfaces failures and DLL errors in the activity log.
func handleHostLine(line string) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return
	}
	switch fields[0] {
	case "status":
		if len(fields) < 3 {
			return
		}
		state := fields[2]
		msg := strings.Join(fields[3:], " ")
		switch state {
		case "waiting":
			setOverlayStatus(hookedStatus)
		case "exited", "injecting":
			setOverlayStatus("")
		case "failed":
			setOverlayStatus("")
			display.Log("Patcher failed: " + msg)
		}
	case "error":
		display.Log("Patcher error: " + strings.Join(fields[2:], " "))
	case "dll":
		// "dll <ts> <pid> <tid> <level> <msg...>"
		if len(fields) < 6 {
			return
		}
		msg := strings.Join(fields[5:], " ")
		if strings.EqualFold(fields[4], "error") || strings.HasSuffix(msg, "joined too late, not overlaying") {
			display.Log("Patcher: " + msg)
		}
	}
}

// Exists checks that mod-tools and the patcher binaries are installed
func Exists() bool {
	for _, name := range []string{"mod-tools.exe", PatcherHostExe, PatcherDLL} {
		if _, err := os.Stat(filepath.Join(config.ToolsDir, name)); err != nil {
			return false
		}
	}
	return true
}

// IsRunning checks if an overlay is armed and the patcher host is running
func IsRunning() bool {
	hostMu.Lock()
	defer hostMu.Unlock()
	return armed && hostProcess != nil
}
