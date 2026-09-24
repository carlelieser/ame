package modtools

import "testing"

func TestHandleHostLineTracksHookState(t *testing.T) {
	setOverlayStatus("")

	handleHostLine("status 0.0012345 injecting scanning for game")
	if IsHooked() {
		t.Fatal("hooked while still scanning for the game")
	}

	handleHostLine("status 3.2100000 waiting overlay active")
	if !IsHooked() {
		t.Fatal("not hooked after the host reported waiting")
	}

	handleHostLine("status 90.0000000 exited game closed")
	if IsHooked() {
		t.Fatal("still hooked after the game exited")
	}
}

func TestHandleHostLineIgnoresMalformedLines(t *testing.T) {
	setOverlayStatus(hookedStatus)

	for _, line := range []string{"", "status", "status 1.0", "ok 1.0 config prefix set", "foobar 1.0 waiting"} {
		handleHostLine(line)
	}
	if !IsHooked() {
		t.Fatal("a line without a status state changed the hook state")
	}
}
