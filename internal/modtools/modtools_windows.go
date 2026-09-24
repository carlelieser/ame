//go:build windows

package modtools

import (
	"syscall"
)

// getSysProcAttr returns Windows-specific process attributes
func getSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		// Don't hide window - match PowerShell's -NoNewWindow behavior
	}
}

// getDetachedSysProcAttr returns Windows-specific process attributes for detached processes
func getDetachedSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP,
	}
}

// getHiddenSysProcAttr returns process attributes that keep a console child
// from opening its own window
func getHiddenSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
}
