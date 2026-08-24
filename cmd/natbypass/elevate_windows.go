//go:build windows

package main

import (
	"os"
	"strings"
	"unsafe"

	"github.com/natbypass/natbypass/internal/diagnostic"
	"golang.org/x/sys/windows"
)

func ensureAdminOnWindows() {
	if !diagnostic.CheckIsAdmin() {
		verb, _ := windows.UTF16PtrFromString("runas")
		exePath, err := os.Executable()
		if err != nil {
			return
		}
		exePathPtr, _ := windows.UTF16PtrFromString(exePath)

		var args string
		if len(os.Args) > 1 {
			args = strings.Join(os.Args[1:], " ")
		}
		argsPtr, _ := windows.UTF16PtrFromString(args)

		modshell32 := windows.NewLazySystemDLL("shell32.dll")
		procShellExecuteW := modshell32.NewProc("ShellExecuteW")
		ret, _, _ := procShellExecuteW.Call(0, uintptr(unsafe.Pointer(verb)), uintptr(unsafe.Pointer(exePathPtr)), uintptr(unsafe.Pointer(argsPtr)), 0, 1 /* SW_SHOWNORMAL */)
		if ret > 32 {
			os.Exit(0)
		}
	}
}
