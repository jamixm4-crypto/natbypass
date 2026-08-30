//go:build !windows

package webui

import "os/exec"

func setHideWindow(cmd *exec.Cmd) {}