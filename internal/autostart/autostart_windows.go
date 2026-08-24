//go:build windows

package autostart

import (
	"golang.org/x/sys/windows/registry"
)

func SetAutoStart(name, execPath string, enable bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, `Software\Microsoft\Windows\CurrentVersion\Run`, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if enable {
		return k.SetStringValue(name, `"` + execPath + `"`)
	}
	_ = k.DeleteValue(name)
	return nil
}
