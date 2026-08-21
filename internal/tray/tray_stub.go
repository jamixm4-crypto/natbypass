//go:build !windows

package tray

import "context"

type TrayOptions struct {
	WebUIPort     int
	ConfigPath    string
	GetWebUIPort  func() int
	OnRefreshIP   func()
	OnExit        func()
	GetStatusText func() string
}

type TrayApp struct{}

func NewTray(opts TrayOptions) *TrayApp {
	return &TrayApp{}
}

func (t *TrayApp) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func (t *TrayApp) ShowNotification(title, message string) {}