//go:build !windows

// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package tray

import "context"

type TrayOptions struct {
	WebUIPort     int
	ConfigPath    string
	GetWebUIPort  func() int
	OnRefreshIP   func()
	OnExit        func()
	GetStatusText func() string
	OnOpenUI      func()
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