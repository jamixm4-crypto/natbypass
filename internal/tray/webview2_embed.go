//go:build windows

package tray

import _ "embed"

//go:embed assets/MicrosoftEdgeWebview2Setup.exe
var webview2Bootstrapper []byte