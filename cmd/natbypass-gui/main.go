package main

import (
	"embed"
	"flag"
	"fmt"
	"os"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"

	"github.com/natbypass/natbypass/internal/tray"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	configPath := flag.String("config", "config.yaml", "path to config.yaml")
	flag.Parse()

	app := NewApp(*configPath)

	// Запуск системного трея в отдельной горутине
	go func() {
		trayApp := tray.NewTray(tray.TrayOptions{
			WebUIPort:  8080,
			ConfigPath: *configPath,
			GetWebUIPort: func() int {
				st, err := app.GetStatus()
				if err == nil && st.WebUIPort > 0 {
					return st.WebUIPort
				}
				return 8080
			},
			OnRefreshIP: func() {
				app.UpdateIP()
			},
			OnExit: func() {
				app.QuitApp()
				os.Exit(0)
			},
			GetStatusText: func() string {
				st, err := app.GetStatus()
				if err == nil {
					return fmt.Sprintf("💡 Статус: Онлайн (%s | IP: %s)", st.CurrentChannel, st.PublicIP)
				}
				return "💡 Статус: Онлайн"
			},
		})
		trayApp.Run(app.engineCtx)
	}()

	// Запуск Wails приложения
	err := wails.Run(&options.App{
		Title:             "NatBypass — P2P NAT Traversal",
		Width:             960,
		Height:            700,
		MinWidth:          800,
		MinHeight:         600,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 18, G: 22, B: 30, A: 255},
		OnStartup:        app.Startup,
		OnBeforeClose:    app.BeforeClose,
		OnShutdown:       app.Shutdown,
		Bind: []interface{}{
			app,
		},
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
			DisableWindowIcon:    false,
		},
	})

	if err != nil {
		fmt.Printf("Error running Wails: %v\n", err)
	}
}