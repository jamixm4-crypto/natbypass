package daemon

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/rs/zerolog"
)

var (
	hooksMutex    sync.Mutex
	shutdownHooks []ShutdownHook
)

// ShutdownHook is a function that will be called during graceful shutdown.
type ShutdownHook func()

// RegisterShutdownHook registers a hook to be executed on shutdown.
func RegisterShutdownHook(h ShutdownHook) {
	hooksMutex.Lock()
	defer hooksMutex.Unlock()
	shutdownHooks = append(shutdownHooks, h)
}

// Run executes the main function and handles OS signals for graceful shutdown and reloads.
func Run(ctx context.Context, mainFunc func(ctx context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	errCh := make(chan error, 1)
	go func() {
		errCh <- mainFunc(ctx)
	}()

	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				// Handle SIGHUP: trigger log rotation / config reload
				fmt.Println("Получен SIGHUP (перезагрузка конфигурации/логов)")
				// Implementation for config reload notification would go here
			case syscall.SIGINT, syscall.SIGTERM:
				fmt.Printf("Получен сигнал %s, инициируем завершение...\n", sig)
				cancel()
				
				hooksMutex.Lock()
				for _, hook := range shutdownHooks {
					hook()
				}
				hooksMutex.Unlock()
				
				return <-errCh
			}
		case err := <-errCh:
			return err
		}
	}
}

// WritePID writes the current process ID to the specified file path.
func WritePID(path string) error {
	pid := os.Getpid()
	return os.WriteFile(path, []byte(fmt.Sprintf("%d", pid)), 0644)
}

// RemovePID removes the PID file.
func RemovePID(path string) {
	_ = os.Remove(path)
}

// SetupLogging initializes zerolog with the given file and level.
func SetupLogging(logFile string, level string) *zerolog.Logger {
	var l zerolog.Level
	switch level {
	case "debug":
		l = zerolog.DebugLevel
	case "info":
		l = zerolog.InfoLevel
	case "warn":
		l = zerolog.WarnLevel
	case "error":
		l = zerolog.ErrorLevel
	default:
		l = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(l)

	var output *os.File
	if logFile != "" {
		var err error
		output, err = os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Не удалось открыть лог-файл %s: %v\n", logFile, err)
			output = os.Stdout
		}
	} else {
		output = os.Stdout
	}

	logger := zerolog.New(output).With().Timestamp().Logger()
	return &logger
}
