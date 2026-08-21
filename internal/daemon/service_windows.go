//go:build windows

package daemon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const ServiceName = "NatBypass"
const ServiceDisplayName = "NatBypass NAT Traversal Service"
const ServiceDescription = "Provides automatic NAT/CGNAT traversal, P2P mesh connectivity, and signaling management."

// IsWindowsService проверяет, запущен ли процесс под управлением Windows SCM
func IsWindowsService() bool {
	isSvc, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isSvc
}

type natBypassService struct {
	runFunc func(ctx context.Context) error
}

func (m *natBypassService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errChan := make(chan error, 1)
	go func() {
		errChan <- m.runFunc(ctx)
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}

	for {
		select {
		case <-errChan:
			changes <- svc.Status{State: svc.StopPending}
			return false, 0

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-errChan:
				case <-time.After(5 * time.Second):
				}
				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			case svc.Pause:
				changes <- svc.Status{State: svc.Paused, Accepts: cmdsAccepted}
			case svc.Continue:
				changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
			}
		}
	}
}

// RunService запускает приложение как службу Windows
func RunService(runFunc func(ctx context.Context) error) error {
	return svc.Run(ServiceName, &natBypassService{runFunc: runFunc})
}

// InstallService устанавливает службу в Windows SCM
func InstallService(configPath string) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %w", err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return err
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager (run as Admin): %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already installed", ServiceName)
	}

	args := []string{"start"}
	if configPath != "" {
		absConfig, err := filepath.Abs(configPath)
		if err == nil {
			args = append(args, "--config", absConfig)
		}
	}

	s, err = m.CreateService(ServiceName, exePath, mgr.Config{
		DisplayName:      ServiceDisplayName,
		Description:      ServiceDescription,
		StartType:        mgr.StartAutomatic,
		ServiceStartName: "",
	}, args...)
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}
	defer s.Close()

	recoveryActions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 15 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}
	s.SetRecoveryActions(recoveryActions, 86400)

	return nil
}

// UninstallService удаляет службу из Windows SCM
func UninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s not installed: %w", ServiceName, err)
	}
	defer s.Close()

	status, err := s.Query()
	if err == nil && status.State == svc.Running {
		s.Control(svc.Stop)
		time.Sleep(1 * time.Second)
	}

	err = s.Delete()
	if err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}

	return nil
}

// StartWindowsService запускает службу
func StartWindowsService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s not installed: %w", ServiceName, err)
	}
	defer s.Close()

	return s.Start()
}

// StopWindowsService останавливает службу
func StopWindowsService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return fmt.Errorf("service %s not installed: %w", ServiceName, err)
	}
	defer s.Close()

	_, err = s.Control(svc.Stop)
	return err
}

// QueryServiceStatus возвращает текущее состояние службы
func QueryServiceStatus() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", err
	}
	defer m.Disconnect()

	s, err := m.OpenService(ServiceName)
	if err != nil {
		return "NOT_INSTALLED", nil
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return "", err
	}

	switch status.State {
	case svc.Running:
		return "RUNNING", nil
	case svc.Stopped:
		return "STOPPED", nil
	case svc.StartPending:
		return "START_PENDING", nil
	case svc.StopPending:
		return "STOP_PENDING", nil
	default:
		return "UNKNOWN", nil
	}
}