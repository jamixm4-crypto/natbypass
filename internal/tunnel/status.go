// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package tunnel

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// TUNStatus captures real-time health, diagnostic metrics, and failure explanations for the L3 TUN interface.
type TUNStatus struct {
	Active       bool      `json:"active"`
	DeviceName   string    `json:"device_name"`
	VirtualIP    string    `json:"virtual_ip"`
	MTU          int       `json:"mtu"`
	IsAdmin      bool      `json:"is_admin"`
	DriverLoaded bool      `json:"driver_loaded"`
	LastError    string    `json:"last_error,omitempty"`
	ErrorCause   string    `json:"error_cause,omitempty"`  // Detailed cause in Russian
	ErrorRemedy  string    `json:"error_remedy,omitempty"` // Step-by-step instructions to fix in Russian
	LastUpdated  time.Time `json:"last_updated"`
}

var (
	tunStatusMu     sync.RWMutex
	globalTUNStatus = &TUNStatus{
		DeviceName:  "NatBypass",
		MTU:         1280,
		LastUpdated: time.Now(),
	}
)

// GetTUNStatus returns a copy of the current TUN interface status.
func GetTUNStatus() TUNStatus {
	tunStatusMu.RLock()
	defer tunStatusMu.RUnlock()
	if globalTUNStatus == nil {
		return TUNStatus{
			DeviceName:  "NatBypass",
			MTU:         1280,
			LastUpdated: time.Now(),
		}
	}
	return *globalTUNStatus
}

// SetTUNStatus updates the global TUN interface status.
func SetTUNStatus(s *TUNStatus) {
	if s == nil {
		return
	}
	tunStatusMu.Lock()
	defer tunStatusMu.Unlock()
	s.LastUpdated = time.Now()
	globalTUNStatus = s
}

// CheckIsAdmin checks whether the current process is running with administrative (root / UAC elevated) privileges.
func CheckIsAdmin() bool {
	return checkIsAdmin()
}

// DiagnoseTUNError analyzes a TUN creation/runtime error and returns human-readable cause and remedy in Russian.
func DiagnoseTUNError(err error) (cause string, remedy string) {
	isAdmin := checkIsAdmin()

	if !isAdmin {
		cause = "Процесс запущен без прав Администратора (UAC / root). Создание виртуального сетевого адаптера заблокировано операционной системой."
		remedy = "Запустите приложение от имени Администратора (нажмите правой кнопкой мыши -> «Запуск от имени администратора» на Windows или запустите через 'sudo' в Linux)."
		return
	}

	if err == nil {
		return "", ""
	}

	errStr := strings.ToLower(err.Error())

	switch {
	case strings.Contains(errStr, "wintun.dll") || strings.Contains(errStr, "не удалось сохранить") || strings.Contains(errStr, "библиотек"):
		cause = "Библиотека сетевого драйвера Wintun (wintun.dll) не найдена или не может быть загружена."
		remedy = "Поместите оригинальный файл wintun.dll в папку с исполняемым файлом программы или проверьте подключение к интернету для автоматической загрузки."
	case strings.Contains(errStr, "сесси") || strings.Contains(errStr, "session") || strings.Contains(errStr, "зависл"):
		cause = "Предыдущая сессия адаптера Wintun не была корректно освобождена службой Windows."
		remedy = "Перезапустите приложение или выполните в PowerShell: 'Get-NetAdapter -Name NatBypass | Restart-NetAdapter'."
	case strings.Contains(errStr, "dev/net/tun") || strings.Contains(errStr, "no such file") || strings.Contains(errStr, "modprobe"):
		cause = "В ядре Linux отсутствует или не загружен модуль сетевого туннелирования TUN/TAP."
		remedy = "Выполните в терминале команду 'sudo modprobe tun', убедитесь в наличии /dev/net/tun и перезапустите NatBypass."
	case strings.Contains(errStr, "conflict") || strings.Contains(errStr, "already exists") || strings.Contains(errStr, "ip"):
		cause = "Конфликт виртуального IP-адреса или имени адаптера с существующим сетевым подключением."
		remedy = "Измените Virtual IP в настройках профиля или удалите старый адаптер: 'Remove-NetIPAddress -InterfaceAlias NatBypass'."
	case strings.Contains(errStr, "access denied") || strings.Contains(errStr, "отказано в доступе") || strings.Contains(errStr, "требуются права"):
		cause = "Недостаточно системных привилегий для настройки сетевого стека NDIS/маршрутизации."
		remedy = "Запустите программу от имени Администратора."
	default:
		cause = fmt.Sprintf("Ошибка инициализации интерфейса: %s", err.Error())
		remedy = "Убедитесь, что запуск выполнен с правами Администратора, и антивирус/файрвол не блокирует установку драйверов Wintun."
	}
	return
}
