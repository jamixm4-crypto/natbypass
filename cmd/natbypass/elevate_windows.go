//go:build windows

package main

import (
	"github.com/natbypass/natbypass/internal/diagnostic"
	"github.com/rs/zerolog/log"
)

func ensureAdminOnWindows() {
	if !diagnostic.CheckIsAdmin() {
		log.Warn().Msg("⚠️ Внимание: Приложение запущено без прав администратора. Для создания виртуального интерфейса Wintun и настройки сетевых маршрутов рекомендуем запуск от имени Администратора.")
	}
}
