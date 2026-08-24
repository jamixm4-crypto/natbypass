package main

import (
	"bufio"
	"fmt"
	"os"

	"github.com/natbypass/natbypass/internal/diagnostic"
)

func main() {
	fmt.Println("================================================================")
	fmt.Println("       🩺 NatBypass — Низкоуровневая диагностика системы        ")
	fmt.Println("================================================================")
	fmt.Println()

	rep := diagnostic.RunFullDiagnostics()
	fmt.Printf("Хост: %s | ОС: %s | Архитектура: %s\n", rep.Hostname, rep.OS, rep.Arch)
	fmt.Printf("Права Администратора: %v\n\n", rep.IsAdmin)

	for i, item := range rep.Items {
		statusIcon := "🟢"
		if !item.Passed {
			statusIcon = "🔴"
		}
		fmt.Printf("[%d/8] %s %s (%d ms)\n", i+1, statusIcon, item.Name, item.Elapsed.Milliseconds())
		fmt.Printf("      %s\n", item.Message)
		if item.Details != "" {
			fmt.Printf("      Подробности: %s\n", item.Details)
		}
		fmt.Println()
	}

	fmt.Println("================================================================")
	if rep.AllPassed {
		fmt.Println("✅ Все тесты пройдены успешно! Оборудование и сеть полностью готовы.")
	} else {
		fmt.Println("⚠️ Обнаружены проблемы. Ознакомьтесь с подсказками выше.")
	}
	fmt.Println("================================================================")

	fmt.Println("\nНажмите Enter для выхода...")
	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
}
