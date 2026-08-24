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
	fmt.Println("    ⚡ RFC 4787 / STUN Анализ типа NAT и шансов DirectP2P      ")
	fmt.Println("================================================================")
	fmt.Println("Тестирование трансляции портов...")

	natInfo, err := diagnostic.ClassifyNATBehavior()
	if err != nil {
		fmt.Printf("⚠️ Ошибка тестирования NAT: %v\n", err)
	} else {
		fmt.Printf("• Внешний IP адрес:      %s\n", natInfo.PublicIP)
		fmt.Printf("• Тип NAT роутера:       %s\n", natInfo.NATType)
		fmt.Printf("• Поведение портов (EIM):%s\n", natInfo.MappingType)
		fmt.Printf("• Вероятность DirectP2P: %s\n", natInfo.P2PFeasibility)
		fmt.Printf("• Рекомендация:          %s\n", natInfo.Recommendation)
	}

	fmt.Println("================================================================")
	if rep.AllPassed {
		fmt.Println("✅ Все базовые тесты пройдены! Оборудование и сеть готовы к работе.")
	} else {
		fmt.Println("⚠️ Обнаружены системные замечания. Ознакомьтесь с подсказками выше.")
	}
	fmt.Println("================================================================")

	fmt.Println("\nНажмите Enter для выхода...")
	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
}
