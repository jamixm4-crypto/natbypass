// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newAntigravityCmd creates the easter egg antigravity command.
func newAntigravityCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "antigravity",
		Short:  "Activate antigravity mode",
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf(`
       .--.
      |o_o |
      |:_/ |
     //   \ \
    (|     | )
   /'\_   _/`+"`"+`\
   \___)=(___/

NatBypass v%s — обходим гравитацию NAT!

Вдохновлено: import antigravity (Python)
Режим невесомости: АКТИВИРОВАН
Все пакеты теперь летят напрямую!
`, Version)
		},
	}
}

// newKonamiCmd creates the easter egg konami code command.
func newKonamiCmd() *cobra.Command {
	return &cobra.Command{
		Use:    "konami",
		Short:  "God mode settings",
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("↑ ↑ ↓ ↓ ← → ← → B A")
			fmt.Println("Режим разработчика активирован:")
			fmt.Println("  - Direct P2P: Force Always")
			fmt.Println("  - Encryption: ChaCha20-Poly1305 (256-bit)")
			fmt.Println("  - Traffic Obfuscation: Active")
			fmt.Println("  - Anti-DPI Noise: Jc=4 S1=48 S2=32")
		},
	}
}