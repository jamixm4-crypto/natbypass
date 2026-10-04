// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package updater

import (
	"crypto/ed25519"
	"encoding/hex"
)

// DefaultReleasePublicKeyHex — официальный открытый ключ Ed25519 jamixm4-crypto для подписи релизов NatBypass.
// Зашит непосредственно в бинарный файл для предотвращения RCE при использовании сторонних зеркал/прокси.
const DefaultReleasePublicKeyHex = "517304076d4f9796dab5203f910f7badaedc0ca3d4ae0d70d037bae1cdc0496c"

func init() {
	if pubBytes, err := hex.DecodeString(DefaultReleasePublicKeyHex); err == nil && len(pubBytes) == ed25519.PublicKeySize {
		DefaultReleasePublicKey = ed25519.PublicKey(pubBytes)
	}
}
