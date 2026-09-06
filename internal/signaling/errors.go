// Copyright (C) 2026 jamixm4-crypto
//
// NatBypass is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package signaling

import "errors"

var (
	// ErrAllChannelsFailed indicates all primary and fallback signaling channels are unreachable.
	ErrAllChannelsFailed = errors.New("all signaling channels failed")

	// ErrInvalidPayload indicates corrupted or unparseable signaling payload data.
	ErrInvalidPayload = errors.New("invalid signaling payload")

	// ErrDecryptFailed indicates MAC or decryption verification failure.
	ErrDecryptFailed = errors.New("failed to decrypt signaling payload")

	// ErrChannelTimeout indicates a timeout waiting for signaling responses.
	ErrChannelTimeout = errors.New("signaling channel operation timed out")
)