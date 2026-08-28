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