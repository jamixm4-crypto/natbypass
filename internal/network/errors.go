package network

import "errors"

var (
	// ErrSTUNTimeout indicates that no STUN server responded within the timeout deadline.
	ErrSTUNTimeout = errors.New("STUN discovery timeout")

	// ErrSocketClosed indicates operations on a closed UDP socket.
	ErrSocketClosed = errors.New("network socket is closed")

	// ErrInvalidAddress indicates a malformed IP or endpoint string.
	ErrInvalidAddress = errors.New("invalid IP or endpoint address")

	// ErrPunchTimeout indicates direct UDP hole punching failed to receive a probe reply.
	ErrPunchTimeout = errors.New("hole punching probe timed out")
)