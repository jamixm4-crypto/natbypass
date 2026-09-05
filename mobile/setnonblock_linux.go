//go:build linux

package mobile

import "syscall"

// setTunNonblock переводит TUN fd в non-blocking режим (Linux/Android).
// Это позволяет tf.Read() возвращать EAGAIN вместо блокировки навсегда,
// что необходимо для корректного завершения TUN read goroutine при отключении.
func setTunNonblock(fd int) error {
	return syscall.SetNonblock(fd, true)
}
