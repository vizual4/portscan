package portscan

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
)

// classify анализирует ошибку подключения и возвращает строгий State.
func classify(err error) State {
	if err == nil {
		return StateOpen
	}

	if errors.Is(err, context.Canceled) {
		return StateCanceled
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return StateTimeout
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StateTimeout
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return classifySyscall(opErr.Err)
	}

	var sysErr *os.SyscallError
	if errors.As(err, &sysErr) {
		return classifySyscall(sysErr.Err)
	}

	if errors.Is(err, syscall.ECONNREFUSED) {
		return StateClosed
	}
	if errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EACCES) {
		return StateUnreachable
	}

	return StateError
}

// classifySyscall маппит специфичные для ОС коды ошибок
func classifySyscall(err error) State {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return StateClosed
	}
	if errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EACCES) ||
		errors.Is(err, syscall.EPERM) {
		return StateUnreachable
	}
	if errors.Is(err, syscall.ETIMEDOUT) {
		return StateTimeout
	}
	return StateError
}
