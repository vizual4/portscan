package portscan

import (
	"fmt"
	"net"
	"time"
)

// Result хранит детальную информацию о проверке TCP-порта на хосте.
type Result struct {
	// Host — исходное имя хоста (строка), переданное пользователем (IP или домен).
	Host string

	// IP — конкретный IP-адрес, на который выполнялся дозвон (результат резолва).
	IP net.IP

	// Port — проверяемый номер TCP-порта.
	Port uint16

	// State — определенное состояние порта.
	State State

	// Duration — затраченное время на попытку подключения.
	Duration time.Duration

	// Err заполняется только если State == StateError, в остальных случаях nil.
	Err error
}

func (r Result) String() string {
	if r.Err != nil {
		return fmt.Sprintf("%s (%s):%d %s (%v) in %s",
			r.Host, r.IP, r.Port, r.State, r.Err, r.Duration)
	}
	return fmt.Sprintf("%s (%s):%d %s in %s",
		r.Host, r.IP, r.Port, r.State, r.Duration)
}

func (r Result) Address() string {
	if r.IP.To4() != nil {
		return fmt.Sprintf("%s:%d", r.IP.String(), r.Port)
	}
	return fmt.Sprintf("[%s]:%d", r.IP.String(), r.Port)
}
