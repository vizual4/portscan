package portscan

// State представляет результат проверки конкретного TCP-порта.
type State uint8

const (
	// StateUnknown — нулевое значение по умолчанию, в реальных результатах быть не должно.
	StateUnknown State = iota

	// StateOpen означает, что TCP 3-way handshake прошло успешно.
	StateOpen

	// StateClosed означает, что удаленный узел явно сбросил/отклонил соединение (пакет RST).
	StateClosed

	// StateTimeout означает, что соединение не успело установиться за отведенное время (таймаут).
	StateTimeout

	// StateUnreachable означает, что сеть или хост физически/логически недоступны (ICMP ошибки).
	StateUnreachable

	// StateCanceled означает, что сканирование было прервано через context.Context.
	StateCanceled

	// StateError — прочие неожиданные системные или сетевые ошибки.
	StateError
)

// Реализация интерфейса fmt.Stringer.
func (s State) String() string {
	switch s {
	case StateOpen:
		return "open"
	case StateClosed:
		return "closed"
	case StateTimeout:
		return "timeout"
	case StateUnreachable:
		return "unreachable"
	case StateCanceled:
		return "canceled"
	case StateError:
		return "error"
	default:
		return "unknown"
	}
}

// IsTerminal проверяет, является ли состояние финальным (определенным),
// то есть не требующим повторных переподключений.
func (s State) IsTerminal() bool {
	return s == StateOpen || s == StateClosed
}
