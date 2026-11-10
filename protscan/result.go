package portscan

import (
	"net"
	"time"
)

// State описывает состояние проверенного порта.
type State int

const (
	StateOpen State = iota
	StateClosed
	StateTimeout
	StateUnreachable
	StateCanceled
	StateError
)

// String возвращает строковое представление состояния.
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

// Result содержит информацию о результате сканирования конкретного порта.
type Result struct {
	Host     string        // Исходный хост (IP или DNS-имя)
	IP       net.IP        // Разрешенный IP-адрес
	Port     uint16        // Номер порта
	State    State         // Состояние порта
	Duration time.Duration // Время, затраченное на проверку
	Err      error         // Оригинальная ошибка (если есть)
}