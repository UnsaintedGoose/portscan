package portscan

import "errors"

var (
	ErrEmptyPorts  = errors.New("port list is empty")
	ErrInvalidPort = errors.New("invalid port number (must be 1-65535)")
)

// Ports представляет собой набор портов для сканирования.
type Ports []uint16

// Range создает диапазон портов. Если start > end, они меняются местами.
func Range(start, end uint16) Ports {
	if start > end {
		start, end = end, start
	}
	p := make(Ports, 0, end-start+1)
	for i := start; i <= end; i++ {
		p = append(p, i)
	}
	return p
}

// List создает набор портов из списка.
func List(ports ...uint16) Ports {
	return Ports(ports)
}

// Validate проверяет порты на валидность, удаляет дубликаты и возвращает чистый срез.
// Поведение для граничных случаев:
// - Порт 0 или > 65535: возвращается ошибка ErrInvalidPort.
// - Дубликаты: автоматически удаляются.
// - Пустой список: возвращается ошибка ErrEmptyPorts.
func (p Ports) Validate() ([]uint16, error) {
	if len(p) == 0 {
		return nil, ErrEmptyPorts
	}

	seen := make(map[uint16]struct{}, len(p))
	var res []uint16

	for _, port := range p {
		if port == 0 || port > 65535 {
			return nil, ErrInvalidPort
		}
		if _, ok := seen[port]; !ok {
			seen[port] = struct{}{}
			res = append(res, port)
		}
	}

	if len(res) == 0 {
		return nil, ErrEmptyPorts
	}

	return res, nil
}