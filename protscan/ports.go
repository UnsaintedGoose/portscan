package portscan

import "errors"

var (
	ErrEmptyPorts  = errors.New("port list is empty")
	ErrInvalidPort = errors.New("invalid port number (must be 1-65535)")
)

// Ports представляет собой набор портов для сканирования.
// Мы используем int вместо uint16, чтобы позволить пользователю передать 
// заведомо невалидные значения (например, 70000 или -1) и получить 
// структурированную ошибку валидации, а не ошибку компиляции.
type Ports []int

// Range создает диапазон портов. Если start > end, они автоматически меняются местами.
func Range(start, end int) Ports {
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
func List(ports ...int) Ports {
	return Ports(ports)
}

// Validate проверяет порты на валидность, удаляет дубликаты и возвращает 
// безопасный срез uint16 для внутреннего использования в сканере.
func (p Ports) Validate() ([]uint16, error) {
	if len(p) == 0 {
		return nil, ErrEmptyPorts
	}

	seen := make(map[int]struct{}, len(p))
	var res []uint16

	for _, port := range p {
		// Валидация граничных случаев: порт должен быть строго от 1 до 65535
		if port <= 0 || port > 65535 {
			return nil, ErrInvalidPort
		}
		
		// Удаление дубликатов
		if _, ok := seen[port]; !ok {
			seen[port] = struct{}{}
			res = append(res, uint16(port)) // Безопасное преобразование после валидации
		}
	}

	if len(res) == 0 {
		return nil, ErrEmptyPorts
	}

	return res, nil
}