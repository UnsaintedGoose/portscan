package portscan

import (
	"context"
	"errors"
	"net"
)

var (
	ErrEmptyHost      = errors.New("host list is empty or contains empty string")
	ErrUnresolvedHost = errors.New("could not resolve host")
)

// target представляет собой цель для сканирования.
type target struct {
	host string
	ips  []net.IP
}

// resolveHosts валидирует хосты, резолвит DNS и удаляет дубликаты.
// Поведение для граничных случаев:
// - Пустой хост или пустой список: ошибка ErrEmptyHost.
// - Некорректный адрес / неразрешимый DNS: ошибка ErrUnresolvedHost.
// - Дубликаты хостов: обрабатываются только уникальные строки хостов.
// - DNS с несколькими IP: сканируются все полученные IP-адреса.
func resolveHosts(ctx context.Context, hosts []string) ([]target, error) {
	if len(hosts) == 0 {
		return nil, ErrEmptyHost
	}

	seen := make(map[string]struct{})
	var targets []target

	for _, h := range hosts {
		if h == "" {
			return nil, ErrEmptyHost
		}

		// Пропускаем дубликаты хостов
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}

		// Если это уже IP-адрес, просто добавляем его
		if ip := net.ParseIP(h); ip != nil {
			targets = append(targets, target{host: h, ips: []net.IP{ip}})
			continue
		}

		// Резолвим DNS-имя
		ips, err := net.DefaultResolver.LookupIPAddr(ctx, h)
		if err != nil {
			return nil, errors.Join(ErrUnresolvedHost, err)
		}
		if len(ips) == 0 {
			return nil, ErrUnresolvedHost
		}

		var netIPs []net.IP
		for _, ipAddr := range ips {
			netIPs = append(netIPs, ipAddr.IP)
		}
		targets = append(targets, target{host: h, ips: netIPs})
	}

	return targets, nil
}