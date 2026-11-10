package portscan

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"time"
)

var (
	ErrInvalidConcurrency = errors.New("concurrency must be greater than 0")
	ErrInvalidTimeout     = errors.New("timeout must be greater than 0")
)

// Scanner выполняет TCP-сканирование портов.
type Scanner struct {
	concurrency    int
	connectTimeout time.Duration
}

// Option функциональная опция для настройки Scanner.
type Option func(*Scanner)

// WithConcurrency устанавливает максимальное количество одновременных подключений.
func WithConcurrency(c int) Option {
	return func(s *Scanner) {
		s.concurrency = c
	}
}

// WithConnectTimeout устанавливает таймаут подключения.
func WithConnectTimeout(t time.Duration) Option {
	return func(s *Scanner) {
		s.connectTimeout = t
	}
}

// New создает новый экземпляр Scanner.
func New(opts ...Option) (*Scanner, error) {
	s := &Scanner{
		concurrency:    100,
		connectTimeout: time.Second,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.concurrency <= 0 {
		return nil, ErrInvalidConcurrency
	}
	if s.connectTimeout <= 0 {
		return nil, ErrInvalidTimeout
	}
	return s, nil
}

type task struct {
	host string
	ip   net.IP
	port uint16
}

// Scan запускает сканирование указанных хостов и портов.
// Возвращает канал с результатами. Канал закрывается автоматически после завершения.
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports Ports) (<-chan Result, error) {
	if ctx == nil {
		return nil, errors.New("context is nil")
	}

	targets, err := resolveHosts(ctx, hosts)
	if err != nil {
		return nil, err
	}

	validPorts, err := ports.Validate()
	if err != nil {
		return nil, err
	}

	// Буферизированные каналы для снижения блокировок
	tasksCh := make(chan task, s.concurrency)
	resultsCh := make(chan Result, s.concurrency)

	var wg sync.WaitGroup

	// 1. Запускаем пул воркеров
	for i := 0; i < s.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range tasksCh {
				res := s.scanPort(ctx, t)
				// Если контекст отменен, прекращаем отправку результатов
				select {
				case resultsCh <- res:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	// 2. Запускаем диспетчер задач
	go func() {
		defer close(tasksCh)
		for _, t := range targets {
			for _, ip := range t.ips {
				for _, p := range validPorts {
					// Если контекст отменен, прекращаем генерацию новых задач
					select {
					case tasksCh <- task{host: t.host, ip: ip, port: p}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	// 3. Запускаем горутину для закрытия канала результатов
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	return resultsCh, nil
}

// scanPort выполняет одно TCP-подключение.
func (s *Scanner) scanPort(ctx context.Context, t task) Result {
	start := time.Now()

	dialer := net.Dialer{
		Timeout: s.connectTimeout,
	}

	// net.JoinHostPort корректно обрабатывает IPv6, добавляя скобки
	addr := net.JoinHostPort(t.ip.String(), strconv.Itoa(int(t.port)))
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	duration := time.Since(start)

	res := Result{
		Host:     t.host,
		IP:       t.ip,
		Port:     t.port,
		Duration: duration,
	}

	if err != nil {
		res.State = classifyError(err)
		res.Err = err
	} else {
		res.State = StateOpen
		// Обязательно закрываем успешное соединение
		conn.Close()
	}

	return res
}

// classifyError определяет состояние порта по типу ошибки БЕЗ сравнения текста.
func classifyError(err error) State {
	if err == nil {
		return StateOpen
	}
	
	// Обработка отмены контекста
	if errors.Is(err, context.Canceled) {
		return StateCanceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return StateTimeout
	}

	// Обработка сетевых таймаутов
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return StateTimeout
	}

	// Обработка системных ошибок через type assertion
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		var sysErr *os.SyscallError
		if errors.As(opErr.Err, &sysErr) {
			switch {
			case errors.Is(sysErr.Err, syscall.ECONNREFUSED):
				return StateClosed
			case errors.Is(sysErr.Err, syscall.ETIMEDOUT):
				return StateTimeout
			case errors.Is(sysErr.Err, syscall.ENETUNREACH), 
			     errors.Is(sysErr.Err, syscall.EHOSTUNREACH), 
			     errors.Is(sysErr.Err, syscall.ENETDOWN):
				return StateUnreachable
			}
		}
	}

	return StateError
}