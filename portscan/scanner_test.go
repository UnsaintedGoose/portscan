package portscan

import (
	"context"
	"net"
	"testing"
	"time"

)
func TestScanner_Basic(t *testing.T) {
	// Поднимаем локальный TCP-сервер для теста открытого порта
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)
	
	// net.TCPAddr.Port уже имеет тип int, что идеально подходит для нашего API
	openPort := addr.Port 
	closedPort := 1 // Порт 1 обычно закрыт, тип int

	scanner, err := New(
		WithConcurrency(10),
		WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	
	// Передаем int в List
	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, List(openPort, closedPort))
	if err != nil {
		t.Fatal(err)
	}

	foundOpen, foundClosed := false, false

	for res := range results {
		// res.Port имеет тип uint16, поэтому приводим openPort/closedPort для сравнения
		if res.Port == uint16(openPort) && res.State == StateOpen {
			foundOpen = true
		}
		if res.Port == uint16(closedPort) && res.State == StateClosed {
			foundClosed = true
		}
	}

	if !foundOpen {
		t.Error("open port not found or incorrect state")
	}
	if !foundClosed {
		t.Error("closed port not found or incorrect state")
	}
}

func TestScanner_ContextCancellation(t *testing.T) {
	scanner, _ := New(WithConnectTimeout(time.Second))
	ctx, cancel := context.WithCancel(context.Background())

	// Range теперь принимает int
	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, Range(1, 1000))
	if err != nil {
		t.Fatal(err)
	}

	// Отменяем контекст сразу
	cancel()

	// Дренируем канал, чтобы убедиться, что он закрывается и нет зависаний
	count := 0
	for range results {
		count++
	}
	
	// Количество результатов должно быть меньше общего числа задач (1000)
	if count >= 1000 {
		t.Error("context cancellation did not stop scanning early")
	}
}

func TestScanner_InvalidInputs(t *testing.T) {
	scanner, _ := New()
	ctx := context.Background()

	// Пустые хосты
	_, err := scanner.Scan(ctx, []string{}, List(80))
	if err == nil {
		t.Error("expected error for empty hosts")
	}

	// Пустые порты
	_, err = scanner.Scan(ctx, []string{"127.0.0.1"}, Ports{})
	if err == nil {
		t.Error("expected error for empty ports")
	}

	// Невалидный порт (0)
	_, err = scanner.Scan(ctx, []string{"127.0.0.1"}, List(0))
	if err == nil {
		t.Error("expected error for port 0")
	}
	
	// Невалидный порт (>65535)
	// Теперь это компилируется, так как List принимает int
	_, err = scanner.Scan(ctx, []string{"127.0.0.1"}, List(70000))
	if err == nil {
		t.Error("expected error for port > 65535")
	}

	// Отрицательный порт
	_, err = scanner.Scan(ctx, []string{"127.0.0.1"}, List(-5))
	if err == nil {
		t.Error("expected error for negative port")
	}
	
	// Проверка обратного диапазона (должен автоматически инвертироваться в 1-100)
	ports := Range(100, 1)
	validPorts, err := ports.Validate()
	if err != nil {
		t.Errorf("unexpected error for reversed range: %v", err)
	}
	if len(validPorts) != 100 || validPorts[0] != 1 || validPorts[99] != 100 {
		t.Error("reversed range was not handled correctly")
	}
}