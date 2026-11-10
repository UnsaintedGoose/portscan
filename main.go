package main

import (
	"context"
	"fmt"
	"time"

	"github.com/UnsaintedGoose/portscan"

)

func main() {
	// Создаем сканер с настройками
	scanner, err := portscan.New(
		portscan.WithConcurrency(100),
		portscan.WithConnectTimeout(500*time.Millisecond),
	)
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	
	// Запускаем сканирование
	results, err := scanner.Scan(
		ctx,
		[]string{"192.168.1.10", "example.com"},
		portscan.Range(1, 1000),
	)
	if err != nil {
		panic(err)
	}

	// Читаем результаты
	for res := range results {
		fmt.Printf("%s (%s):%d - %s\n", res.Host, res.IP, res.Port, res.State)
	}
}