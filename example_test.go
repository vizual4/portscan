package portscan

import (
	"context"
	"fmt"
	"time"
)

func ExampleScanner_Scan() {
	scanner, err := New(
		WithConcurrency(100),
		WithConnectTimeout(time.Second),
	)
	if err != nil {
		panic(err)
	}

	webPorts, _ := Ports(80, 443)
	ctx := context.Background()

	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, webPorts)
	if err != nil {
		panic(err)
	}

	for r := range results {
		fmt.Printf("%s:%d -> %s\n", r.Host, r.Port, r.State)
	}
}
