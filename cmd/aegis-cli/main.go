package main

import (
	"context"
	"fmt"
	"time"

	"aegis-engine/internal/scanner"
)

func main() {
	fmt.Println("AegisEngine CLI v2.0 - Security Scanner Core")
	fmt.Println("-----------------------------------------------")

	targets := []scanner.Target{
		{URL: "[https://httpbin.org/get](https://httpbin.org/get)"},
		{URL: "[https://httpbin.org/status/404](https://httpbin.org/status/404)"},
		{URL: "[https://httpbin.org/delay/1](https://httpbin.org/delay/1)"},
	}

	engine := scanner.NewScannerEngine(5)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	fmt.Printf("[+] Scanning %d targets...\n", len(targets))
	results := engine.ProcessTargets(ctx, targets)

	for _, res := range results {
		if res.Error != nil {
			fmt.Printf("[!] %s -> Error: %v\n", res.URL, res.Error)
		} else {
			fmt.Printf("[+] %s -> Status: %d (%v)\n", res.URL, res.StatusCode, res.Latency)
		}
	}
}
