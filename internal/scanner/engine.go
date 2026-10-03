package scanner

import (
	"context"
	"net/http"
	"sync"
	"time"

	"aegis-engine/internal/proxy"
)

type Target struct {
	URL string
}

type ScanResult struct {
	URL        string
	StatusCode int
	Latency    time.Duration
	Error      error
}

type ScannerEngine struct {
	WorkerCount  int
	ProxyManager *proxy.ProxyManager
}

func NewScannerEngine(workers int, pm *proxy.ProxyManager) *ScannerEngine {
	return &ScannerEngine{
		WorkerCount:  workers,
		ProxyManager: pm,
	}
}

func (s *ScannerEngine) ProcessTargets(ctx context.Context, targets []Target) []ScanResult {
	targetChan := make(chan Target, len(targets))
	resultChan := make(chan ScanResult, len(targets))
	var wg sync.WaitGroup

	for i := 0; i < s.WorkerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targetChan {
				start := time.Now()

				// Fetch client with rotated proxy if proxy manager is set
				var client *http.Client
				var err error
				if s.ProxyManager != nil {
					client, err = s.ProxyManager.BuildHTTPClient(5 * time.Second)
				} else {
					client = &http.Client{Timeout: 5 * time.Second}
				}

				if err != nil {
					resultChan <- ScanResult{URL: target.URL, Error: err}
					continue
				}

				req, err := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
				if err != nil {
					resultChan <- ScanResult{URL: target.URL, Error: err}
					continue
				}

				resp, err := client.Do(req)
				latency := time.Since(start)

				if err != nil {
					resultChan <- ScanResult{URL: target.URL, Latency: latency, Error: err}
					continue
				}

				resultChan <- ScanResult{
					URL:        target.URL,
					StatusCode: resp.StatusCode,
					Latency:    latency,
				}
				resp.Body.Close()
			}
		}()
	}

	for _, t := range targets {
		targetChan <- t
	}
	close(targetChan)

	wg.Wait()
	close(resultChan)

	var results []ScanResult
	for res := range resultChan {
		results = append(results, res)
	}

	return results
}