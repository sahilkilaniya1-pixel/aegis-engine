package scanner

import (
	"context"
	"net/http"
	"sync"
	"time"
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
	WorkerCount int
	Client      *http.Client
}

func NewScannerEngine(workers int) *ScannerEngine {
	return &ScannerEngine{
		WorkerCount: workers,
		Client: &http.Client{
			Timeout: 5 * time.Second,
		},
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
				req, err := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
				if err != nil {
					resultChan <- ScanResult{URL: target.URL, Error: err}
					continue
				}

				resp, err := s.Client.Do(req)
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