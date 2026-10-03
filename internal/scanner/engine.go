cat << 'EOF' > internal/scanner/engine.go
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
				select {
				case <-ctx.Done():
					return
				default:
					s.checkTarget(target, resultChan)
				}
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

func (s *ScannerEngine) checkTarget(target Target, results chan<- ScanResult) {
	start := time.Now()
	resp, err := s.Client.Get(target.URL)
	duration := time.Since(start)

	if err != nil {
		results <- ScanResult{URL: target.URL, Error: err}
		return
	}
	defer resp.Body.Close()

	results <- ScanResult{
		URL:        target.URL,
		StatusCode: resp.StatusCode,
		Latency:    duration,
	}
}
EOF