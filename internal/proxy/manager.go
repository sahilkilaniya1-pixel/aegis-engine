package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"
)

type ProxyNode struct {
	URL          *url.URL
	Active       bool
	FailureCount int64
}

type ProxyManager struct {
	mu      sync.RWMutex
	proxies []*ProxyNode
	counter uint64
}

func NewProxyManager(proxyList []string) (*ProxyManager, error) {
	var nodes []*ProxyNode
	for _, p := range proxyList {
		parsedURL, err := url.Parse(p)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL %s: %v", p, err)
		}
		nodes = append(nodes, &ProxyNode{
			URL:    parsedURL,
			Active: true,
		})
	}

	if len(nodes) == 0 {
		return nil, errors.New("no valid proxies provided")
	}

	return &ProxyManager{
		proxies: nodes,
	}, nil
}

// GetNextProxy Round-Robin format mein active proxy return karta hai
func (pm *ProxyManager) GetNextProxy() (*url.URL, error) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	total := uint64(len(pm.proxies))
	if total == 0 {
		return nil, errors.New("proxy pool is empty")
	}

	for i := uint64(0); i < total; i++ {
		idx := atomic.AddUint64(&pm.counter, 1) % total
		node := pm.proxies[idx]
		if node.Active {
			return node.URL, nil
		}
	}

	return nil, errors.New("no active proxies available in pool")
}

// BuildHTTPClient Rotated proxy ke sath custom HTTP Client return karta hai
func (pm *ProxyManager) BuildHTTPClient(timeout time.Duration) (*http.Client, error) {
	proxyURL, err := pm.GetNextProxy()
	if err != nil {
		return &http.Client{Timeout: timeout}, nil // Fallback to direct connection if no proxy
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}
