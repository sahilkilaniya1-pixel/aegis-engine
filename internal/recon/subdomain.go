package recon

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type CRTEntry struct {
	NameValue string `json:"name_value"`
}

type SubdomainResolver struct {
	Client *http.Client
}

func NewSubdomainResolver() *SubdomainResolver {
	return &SubdomainResolver{
		Client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (r *SubdomainResolver) FetchPassiveSubdomains(ctx context.Context, domain string) ([]string, error) {
	subdomainMap := make(map[string]bool)

	// 1. Primary Source: crt.sh
	crtSubs, err := r.fetchFromCRT(ctx, domain)
	if err == nil {
		for _, s := range crtSubs {
			subdomainMap[s] = true
		}
	}

	// 2. Secondary Source: HackerTarget (Fallback)
	htSubs, errHT := r.fetchFromHackerTarget(ctx, domain)
	if errHT == nil {
		for _, s := range htSubs {
			subdomainMap[s] = true
		}
	}

	var results []string
	for sub := range subdomainMap {
		results = append(results, sub)
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no subdomains found across passive sources")
	}

	return results, nil
}

func (r *SubdomainResolver) fetchFromCRT(ctx context.Context, domain string) ([]string, error) {
	reqURL := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh status %d", resp.StatusCode)
	}

	var entries []CRTEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, err
	}

	var list []string
	for _, entry := range entries {
		names := strings.Split(entry.NameValue, "\n")
		for _, name := range names {
			clean := strings.TrimPrefix(strings.TrimSpace(name), "*.")
			if clean != "" && strings.HasSuffix(clean, domain) {
				list = append(list, clean)
			}
		}
	}
	return list, nil
}

func (r *SubdomainResolver) fetchFromHackerTarget(ctx context.Context, domain string) ([]string, error) {
	reqURL := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hackertarget status %d", resp.StatusCode)
	}

	var list []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), ",")
		if len(parts) > 0 {
			sub := strings.TrimSpace(parts[0])
			if sub != "" && strings.HasSuffix(sub, domain) {
				list = append(list, sub)
			}
		}
	}

	// Warning Fix: Scan loop ke baad error check add kiya gaya hai
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading response stream: %w", err)
	}

	return list, nil
}