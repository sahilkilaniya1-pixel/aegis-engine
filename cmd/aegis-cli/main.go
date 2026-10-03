package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"aegis-engine/internal/proxy"
	"aegis-engine/internal/recon"
	"aegis-engine/internal/scanner"
)

type AlertPayload struct {
	TargetURL         string `json:"target_url"`
	StatusCode        int    `json:"status_code"`
	RawResponse       string `json:"raw_response"`
	VulnerabilityType string `json:"vulnerability_type"`
}

func main() {
	fmt.Println("🛡️  AegisEngine v2.0 - Security Scanner Core")
	fmt.Println("-----------------------------------------------")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Subdomain Recon Phase
	targetDomain := "example.com"
	fmt.Printf("[+] Starting Passive Subdomain Recon for: %s\n", targetDomain)

	resolver := recon.NewSubdomainResolver()
	subdomains, err := resolver.FetchPassiveSubdomains(ctx, targetDomain)
	if err != nil || len(subdomains) == 0 {
		fmt.Printf("[!] Recon failed or no subdomains found: %v. Falling back to base domain.\n", err)
		subdomains = []string{targetDomain}
	} else {
		fmt.Printf("[✓] Discovered %d unique subdomains!\n", len(subdomains))
	}

	// Subdomains ko Scanner Targets mein convert karein
	var targets []scanner.Target
	for _, sub := range subdomains {
		targets = append(targets, scanner.Target{URL: fmt.Sprintf("https://%s", sub)})
	}

	// 2. Proxy Configuration
	proxyList := []string{}
	var pm *proxy.ProxyManager
	if len(proxyList) > 0 {
		var pErr error
		pm, pErr = proxy.NewProxyManager(proxyList)
		if pErr != nil {
			fmt.Printf("[!] Proxy error: %v. Running direct mode.\n", pErr)
			pm = nil
		}
	} else {
		fmt.Println("[i] No proxy configured. Running in direct connection mode.")
		pm = nil
	}

	// 3. Scan & Triage Phase
	engine := scanner.NewScannerEngine(5, pm)
	fmt.Printf("\n[+] Scanning %d targets...\n\n", len(targets))
	results := engine.ProcessTargets(ctx, targets)

	for _, res := range results {
		if res.Error != nil {
			fmt.Printf("[!] %s -> Error: %v\n", res.URL, res.Error)
			continue
		}

		fmt.Printf("[✓] %s -> Status: %d (%v)\n", res.URL, res.StatusCode, res.Latency)

		payload := AlertPayload{
			TargetURL:         res.URL,
			StatusCode:        res.StatusCode,
			RawResponse:       fmt.Sprintf("Mock response for %s", res.URL),
			VulnerabilityType: "Reflected XSS Check",
		}

		jsonBody, _ := json.Marshal(payload)
		resp, err := http.Post("http://localhost:8000/api/v1/scan-and-verify", "application/json", bytes.NewBuffer(jsonBody))

		if err != nil {
			fmt.Printf("   └─ [!] AI Triage API Offline (Ensure Uvicorn is running on port 8000)\n\n")
		} else {
			fmt.Printf("   └─ [✓] Processed by AI Triage Engine (HTTP %d)\n\n", resp.StatusCode)
			resp.Body.Close()
		}
	}
}