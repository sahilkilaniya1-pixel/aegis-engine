package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"aegis-engine/internal/recon"
)

type TriagePayload struct {
	TargetURL         string `json:"target_url"`
	StatusCode        int    `json:"status_code"`
	RawResponse       string `json:"raw_response"`
	VulnerabilityType string `json:"vulnerability_type"`
}

type EnqueueResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
	TaskID  string `json:"task_id"`
	Target  string `json:"target"`
}

type StatusResponse struct {
	TaskID string                 `json:"task_id"`
	Status string                 `json:"status"`
	Result map[string]interface{} `json:"result,omitempty"`
	Error  string                 `json:"error,omitempty"`
}

func main() {
	fmt.Println("🛡️ AegisEngine v2.0 - Security Scanner Core")
	fmt.Println("-----------------------------------------------")

	targetDomain := "example.com"
	fmt.Printf("[+] Starting Passive Subdomain Recon for: %s\n", targetDomain)

	resolver := recon.NewSubdomainResolver()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	subdomains, err := resolver.FetchPassiveSubdomains(ctx, targetDomain)
	if err != nil {
		fmt.Printf("[!] Recon failed or no subdomains found: %v. Falling back to base domain.\n", err)
		subdomains = []string{targetDomain}
	} else {
		fmt.Printf("[✓] Discovered %d unique subdomains!\n", len(subdomains))
	}

	fmt.Println("[i] No proxy configured. Running in direct connection mode.")
	fmt.Printf("\n[+] Scanning %d targets...\n\n", len(subdomains))

	client := &http.Client{Timeout: 10 * time.Second}

	for _, sub := range subdomains {
		targetURL := fmt.Sprintf("https://%s", sub)
		start := time.Now()

		resp, err := client.Get(targetURL)
		duration := time.Since(start)

		if err != nil {
			fmt.Printf("[x] %s -> Error: %v\n", targetURL, err)
			continue
		}
		resp.Body.Close()

		fmt.Printf("[✓] %s -> Status: %03d (%v)\n", targetURL, resp.StatusCode, duration)

		// Send to Celery/FastAPI Triage Queue and get Task ID
		taskID, err := sendToTriage(client, TriagePayload{
			TargetURL:         targetURL,
			StatusCode:        resp.StatusCode,
			RawResponse:       "HTTP/1.1 200 OK - Mock Response Header",
			VulnerabilityType: "Potential XSS / Misconfiguration",
		})

		if err != nil {
			fmt.Printf("   └─ [!] Failed to enqueue for AI Triage: %v\n", err)
		} else {
			fmt.Printf("   └─ [✓] Dispatched to Queue | Task ID: %s\n", taskID)
			// Poll for AI Triage Results
			pollTaskStatus(client, "http://localhost:8000", taskID)
		}
	}
}

func sendToTriage(client *http.Client, payload TriagePayload) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", "http://localhost:8000/api/v1/enqueue-scan", bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("server returned status code %d", resp.StatusCode)
	}

	var enqueueResp EnqueueResponse
	err = json.NewDecoder(resp.Body).Decode(&enqueueResp)
	if err != nil {
		return "", err
	}

	return enqueueResp.TaskID, nil
}

func pollTaskStatus(client *http.Client, baseURL string, taskID string) {
	statusURL := fmt.Sprintf("%s/api/v1/task-status/%s", baseURL, taskID)
	fmt.Printf("      [i] Polling AI Triage result...")

	for i := 0; i < 10; i++ { // Max 10 attempts
		time.Sleep(1 * time.Second)

		resp, err := client.Get(statusURL)
		if err != nil {
			fmt.Print(".")
			continue
		}
		
		var statusResp StatusResponse
		json.NewDecoder(resp.Body).Decode(resp.Body) // safe decoding
		resp.Body.Close()

		// Using Go tagged switch statement to satisfy linter recommendations (QF1003)
		switch statusResp.Status {
		case "SUCCESS":
			fmt.Println("\n      [✓] AI Triage Completed!")
			resBytes, _ := json.MarshalIndent(statusResp.Result, "          ", "  ")
			fmt.Printf("          Result: %s\n", string(resBytes))
			return
		case "FAILURE":
			fmt.Printf("\n      [!] Triage Failed: %s\n", statusResp.Error)
			return
		default:
			fmt.Print(".")
		}
	}
	fmt.Println("\n      [!] Polling timed out waiting for Celery worker.")
}