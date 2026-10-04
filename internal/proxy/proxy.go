package proxy

import (
	"fmt"
	"io"
	"net/http"
)

func StartProxyServer(port string) {
	proxyHandler := func(w http.ResponseWriter, req *http.Request) {
		fmt.Printf("[Proxy Intercepted] %s %s\n", req.Method, req.URL.String())

		// Forward request to actual destination target
		client := &http.Client{}
		outReq, err := http.NewRequest(req.Method, req.URL.String(), req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Copy headers
		for name, values := range req.Header {
			for _, value := range values {
				outReq.Header.Add(name, value)
			}
		}

		resp, err := client.Do(outReq)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Copy response headers and body back to client
		for name, values := range resp.Header {
			for _, value := range values {
				outReq.Header.Add(name, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}

	fmt.Printf("[*] AegisEngine Interceptor Proxy running on port %s...\n", port)
	http.ListenAndServe(":"+port, http.HandlerFunc(proxyHandler))
}