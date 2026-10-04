package proxy

import (
	"fmt"
	"io"
	"net/http"
)

func StartProxyServer(port string) {
	proxyHandler := func(w http.ResponseWriter, req *http.Request) {
		// Agar request HTTPS CONNECT method ki hai (Tunnel ke liye)
		if req.Method == http.MethodConnect {
			HandleConnect(w, req)
			return
		}

		fmt.Printf("[Proxy Intercepted] %s %s\n", req.Method, req.URL.String())

		// Forward request to actual destination target
		client := &http.Client{}
		outReq, err := http.NewRequest(req.Method, req.URL.String(), req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Copy request headers
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

		// Copy response headers back to client (Fixed: using w.Header())
		for name, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}

	fmt.Printf("[*] AegisEngine Interceptor Proxy running on port %s...\n", port)
	http.ListenAndServe(":"+port, http.HandlerFunc(proxyHandler))
}

func HandleConnect(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	fmt.Printf("[+] HTTPS CONNECT Tunnel established for: %s\n", r.Host)
}