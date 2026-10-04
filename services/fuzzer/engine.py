import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

class ActiveFuzzerEngine:
    def __init__(self, target_url: str, payloads: list):
        self.target_url = target_url
        self.payloads = payloads

    def fuzz_parameters(self):
        """Injects payloads into URL query parameters to check for XSS/SQLi"""
        parsed_url = urlparse(self.target_url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            return [{"info": "No query parameters found for active fuzzing."}]

        vulnerabilities_found = []

        for param in query_params:
            for payload in self.payloads:
                # Create a copy and inject payload
                test_params = query_params.copy()
                test_params[param] = [payload]
                
                new_query = urlencode(test_params, doseq=True)
                fuzz_url = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    new_query,
                    parsed_url.fragment
                ))

                try:
                    resp = requests.get(fuzz_url, timeout=5)
                    # Heuristic check for reflection or database errors
                    if payload in resp.text:
                        vulnerabilities_found.append({
                            "parameter": param,
                            "payload": payload,
                            "vulnerable_url": fuzz_url,
                            "evidence": "Payload reflected in response body"
                        })
                except Exception as e:
                    continue

        return vulnerabilities_found