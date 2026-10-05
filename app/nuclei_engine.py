import os
import yaml
import httpx
import re
from sqlalchemy.orm import Session
from app.models import Vulnerability

class NucleiYAMLParser:
    def __init__(self, templates_dir: str):
        self.templates_dir = templates_dir

    def load_templates(self):
        templates = []
        if not os.path.exists(self.templates_dir):
            return templates
        
        for root, _, files in os.walk(self.templates_dir):
            for file in files:
                if file.endswith(".yaml") or file.endswith(".yml"):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            data = yaml.safe_load(f)
                            if data:
                                templates.append(data)
                    except Exception as e:
                        print(f"Error loading template {file_path}: {e}")
        return templates

class NucleiEngine:
    def __init__(self, db: Session, templates_dir: str = "templates/nuclei"):
        self.db = db
        self.parser = NucleiYAMLParser(templates_dir)

    def run_scan(self, target_url: str, target_id: int):
        templates = self.parser.load_templates()
        findings = []

        client = httpx.Client(verify=False, follow_redirects=True, timeout=10.0)

        for template in templates:
            info = template.get("info", {})
            template_id = info.get("name", "Unknown Template")
            severity = info.get("severity", "Info").capitalize()
            
            requests_data = template.get("requests", [])
            for req in requests_data:
                method = req.get("method", "GET").upper()
                path = req.get("path", ["/"])[0]
                
                # Construct full URL
                full_url = target_url.rstrip("/") + path
                matchers = req.get("matchers", [])

                try:
                    response = client.request(method, full_url)
                    
                    # Evaluate Matchers
                    matched = self._evaluate_matchers(response, matchers)
                    if matched:
                        vuln = Vulnerability(
                            target_id=target_id,
                            title=f"[Nuclei] {template_id}",
                            severity=severity,
                            cwe=info.get("cwe", "CWE-200"),
                            owasp_category=info.get("classification", {}).get("owasp-top10", "A01:2021-Broken Access Control"),
                            description=info.get("description", "Vulnerability detected via custom Nuclei template."),
                            remediation=info.get("remediation", "Review application code and apply vendor patches."),
                            poc=f"Request: {method} {full_url}\nStatus: {response.status_code}"
                        )
                        self.db.add(vuln)
                        self.db.commit()
                        findings.append(template_id)
                except Exception as ex:
                    print(f"Request failed for {full_url}: {ex}")

        client.close()
        return findings

    def _evaluate_matchers(self, response, matchers) -> bool:
        if not matchers:
            return False

        for matcher in matchers:
            m_type = matcher.get("type")
            words = matcher.get("words", [])
            regexes = matcher.get("regex", [])
            status_codes = matcher.get("status", [])

            # Status Code matching
            if status_codes and response.status_code not in status_codes:
                return False

            # Word matching
            if words:
                body_text = response.text
                for word in words:
                    if word not in body_text:
                        return False

            # Regex matching
            if regexes:
                body_text = response.text
                for rx in regexes:
                    if not re.search(rx, body_text):
                        return False

        return True