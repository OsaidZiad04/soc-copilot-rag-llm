import re
from typing import Dict, Any, List


class ThreatIntelAnalyzer:

    def __init__(self):
        self.cve_pattern = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
        self.cvss_pattern = re.compile(r"\bCVSS[:\s]*([0-9](?:\.[0-9])?)\b", re.IGNORECASE)
        self.ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        self.url_pattern = re.compile(r"\b(?:https?|ftp)://[^\s\"'<>]+", re.IGNORECASE)
        self.domain_pattern = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
        self.hash_pattern = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
        self.email_pattern = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
        self.registry_pattern = re.compile(
            r"\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\n,;]+",
            re.IGNORECASE,
        )
        self.file_path_pattern = re.compile(r"\b(?:[A-Za-z]:\\|/)[^\n,;]+")
        self.process_pattern = re.compile(r"\b[A-Za-z0-9._-]+\.exe\b", re.IGNORECASE)
        self.user_pattern = re.compile(
            r"\b(?:user|username|account|targetusername|subjectusername)[=:]\s*['\"]?([A-Za-z0-9._\\-]+)['\"]?",
            re.IGNORECASE,
        )
        self.mitre_rules = [
            {
                "technique_id": "T1566.001",
                "technique_name": "Spearphishing Attachment",
                "tactic": "initial-access",
                "description": "Suspicious content suggests delivery through a malicious attachment.",
                "keywords": ["phishing", "attachment", "invoice", "macro", "zip archive"],
            },
            {
                "technique_id": "T1059.001",
                "technique_name": "PowerShell",
                "tactic": "execution",
                "description": "PowerShell-based execution behavior was observed.",
                "keywords": ["powershell", "pwsh", "invoke-expression", "iex ", "-enc", "encodedcommand"],
            },
            {
                "technique_id": "T1105",
                "technique_name": "Ingress Tool Transfer",
                "tactic": "command-and-control",
                "description": "Downloaded payload or transfer of tooling was observed.",
                "keywords": ["download", "payload.exe", "invoke-webrequest", "curl ", "wget ", "bitsadmin", "certutil", "http://", "https://"],
            },
            {
                "technique_id": "T1547.001",
                "technique_name": "Registry Run Keys / Startup Folder",
                "tactic": "persistence",
                "description": "Autorun persistence via registry or startup folder was observed.",
                "keywords": ["currentversion\\run", "runonce", "startup", "autorun"],
            },
            {
                "technique_id": "T1003.001",
                "technique_name": "LSASS Memory",
                "tactic": "credential-access",
                "description": "Credential dumping activity linked to LSASS or Mimikatz was referenced.",
                "keywords": ["mimikatz", "lsass", "sekurlsa", "credential dump", "credential access"],
            },
            {
                "technique_id": "T1003.008",
                "technique_name": "/etc/passwd and /etc/shadow",
                "tactic": "credential-access",
                "description": "Linux credential material such as /etc/shadow was accessed.",
                "keywords": ["/etc/shadow", "/etc/passwd", "cat /etc/shadow"],
            },
            {
                "technique_id": "T1078",
                "technique_name": "Valid Accounts",
                "tactic": "persistence",
                "description": "Successful login or use of valid credentials was referenced.",
                "keywords": ["accepted password", "valid account", "ssh2", "login successful"],
            },
            {
                "technique_id": "T1550.002",
                "technique_name": "Pass the Hash",
                "tactic": "lateral-movement",
                "description": "Pass-the-hash behavior was referenced.",
                "keywords": ["pass-the-hash", "pth"],
            },
            {
                "technique_id": "T1071.001",
                "technique_name": "Web Protocols",
                "tactic": "command-and-control",
                "description": "Network beaconing or web-based command and control was observed.",
                "keywords": ["beacon", "c2", "command and control", "callback", "destinationip", "destinationhostname", "outbound connection", ":4444", "/dev/tcp/", "https://", "http://"],
            },
            {
                "technique_id": "T1053.005",
                "technique_name": "Scheduled Task",
                "tactic": "persistence",
                "description": "Persistence through a scheduled task was observed.",
                "keywords": ["scheduled task", "schtasks"],
            },
            {
                "technique_id": "T1027",
                "technique_name": "Obfuscated Files or Information",
                "tactic": "defense-evasion",
                "description": "Encoded or obfuscated content was detected.",
                "keywords": ["base64", "obfuscat", "-enc", "encodedcommand"],
            },
            {
                "technique_id": "T1047",
                "technique_name": "Windows Management Instrumentation",
                "tactic": "execution",
                "description": "WMI-based execution was observed.",
                "keywords": ["wmic", "windows management instrumentation"],
            },
            {
                "technique_id": "T1021.002",
                "technique_name": "SMB/Windows Admin Shares",
                "tactic": "lateral-movement",
                "description": "SMB or PsExec style lateral movement was referenced.",
                "keywords": ["psexec", "admin$", "smb"],
            },
            {
                "technique_id": "T1190",
                "technique_name": "Exploit Public-Facing Application",
                "tactic": "initial-access",
                "description": "Exploitation of a public-facing application or vulnerability was referenced.",
                "keywords": ["rce", "remote code execution", "exploit", "cve-", "public-facing", "upload.php", "phpmyadmin", "webshell", "web shell"],
            },
            {
                "technique_id": "T1505.003",
                "technique_name": "Server Software Component: Web Shell",
                "tactic": "persistence",
                "description": "Web shell behavior or server-side command execution was referenced.",
                "keywords": ["webshell", "web shell", "shell.php", "cmd=", "www-data", "upload.php"],
            },
            {
                "technique_id": "T1059.004",
                "technique_name": "Unix Shell",
                "tactic": "execution",
                "description": "Unix shell command execution was observed.",
                "keywords": ["/bin/bash", "bash -i", " sh -i", "cmd=whoami", "cmd=id", "command=/bin/bash"],
            },
            {
                "technique_id": "T1068",
                "technique_name": "Exploitation for Privilege Escalation",
                "tactic": "privilege-escalation",
                "description": "Privilege escalation or root shell behavior was referenced.",
                "keywords": ["privilege escalation", "sudo:", "user=root", "tty=pts", "www-data :"],
            },
            {
                "technique_id": "T1041",
                "technique_name": "Exfiltration Over C2 Channel",
                "tactic": "exfiltration",
                "description": "Potential exfiltration over the same C2 channel was referenced.",
                "keywords": ["exfiltrat", "data staging", "archive staging"],
            },
        ]

    def _dedupe_strings(self, values: List[str]) -> List[str]:
        items = []
        seen = set()

        for value in values:
            if not isinstance(value, str):
                continue

            item = value.strip()
            if not item:
                continue

            key = item.lower()
            if key in seen:
                continue

            seen.add(key)
            items.append(item)

        return items

    def _normalize_indicator_text(self, text: str) -> str:
        text = text or ""
        return (
            text.replace("[.]", ".")
            .replace("(.)", ".")
            .replace("hxxps://", "https://")
            .replace("hxxp://", "http://")
        )

    def _clean_indicator_value(self, value: str) -> str:
        if not isinstance(value, str):
            return ""

        cleaned = value.strip().strip("\"'`")
        cleaned = re.split(r"\s+(?:and|or|every|then|with|where)\s+", cleaned, maxsplit=1, flags=re.IGNORECASE)[0]
        cleaned = re.split(r"[,\n;|]+", cleaned, maxsplit=1)[0]
        if ":\\" in cleaned or cleaned.startswith("/"):
            match = re.search(
                r"^(.*?\.(?:exe|dll|ps1|bat|cmd|sys|tmp|log|txt|pdf|doc|docx|zip|rar|7z))\b",
                cleaned,
                flags=re.IGNORECASE,
            )
            if match:
                cleaned = match.group(1)
        return cleaned.rstrip(" .:)]}")

    def _validate_cves(self, values: List[str]) -> List[str]:
        valid = []
        for value in values:
            if not isinstance(value, str):
                continue
            cve = value.strip().upper()
            if self.cve_pattern.match(cve):
                valid.append(cve)
        return self._dedupe_strings(valid)

    def _contains_any(self, text: str, keywords: List[str]) -> bool:
        lowered = text.lower()
        return any(keyword in lowered for keyword in keywords)

    def _mitre_url(self, technique_id: str) -> str:
        if not isinstance(technique_id, str) or not technique_id.startswith("T"):
            return ""
        return "https://attack.mitre.org/techniques/" + technique_id[1:].replace(".", "/") + "/"

    def extract_observables(self, text: str) -> Dict[str, List[str]]:
        normalized = self._normalize_indicator_text(text)

        urls = self._dedupe_strings([
            self._clean_indicator_value(value)
            for value in self.url_pattern.findall(normalized)
        ])
        ip_addresses = self._dedupe_strings(self.ip_pattern.findall(normalized))
        file_hashes = self._dedupe_strings(self.hash_pattern.findall(normalized))
        email_addresses = self._dedupe_strings(self.email_pattern.findall(normalized))
        registry_keys = self._dedupe_strings([
            self._clean_indicator_value(value)
            for value in self.registry_pattern.findall(normalized)
        ])
        file_paths = self._dedupe_strings([
            self._clean_indicator_value(value)
            for value in self.file_path_pattern.findall(normalized)
        ])
        processes = self._dedupe_strings([
            self._clean_indicator_value(value)
            for value in self.process_pattern.findall(normalized)
        ])
        users = self._dedupe_strings(
            self.user_pattern.findall(normalized)
            + re.findall(r"\buser\s+['\"]([A-Za-z0-9._\\-]+)['\"]", normalized, flags=re.IGNORECASE)
            + re.findall(r"\bof user\s+['\"]?([A-Za-z0-9._\\-]+)['\"]?", normalized, flags=re.IGNORECASE)
        )
        cve_ids = self._validate_cves(self.cve_pattern.findall(normalized))

        def is_valid_domain(value: str):
            value = (value or "").lower().rstrip(".")
            if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
                return False
            if any(sep in value for sep in ["/", "\\", "@"]):
                return False
            suffix = value.split(".")[-1]
            bad_suffixes = {"exe", "dll", "ps1", "bat", "cmd", "sys", "tmp", "log", "txt", "zip", "rar", "7z", "pdf", "doc", "docx", "php", "asp", "aspx", "jsp", "cgi", "pl", "bin"}
            if suffix in bad_suffixes:
                return False
            if re.search(r"\b(?:shell|payload|dropper|loader|beacon|stage|update|install|setup|backup)\.[a-z0-9]{2,5}$", value):
                return False
            return True

        domains = []
        for url in urls:
            match = re.match(r"^[a-z]+://([^/:?#]+)", url, flags=re.IGNORECASE)
            if match and is_valid_domain(match.group(1)):
                domains.append(match.group(1))

        standalone_domains = self.domain_pattern.findall(normalized)
        domains.extend([
            value
            for value in standalone_domains
            if is_valid_domain(value)
        ])
        email_domains = {email.split("@")[-1].lower() for email in email_addresses}
        user_values = {user.lower().rstrip(".") for user in users}
        domains = [
            value for value in self._dedupe_strings(domains)
            if value.lower() not in email_domains and value.lower().rstrip(".") not in user_values
        ]

        return {
            "ip_addresses": ip_addresses,
            "domains": domains,
            "urls": urls,
            "file_hashes": file_hashes,
            "email_addresses": email_addresses,
            "registry_keys": registry_keys,
            "file_paths": file_paths,
            "users": users,
            "processes": processes,
            "cve_ids": cve_ids,
        }

    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        observables = self.extract_observables(text=text)
        return {
            "ip_addresses": observables["ip_addresses"],
            "domains": observables["domains"],
            "urls": observables["urls"],
            "file_hashes": observables["file_hashes"],
            "emails": observables["email_addresses"],
        }

    def _infer_attack_type(self, text: str) -> str:
        lower = text.lower()
        if "rce" in lower or "remote code execution" in lower:
            return "remote_code_execution"
        if "sql injection" in lower:
            return "sql_injection"
        if "privilege escalation" in lower:
            return "privilege_escalation"
        if "xss" in lower or "cross-site scripting" in lower:
            return "xss"
        if "authentication bypass" in lower:
            return "auth_bypass"
        if "phishing" in lower:
            return "phishing"
        if "ransom" in lower or ".locked" in lower:
            return "ransomware"
        return "unknown"

    def infer_threat_type(self, text: str) -> str:
        lower = text.lower()
        scores = {
            "Ransomware": 0,
            "Phishing": 0,
            "Brute Force": 0,
            "Credential Access": 0,
            "Command and Control": 0,
            "Persistence": 0,
            "Exploit": 0,
            "Malware": 0,
        }

        if any(term in lower for term in ["ransom", ".locked", "decrypt", "bitcoin"]):
            scores["Ransomware"] += 5
        if any(term in lower for term in ["phishing", "attachment", "invoice", "macro", "mailbox"]):
            scores["Phishing"] += 4
        if any(term in lower for term in ["brute force", "failed login", "authentication failed", "password spray"]):
            scores["Brute Force"] += 4
        if any(term in lower for term in ["mimikatz", "pass-the-hash", "credential dump", "lsass"]):
            scores["Credential Access"] += 3
        if any(term in lower for term in ["beacon", "c2", "command and control", "callback", "destinationhostname", "reverse shell", ":4444"]):
            scores["Command and Control"] += 4
        if any(term in lower for term in ["currentversion\\run", "runonce", "scheduled task", "autorun"]):
            scores["Persistence"] += 3
        if any(term in lower for term in ["rce", "exploit", "remote code execution", "cve-", "webshell", "web shell", "shell.php", "cmd="]):
            scores["Exploit"] += 4
        if any(term in lower for term in ["payload", "trojan", "malware", "backdoor", "downloaded", "powershell.exe", "shell.php"]):
            scores["Malware"] += 4
        if scores["Malware"] > 0 and scores["Command and Control"] > 0:
            scores["Malware"] += 2
        if scores["Phishing"] > 0 and scores["Malware"] > 0:
            scores["Phishing"] += 1

        best_label = max(scores, key=scores.get)
        if scores[best_label] > 0:
            return best_label

        if any(term in lower for term in ["ransom", ".locked", "decrypt", "bitcoin"]):
            return "Ransomware"
        return "Unknown"

    def infer_affected_systems(self, text: str) -> List[str]:
        lowered = text.lower()
        systems = []

        keyword_map = {
            "windows": ["windows", "powershell", "winword.exe", "currentversion\\run", "eventid=", "schtasks", "\\users\\", "c:\\"],
            "linux": ["linux", "/bin/", "/tmp/", "/etc/", "bash -c", "wget ", "curl "],
            "email": ["phishing", "outlook", "mailbox", "smtp", "attachment"],
            "network": ["destinationip", "destinationhostname", "http://", "https://", "dns", "beacon"],
            "active_directory": ["domain controller", "kerberos", "mimikatz", "pass-the-hash", "lsass"],
        }

        for label, keywords in keyword_map.items():
            if any(keyword in lowered for keyword in keywords):
                systems.append(label)

        observables = self.extract_observables(text)
        if observables["ip_addresses"] or observables["domains"] or observables["urls"]:
            systems.append("external_network")
        if observables["registry_keys"] or observables["file_paths"] or observables["processes"]:
            systems.append("endpoint")

        return self._dedupe_strings(systems)

    def infer_mitre_techniques(self, text: str) -> List[Dict[str, Any]]:
        lowered = self._normalize_indicator_text(text).lower()
        techniques = []
        seen = set()

        for rule in self.mitre_rules:
            if self._contains_any(lowered, rule["keywords"]):
                technique_id = rule["technique_id"]
                if technique_id in seen:
                    continue
                seen.add(technique_id)
                techniques.append({
                    "technique_id": technique_id,
                    "technique_name": rule["technique_name"],
                    "tactic": rule["tactic"],
                    "description": rule["description"],
                    "url": self._mitre_url(technique_id),
                })

        return techniques

    def infer_kill_chain_phase(self, text: str, techniques: List[Dict[str, Any]] = None) -> str:
        techniques = techniques or self.infer_mitre_techniques(text)
        tactics = [technique.get("tactic", "") for technique in techniques if isinstance(technique, dict)]

        tactic_to_phase = {
            "initial-access": "initial-access",
            "execution": "execution",
            "persistence": "persistence",
            "privilege-escalation": "privilege-escalation",
            "defense-evasion": "defense-evasion",
            "credential-access": "credential-access",
            "discovery": "discovery",
            "lateral-movement": "lateral-movement",
            "collection": "collection",
            "command-and-control": "command-and-control",
            "exfiltration": "exfiltration",
            "impact": "impact",
        }

        for tactic in [
            "impact",
            "exfiltration",
            "command-and-control",
            "lateral-movement",
            "credential-access",
            "persistence",
            "execution",
            "initial-access",
        ]:
            if tactic in tactics:
                return tactic_to_phase[tactic]

        return ""

    def _infer_affected_system(self, text: str) -> str:
        affected = self.infer_affected_systems(text=text)
        return affected[0] if affected else "unknown"

    def _infer_severity(self, text: str) -> Dict[str, Any]:
        cvss_match = self.cvss_pattern.search(text)
        score = float(cvss_match.group(1)) if cvss_match else 0.0
        lower = text.lower()
        if not score:
            if "critical" in lower:
                score = 9.0
            elif "high" in lower:
                score = 7.5
            elif "medium" in lower:
                score = 5.0
            elif "low" in lower:
                score = 2.5

        if score >= 9.0:
            level = "critical"
        elif score >= 7.0:
            level = "high"
        elif score >= 4.0:
            level = "medium"
        elif score > 0:
            level = "low"
        else:
            level = "info"

        return {"score": score, "level": level}

    def parse_cve(self, text: str) -> Dict[str, Any]:
        cve_ids = [cve.upper() for cve in self.cve_pattern.findall(text)]
        severity = self._infer_severity(text=text)
        attack_type = self._infer_attack_type(text=text)
        affected_system = self._infer_affected_system(text=text)
        iocs = self.extract_iocs(text=text)
        mitre_techniques = self.infer_mitre_techniques(text=text)

        return {
            "cve_ids": list(dict.fromkeys(cve_ids)),
            "severity": severity,
            "attack_type": attack_type,
            "affected_system": affected_system,
            "iocs": iocs,
            "mitre_techniques": mitre_techniques,
            "kill_chain_phase": self.infer_kill_chain_phase(text=text, techniques=mitre_techniques),
        }
