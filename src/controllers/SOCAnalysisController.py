from .BaseController import BaseController
from .NLPController import NLPController
from models.db_schemes import ThreatAnalysis
from modules.threat_intel import ThreatIntelAnalyzer
import json
import re
import logging


class SOCAnalysisController(BaseController):

    def __init__(self, vectordb_client, generation_client,
                 embedding_client, template_parser):
        super().__init__()

        self.vectordb_client = vectordb_client
        self.generation_client = generation_client
        self.embedding_client = embedding_client
        self.template_parser = template_parser
        self.logger = logging.getLogger("uvicorn.error")
        self.intel_analyzer = ThreatIntelAnalyzer()
        self.nlp_controller = NLPController(
            vectordb_client=vectordb_client,
            generation_client=generation_client,
            embedding_client=embedding_client,
            template_parser=template_parser,
        )

    def _analysis_schema(self):
        return {
            "title": "",
            "summary": "",
            "threat_type": "",
            "affected_systems": [],
            "severity": {
                "score": 0.0,
                "level": "info",
                "confidence": 0.0,
                "justification": "",
                "score_drivers": []
            },
            "threat_actor": None,
            "malware_family": None,
            "cve_ids": [],
            "mitre_techniques": [],
            "kill_chain_phase": "",
            "iocs": {
                "ip_addresses": [],
                "domains": [],
                "file_hashes": [],
                "urls": [],
                "email_addresses": [],
                "registry_keys": [],
                "file_paths": [],
                "cve_ids": [],
                "users": [],
                "processes": []
            },
            "rag_sources": [],
            "detection_rules": {
                "splunk_spl": None,
                "elk_query": None,
                "yara_rule": None,
                "suricata_rule": None,
                "sigma_rule": None
            },
            "recommended_actions": [],
            "false_positive_likelihood": 0.0,
            "false_positive_reasons": []
        }

    def _build_system_prompt(self):
        return (
            "You are an expert SOC analyst. Analyze the security input and return ONLY a valid JSON:\n"
            "{\n"
            "  \"title\": \"...\",\n"
            "  \"summary\": \"...\",\n"
            "  \"threat_type\": \"Ransomware|APT|Phishing|Exploit|BruteForce|...\",\n"
            "  \"affected_systems\": [],\n"
            "  \"severity\": {\"score\": 0.0, \"level\": \"critical|high|medium|low|info\", \"confidence\": 0.0, \"justification\": \"...\", \"score_drivers\": []},\n"
            "  \"threat_actor\": null,\n"
            "  \"malware_family\": null,\n"
            "  \"cve_ids\": [],\n"
            "  \"mitre_techniques\": [{\"technique_id\": \"TXXXX\", \"technique_name\": \"...\", \"tactic\": \"...\", \"description\": \"...\", \"url\": \"...\"}],\n"
            "  \"kill_chain_phase\": \"...\",\n"
            "  \"iocs\": {\"ip_addresses\": [], \"domains\": [], \"file_hashes\": [], \"urls\": [], \"email_addresses\": [], \"registry_keys\": [], \"file_paths\": [], \"cve_ids\": [], \"users\": [], \"processes\": []},\n"
            "  \"rag_sources\": [],\n"
            "  \"detection_rules\": {\"splunk_spl\": null, \"elk_query\": null, \"yara_rule\": null, \"suricata_rule\": null, \"sigma_rule\": null},\n"
            "  \"recommended_actions\": [{\"priority\": 1, \"action\": \"...\", \"description\": \"...\", \"responsible_team\": \"SOC|IR|Network|Endpoint\"}],\n"
            "  \"false_positive_likelihood\": 0.0,\n"
            "  \"false_positive_reasons\": []\n"
            "}\n"
            "Use retrieved context only as supporting evidence, not as final truth.\n"
            "When detection context is sufficient, populate sigma_rule with a valid Sigma YAML rule.\n"
            "Return ONLY the JSON. No markdown. No explanation."
        )

    def _build_user_prompt(self, input_text: str, input_type: str, rag_sources: list):
        context_text = "\n".join([
            f"[{idx+1}] score={round(source.get('score', 0.0), 4)} text={source.get('text', '')}"
            for idx, source in enumerate(rag_sources)
        ])

        return (
            f"INPUT_TYPE: {input_type}\n"
            f"INPUT_TEXT:\n{input_text}\n\n"
            f"RAG_CONTEXT:\n{context_text if len(context_text) else 'NO_CONTEXT'}\n\n"
            "Respond with JSON only."
        )

    def _extract_first_json_object(self, text: str):
        start = text.find("{")
        if start == -1:
            return None

        depth = 0
        for idx in range(start, len(text)):
            if text[idx] == "{":
                depth += 1
            elif text[idx] == "}":
                depth -= 1
                if depth == 0:
                    return text[start:idx + 1]

        return None

    def _sanitize_response(self, text: str):
        if not text:
            return ""

        cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE).strip()

        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```[a-zA-Z0-9_\-]*", "", cleaned).strip()
            cleaned = re.sub(r"```$", "", cleaned).strip()

        return cleaned

    def _safe_float(self, value, default: float = 0.0):
        try:
            return float(value)
        except Exception:
            return default

    def _normalize_level(self, level: str, score: float):
        valid = {"critical", "high", "medium", "low", "info"}
        if isinstance(level, str) and level.lower() in valid:
            return level.lower()

        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score >= 1.0:
            return "low"

        return "info"

    def _level_from_score(self, score: float):
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 5.0:
            return "medium"
        if score >= 3.0:
            return "low"
        return "info"

    def _evidence_present(self, text: str, patterns: list):
        return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)

    def _count_iocs(self, iocs: dict):
        if not isinstance(iocs, dict):
            return 0
        total = 0
        for value in iocs.values():
            if isinstance(value, list):
                total += len([item for item in value if item])
        return total

    def _dynamic_severity_from_evidence(self, input_text: str, iocs: dict, mitre_techniques: list):
        text = input_text or ""
        text_low = text.lower()
        drivers = []
        weighted_drivers = []
        score = 0.0

        def add(condition, points, label):
            nonlocal score
            if condition:
                score += points
                drivers.append(label)
                weighted_drivers.append({"label": label, "weight": round(points, 2)})

        failed_login = self._evidence_present(text, [
            r"\b4625\b", r"failed\s+(?:login|logon|password|auth)", r"authentication failure",
            r"invalid user", r"brute\s*force", r"password spray", r"failurecount\s*=\s*[2-9]\d*"
        ])
        successful_login = self._evidence_present(text, [
            r"\b4624\b", r"successful?\s+(?:login|logon|auth)", r"accepted password",
            r"session established", r"logon type"
        ])
        powershell = self._evidence_present(text, [
            r"powershell(?:\.exe)?", r"\bpwsh(?:\.exe)?", r"\bcmd(?:\.exe)?",
            r"encodedcommand", r"frombase64string", r"downloadstring", r"iex\s*\("
        ])
        credential_access = self._evidence_present(text, [
            r"\bT1003(?:\.\d+)?\b", r"lsass(?:\.exe)?", r"credential(?:s)?\s+(?:dump|dumping|access|theft|harvest)",
            r"mimikatz", r"sekurlsa", r"procdump.*lsass", r"comsvcs\.dll.*minidump",
            r"\bSAM\b.*(?:access|dump|save|copy)", r"ntds\.dit", r"token\s+(?:dump|theft|impersonation)"
        ])
        account_priv = self._evidence_present(text, [
            r"\b4720\b", r"\b4728\b", r"\b4732\b", r"\b4672\b", r"net user.*\/add",
            r"created\s+(?:user|account)", r"localgroup administrators.*\/add", r"privilege escalation"
        ])
        persistence = self._evidence_present(text, [
            r"\b4698\b", r"schtasks(?:\.exe)?", r"scheduled task", r"task scheduler",
            r"persistence", r"crontab", r"cron\s+job", r"currentversion\\run"
        ])
        c2 = self._evidence_present(text, [
            r"\b(?:c2|c&c|command and control)\b", r"beacon(?:ing)?", r"outbound (?:connection|traffic|network)",
            r"connected\s+to", r"destination(?:ip|_ip| ip| address)?", r"\bEventCode=3\b",
            r"(?:curl|wget).*(?:https?|hxxps?):\/\/"
        ])
        exfiltration = self._evidence_present(text, [
            r"exfil(?:tration|trate|trated)?", r"data staging", r"stag(?:e|ed|ing).*?(?:data|files|archive)",
            r"compress-archive", r"(?:7z|rar|zip)(?:\.exe)?", r"rclone", r"scp\b", r"ftp\b",
            r"upload(?:ed|ing)?.*?(?:archive|data|files)"
        ])
        defense_evasion = self._evidence_present(text, [
            r"\b1102\b", r"EventCode=104", r"wevtutil.*\bcl\b", r"clear-eventlog",
            r"security log cleared", r"log(?:s)? (?:cleared|deleted|wiped)", r"defense evasion",
            r"disable(?:d)?.*?(?:defender|logging|audit)"
        ])
        ransomware_impact = self._evidence_present(text, [
            r"ransom", r"\.locked\b", r"decrypt(?:or|ion)?", r"bitcoin", r"files encrypted",
            r"data encrypted for impact", r"\bT1486\b"
        ])
        suspicious_network = bool(iocs.get("domains") or iocs.get("urls")) or self._evidence_present(text, [
            r"hxxps?:\/\/", r"https?:\/\/[^\s]+", r"\b[a-z0-9.-]+\.(?:ru|cn|top|xyz|pw|tk|info)\b"
        ])

        add(failed_login, 2.0, "Failed logins / brute force")
        add(failed_login and successful_login, 1.2, "Successful login after failures")
        add(powershell, 4.0, "PowerShell or encoded command")
        add(credential_access, 6.4, "LSASS / credential access")
        add(account_priv, 5.8, "Account creation / privilege escalation")
        add(persistence, 5.5, "Scheduled task persistence")
        add(c2, 4.8, "Outbound connection / C2")
        add(suspicious_network, 1.0, "Suspicious domain or URL")
        add(exfiltration, 6.8, "Data staging / exfiltration")
        add(defense_evasion, 5.4, "Log clearing / defense evasion")
        add(ransomware_impact, 7.2, "Ransomware / impact")

        ioc_count = self._count_iocs(iocs)
        if ioc_count:
            points = min(1.0, 0.25 + (ioc_count * 0.08))
            score += points
            label = f"{ioc_count} extracted IOC{'s' if ioc_count != 1 else ''}"
            drivers.append(label)
            weighted_drivers.append({"label": label, "weight": round(points, 2)})

        mitre_count = len([item for item in mitre_techniques if isinstance(item, dict)])
        if mitre_count:
            points = min(0.7, 0.18 + (mitre_count * 0.1))
            score += points
            label = f"{mitre_count} MITRE technique{'s' if mitre_count != 1 else ''}"
            drivers.append(label)
            weighted_drivers.append({"label": label, "weight": round(points, 2)})

        stage_flags = {
            "initial_access": failed_login or successful_login,
            "execution": powershell,
            "credential_access": credential_access,
            "privilege_escalation": account_priv,
            "persistence": persistence,
            "command_and_control": c2,
            "exfiltration": exfiltration,
            "defense_evasion": defense_evasion,
            "impact": ransomware_impact,
        }
        correlated_stages = len([value for value in stage_flags.values() if value])
        if correlated_stages >= 2:
            points = min(1.1, 0.25 + (correlated_stages * 0.14))
            score += points
            drivers.append("Event correlation confidence")
            weighted_drivers.append({"label": "Event correlation confidence", "weight": round(points, 2)})

        evidence_cap = 5.0
        cap_reason = "IOC/network-only evidence"
        single_stage_caps = {
            "initial_access": 5.8,
            "execution": 6.0,
            "credential_access": 7.5,
            "privilege_escalation": 7.0,
            "persistence": 7.0,
            "command_and_control": 7.0,
            "exfiltration": 8.0,
            "defense_evasion": 7.0,
            "impact": 8.5,
        }
        active_stage_names = [name for name, value in stage_flags.items() if value]
        if len(active_stage_names) == 1:
            only_stage = active_stage_names[0]
            evidence_cap = single_stage_caps.get(only_stage, 6.0)
            cap_reason = f"single-stage cap: {only_stage.replace('_', ' ')}"
        elif correlated_stages == 2:
            evidence_cap = 7.8
            cap_reason = "two correlated attack stages"
        elif correlated_stages == 3:
            evidence_cap = 8.8
            cap_reason = "three correlated attack stages"
        elif correlated_stages == 4:
            evidence_cap = 9.4
            cap_reason = "four correlated attack stages"
        elif correlated_stages >= 5:
            evidence_cap = 9.8
            cap_reason = "broad multi-stage attack evidence"

        full_critical_chain = credential_access and c2 and exfiltration and defense_evasion
        if full_critical_chain:
            score = max(score, 9.5)
            evidence_cap = 10.0 if correlated_stages >= 5 else 9.7
            cap_reason = "credential access + C2 + exfiltration + defense evasion"
        elif (credential_access and c2) or (persistence and exfiltration) or (powershell and c2 and defense_evasion):
            score = max(score, 7.4)
        elif score == 0 and any(term in text_low for term in ["error", "warning", "failed"]):
            score = 1.4
            drivers.append("Weak suspicious log signal")
            weighted_drivers.append({"label": "Weak suspicious log signal", "weight": 1.4})

        score = max(0.0, min(score, evidence_cap, 10.0))
        confidence = min(0.95, 0.35 + (len(drivers) * 0.055) + (correlated_stages * 0.045))

        deduped_drivers = []
        deduped_weighted = []
        seen = set()
        for idx, driver in enumerate(drivers):
            key = driver.lower()
            if key not in seen:
                seen.add(key)
                deduped_drivers.append(driver)
                if idx < len(weighted_drivers):
                    deduped_weighted.append(weighted_drivers[idx])

        weighted_driver_labels = [
            f"{item['label']} (+{item['weight']})"
            for item in deduped_weighted
        ]
        if weighted_driver_labels:
            weighted_driver_labels.append(f"Evidence cap: {round(evidence_cap, 1)} ({cap_reason})")

        return {
            "score": round(score, 1),
            "level": self._level_from_score(score),
            "confidence": round(confidence, 2),
            "score_drivers": weighted_driver_labels[:10],
            "score_debug": {
                "raw_score": round(sum(item["weight"] for item in deduped_weighted), 2),
                "final_cap": round(evidence_cap, 1),
                "cap_reason": cap_reason,
                "correlated_stages": correlated_stages,
                "active_stages": active_stage_names,
                "weighted_drivers": deduped_weighted[:12],
            },
        }

    def _parse_json(self, llm_response: str):
        cleaned = self._sanitize_response(llm_response)

        if not cleaned:
            return None

        try:
            return json.loads(cleaned)
        except Exception:
            pass

        obj = self._extract_first_json_object(cleaned)
        if not obj:
            return None

        try:
            return json.loads(obj)
        except Exception:
            return None

    def _validate_cves(self, cve_ids: list):
        pattern = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
        valid = []

        for cve in cve_ids:
            if not isinstance(cve, str):
                continue
            cve = cve.strip().upper()
            if pattern.match(cve):
                valid.append(cve)

        return list(dict.fromkeys(valid))

    def _dedupe_strings(self, items):
        values = []
        seen = set()

        for item in items:
            if not isinstance(item, str):
                continue

            value = item.strip()
            if not value:
                continue

            key = value.lower()
            if key in seen:
                continue

            seen.add(key)
            values.append(value)

        return values

    def _normalize_indicator_text(self, text: str):
        text = text or ""
        return (
            text.replace("[.]", ".")
            .replace("(.)", ".")
            .replace("hxxps://", "https://")
            .replace("hxxp://", "http://")
        )

    def _clean_indicator_value(self, value: str):
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

    def _extract_iocs_from_text(self, text: str):
        normalized = self._normalize_indicator_text(text)

        urls = self._dedupe_strings([
            self._clean_indicator_value(value)
            for value in re.findall(
                r"\b(?:https?|ftp)://[^\s\"'<>]+",
                normalized,
                flags=re.IGNORECASE,
            )
        ])
        ip_addresses = self._dedupe_strings(re.findall(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            normalized,
        ))
        file_hashes = self._dedupe_strings(re.findall(
            r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b",
            normalized,
        ))
        email_addresses = self._dedupe_strings(re.findall(
            r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[A-Za-z]{2,}\b",
            normalized,
        ))
        registry_keys = self._dedupe_strings([
            self._clean_indicator_value(value)
            for value in re.findall(
                r"\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\n,;]+",
                normalized,
                flags=re.IGNORECASE,
            )
        ])
        file_paths = self._dedupe_strings([
            self._clean_indicator_value(value)
            for value in re.findall(
                r"\b[A-Za-z]:\\[^\n,;]+",
                normalized,
            )
        ])
        cve_ids = self._validate_cves(re.findall(
            r"\bCVE-\d{4}-\d{4,}\b",
            normalized,
            flags=re.IGNORECASE,
        ))
        users = self._dedupe_strings(
            re.findall(
                r"\b(?:user|username|account|targetusername|subjectusername)[=:]\s*['\"]?([A-Za-z0-9._\\-]+)['\"]?",
                normalized,
                flags=re.IGNORECASE,
            )
            + re.findall(r"\buser\s+['\"]([A-Za-z0-9._\\-]+)['\"]", normalized, flags=re.IGNORECASE)
            + re.findall(r"\bof user\s+['\"]?([A-Za-z0-9._\\-]+)['\"]?", normalized, flags=re.IGNORECASE)
        )
        processes = self._dedupe_strings([
            self._clean_indicator_value(value)
            for value in re.findall(r"\b[A-Za-z0-9._-]+\.exe\b", normalized, flags=re.IGNORECASE)
        ])

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

        standalone_domains = re.findall(
            r"\b(?=.{4,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b",
            normalized,
        )
        domains.extend([
            value
            for value in standalone_domains
            if is_valid_domain(value)
        ])

        domains = [
            value for value in self._dedupe_strings(domains)
            if value.lower() not in {email.split("@")[-1].lower() for email in email_addresses}
            and value.lower().rstrip(".") not in {user.lower().rstrip(".") for user in users}
        ]

        return {
            "ip_addresses": ip_addresses,
            "domains": domains,
            "file_hashes": file_hashes,
            "urls": urls,
            "email_addresses": email_addresses,
            "registry_keys": registry_keys,
            "file_paths": file_paths,
            "cve_ids": cve_ids,
            "users": users,
            "processes": processes,
        }

    def _merge_iocs(self, current_iocs: dict, extracted_iocs: dict):
        merged = {}

        for key in [
            "ip_addresses",
            "domains",
            "file_hashes",
            "urls",
            "email_addresses",
            "registry_keys",
            "file_paths",
            "cve_ids",
            "users",
            "processes",
        ]:
            current_values = current_iocs.get(key, [])
            extracted_values = extracted_iocs.get(key, [])

            if not isinstance(current_values, list):
                current_values = []
            if not isinstance(extracted_values, list):
                extracted_values = []

            merged[key] = self._dedupe_strings(current_values + extracted_values)

        user_values = {value.lower().rstrip(".") for value in merged.get("users", [])}
        email_domains = {email.split("@")[-1].lower() for email in merged.get("email_addresses", []) if "@" in email}
        merged["domains"] = [
            value for value in merged.get("domains", [])
            if value.lower().rstrip(".") not in user_values
            and value.lower().rstrip(".") not in email_domains
        ]

        return merged

    def _merge_mitre_techniques(self, current: list, inferred: list):
        merged = []
        seen = set()

        for item in (current or []) + (inferred or []):
            if not isinstance(item, dict):
                continue

            technique_id = str(item.get("technique_id") or "").strip()
            technique_name = str(item.get("technique_name") or "").strip()
            tactic = str(item.get("tactic") or "").strip()
            description = str(item.get("description") or "").strip()
            url = str(item.get("url") or "").strip()

            key = technique_id or f"{technique_name.lower()}::{tactic.lower()}"
            if not key or key in seen:
                continue

            seen.add(key)
            merged.append({
                "technique_id": technique_id,
                "technique_name": technique_name,
                "tactic": tactic,
                "description": description,
                "url": url,
            })

        return merged

    def _build_fallback_summary(self, input_text: str, threat_type: str, iocs: dict, mitre_techniques: list = None):
        parts = []
        if threat_type:
            parts.append(f"Potential {threat_type.lower()} activity detected")
        else:
            parts.append("Potential malicious activity detected")

        if iocs.get("domains") or iocs.get("ip_addresses"):
            parts.append("with external network indicators")

        if iocs.get("file_hashes"):
            parts.append(f"and {len(iocs['file_hashes'])} observed file hash(es)")

        summary = " ".join(parts).strip()
        if len(summary) and not summary.endswith("."):
            summary += "."

        behavior_notes = []
        text_low = (input_text or "").lower()
        if mitre_techniques:
            names = [
                item.get("technique_name", "")
                for item in mitre_techniques[:3]
                if isinstance(item, dict) and item.get("technique_name")
            ]
            if names:
                behavior_notes.append("Observed techniques included " + ", ".join(names) + ".")
        if "phishing" in text_low:
            behavior_notes.append("Initial access likely involved phishing.")
        if "powershell" in text_low:
            behavior_notes.append("PowerShell execution was observed.")
        if "run\\" in text_low or "currentversion\\run" in text_low:
            behavior_notes.append("Persistence indicators were identified.")
        if "mimikatz" in text_low or "pass-the-hash" in text_low:
            behavior_notes.append("Credential access behavior was referenced.")
        if iocs.get("domains") or iocs.get("urls"):
            network_values = (iocs.get("domains") or []) + (iocs.get("urls") or [])
            behavior_notes.append("Network indicators included " + ", ".join(network_values[:3]) + ".")

        return " ".join([summary] + behavior_notes).strip()

    def _build_sigma_rule(self, iocs: dict, input_text: str):
        selections = []
        conditions = []
        input_low = (input_text or "").lower()

        def yaml_values(values):
            cleaned = self._dedupe_strings(values or [])[:3]
            return "\n".join([f"      - '{value.replace(chr(39), chr(39) + chr(39))}'" for value in cleaned])

        process_values = list(iocs.get("processes") or [])
        if "powershell" in input_low and not any("powershell" in value.lower() for value in process_values if isinstance(value, str)):
            process_values.append("\\powershell.exe")

        process_yaml = yaml_values(process_values)
        if process_yaml:
            selections.append(f"  selection_process:\n    Image|endswith:\n{process_yaml}")
            conditions.append("selection_process")

        path_yaml = yaml_values(iocs.get("file_paths"))
        if path_yaml:
            selections.append(f"  selection_path:\n    CommandLine|contains:\n{path_yaml}")
            conditions.append("selection_path")

        registry_yaml = yaml_values(iocs.get("registry_keys"))
        if registry_yaml:
            selections.append(f"  selection_registry:\n    TargetObject|contains:\n{registry_yaml}")
            conditions.append("selection_registry")

        ip_yaml = yaml_values(iocs.get("ip_addresses"))
        if ip_yaml:
            selections.append(f"  selection_ip:\n    DestinationIp|contains:\n{ip_yaml}")
            conditions.append("selection_ip")

        domain_yaml = yaml_values(iocs.get("domains"))
        if domain_yaml:
            selections.append(f"  selection_domain:\n    DestinationHostname|contains:\n{domain_yaml}")
            conditions.append("selection_domain")

        url_yaml = yaml_values(iocs.get("urls"))
        if url_yaml:
            selections.append(f"  selection_url:\n    CommandLine|contains:\n{url_yaml}")
            conditions.append("selection_url")

        hash_yaml = yaml_values(iocs.get("file_hashes"))
        if hash_yaml:
            selections.append(f"  selection_hash:\n    Hashes|contains:\n{hash_yaml}")
            conditions.append("selection_hash")

        if not selections:
            return None

        condition = " and ".join(conditions) if len(conditions) <= 2 else f"{conditions[0]} and ({' or '.join(conditions[1:])})"
        return (
            "title: Suspicious Alert or File Analysis Activity\n"
            "id: soc-copilot-generated-alert-file-sigma\n"
            "status: experimental\n"
            "logsource:\n"
            "  product: windows\n"
            "detection:\n"
            f"{chr(10).join(selections)}\n"
            f"  condition: {condition}\n"
            "level: high"
        )

    def _build_splunk_rule(self, iocs: dict, input_text: str):
        predicates = []

        if "powershell" in (input_text or "").lower():
            predicates.append('process_name="powershell.exe"')

        for ip in iocs.get("ip_addresses", [])[:2]:
            predicates.append(f'dest_ip="{ip}"')

        for domain in iocs.get("domains", [])[:2]:
            predicates.append(f'dns_query="{domain}"')

        for path in iocs.get("file_paths", [])[:2]:
            predicates.append(f'process_path="{path}"')

        if not predicates:
            return None

        return "search index=* sourcetype=* (" + " OR ".join(predicates) + ") | stats count by host user process_name dest_ip dns_query"

    def _build_elk_rule(self, iocs: dict, input_text: str):
        clauses = []

        if "powershell" in (input_text or "").lower():
            clauses.append('process.name:"powershell.exe"')

        for domain in iocs.get("domains", [])[:2]:
            clauses.append(f'dns.question.name:"{domain}"')

        for ip in iocs.get("ip_addresses", [])[:2]:
            clauses.append(f'destination.ip:"{ip}"')

        if not clauses:
            return None

        return " or ".join(clauses)

    def _build_yara_rule(self, iocs: dict, input_text: str):
        strings = []
        idx = 1

        for value in iocs.get("domains", [])[:3]:
            strings.append(f'    $domain{idx} = "{value}" ascii nocase')
            idx += 1

        for value in iocs.get("file_paths", [])[:2]:
            strings.append(f'    $path{idx} = "{value}" ascii nocase')
            idx += 1

        if "powershell" in (input_text or "").lower():
            strings.append(f'    $proc{idx} = "powershell.exe" ascii nocase')
            idx += 1

        if len(strings) == 0:
            return None

        return (
            "rule soc_copilot_suspicious_artifacts {\n"
            "  meta:\n"
            '    author = "SOC Copilot"\n'
            '    description = "Generated from alert-analysis fallback artifacts"\n'
            "  strings:\n"
            f"{chr(10).join(strings)}\n"
            "  condition:\n"
            "    any of them\n"
            "}"
        )

    def _build_suricata_rule(self, iocs: dict):
        if iocs.get("domains"):
            domain = iocs["domains"][0]
            return (
                'alert http any any -> any any (msg:"SOC Copilot suspicious domain access"; '
                f'http.host; content:"{domain}"; nocase; sid:4200001; rev:1;)'
            )

        if iocs.get("ip_addresses"):
            ip = iocs["ip_addresses"][0]
            return (
                f'alert ip any any -> {ip} any (msg:"SOC Copilot suspicious external indicator"; sid:4200002; rev:1;)'
            )

        return None

    def _build_fallback_detection_rules(self, iocs: dict, input_text: str):
        return {
            "splunk_spl": self._build_splunk_rule(iocs=iocs, input_text=input_text),
            "elk_query": self._build_elk_rule(iocs=iocs, input_text=input_text),
            "yara_rule": self._build_yara_rule(iocs=iocs, input_text=input_text),
            "suricata_rule": self._build_suricata_rule(iocs=iocs),
            "sigma_rule": self._build_sigma_rule(iocs=iocs, input_text=input_text),
        }

    def _augment_recommended_actions(self, actions: list, level: str, threat_type: str, iocs: dict, mitre_techniques: list):
        if not isinstance(actions, list):
            actions = []

        existing = {
            str(item.get("action", "")).strip().lower()
            for item in actions
            if isinstance(item, dict)
        }

        def add_action(priority: int, action: str, description: str, responsible_team: str):
            key = action.strip().lower()
            if key in existing:
                return
            existing.add(key)
            actions.append({
                "priority": priority,
                "action": action,
                "description": description,
                "responsible_team": responsible_team,
            })

        if level in {"critical", "high"}:
            add_action(
                1,
                "Isolate impacted host and begin triage",
                "Contain the affected endpoint or workload and capture supporting evidence before remediation.",
                "IR",
            )
        if iocs.get("domains") or iocs.get("ip_addresses") or iocs.get("urls"):
            add_action(
                2,
                "Block observed indicators in network controls",
                "Deploy temporary blocks for the observed IPs, domains, and URLs and review related traffic.",
                "Network",
            )
        if iocs.get("registry_keys"):
            add_action(
                2,
                "Review registry persistence and startup artifacts",
                "Hunt for the same autorun entries or registry modifications on other endpoints.",
                "Endpoint",
            )
        if iocs.get("email_addresses") or threat_type == "Phishing":
            add_action(
                2,
                "Hunt for related phishing artifacts",
                "Search mail telemetry for the same sender, recipient, subject, or attachment patterns and quarantine related messages.",
                "SOC",
            )
        if any(item.get("tactic") == "credential-access" for item in mitre_techniques if isinstance(item, dict)):
            add_action(
                2,
                "Reset exposed credentials and review privileged activity",
                "Investigate authentication logs and rotate credentials for impacted identities.",
                "IR",
            )
        if any(item.get("technique_id") == "T1190" for item in mitre_techniques if isinstance(item, dict)) or iocs.get("cve_ids"):
            add_action(
                3,
                "Patch or mitigate the referenced vulnerability path",
                "Validate exposure for the referenced CVEs and deploy patch or compensating controls.",
                "Endpoint",
            )

        actions.sort(key=lambda item: (item.get("priority", 99), item.get("action", "")))
        return actions[:6]

    def _validate(self, result: dict, input_text: str):
        if not isinstance(result, dict):
            result = {}

        base = self._analysis_schema()
        base.update(result)
        result = base

        if not isinstance(result.get("severity"), dict):
            result["severity"] = {}

        severity = result["severity"]
        score = self._safe_float(severity.get("score"), 0.0)
        confidence = self._safe_float(severity.get("confidence"), 0.0)
        level = str(severity.get("level") or "").lower().strip()

        rag_sources = result.get("rag_sources")
        if not isinstance(rag_sources, list):
            rag_sources = []
            result["rag_sources"] = rag_sources

        if len(rag_sources) == 0:
            confidence = min(confidence if confidence > 0 else 0.6, 0.6)

        text_low = (input_text or "").lower()
        heuristic_observables = self.intel_analyzer.extract_observables(input_text)
        extracted_iocs = self._merge_iocs(
            self._extract_iocs_from_text(input_text),
            {
                "ip_addresses": heuristic_observables.get("ip_addresses", []),
                "domains": heuristic_observables.get("domains", []),
                "file_hashes": heuristic_observables.get("file_hashes", []),
                "urls": heuristic_observables.get("urls", []),
                "email_addresses": heuristic_observables.get("email_addresses", []),
                "registry_keys": heuristic_observables.get("registry_keys", []),
                "file_paths": heuristic_observables.get("file_paths", []),
                "cve_ids": heuristic_observables.get("cve_ids", []),
                "users": heuristic_observables.get("users", []),
                "processes": heuristic_observables.get("processes", []),
            },
        )
        inferred_threat_type = self.intel_analyzer.infer_threat_type(input_text)
        inferred_mitre = self.intel_analyzer.infer_mitre_techniques(input_text)
        inferred_kill_chain = self.intel_analyzer.infer_kill_chain_phase(
            text=input_text,
            techniques=inferred_mitre,
        )
        inferred_systems = self.intel_analyzer.infer_affected_systems(input_text)

        if any(term in text_low for term in ["test", "sandbox", "poc", "demo"]):
            fp = self._safe_float(result.get("false_positive_likelihood"), 0.0)
            result["false_positive_likelihood"] = max(fp, 0.7)

            reasons = result.get("false_positive_reasons")
            if not isinstance(reasons, list):
                reasons = []
            reasons.append("Input contains test/sandbox/poc/demo indicators")
            result["false_positive_reasons"] = list(dict.fromkeys(reasons))

        if any(term in text_low for term in ["encrypted", "ransom", ".locked", "bitcoin", "decrypt"]):
            result["threat_type"] = "Ransomware"
            score = max(score, 8.5)
            level = "critical"

        current_threat_type = str(result.get("threat_type") or "").strip()
        if not current_threat_type or current_threat_type.lower() in {"unknown", "info"}:
            if inferred_threat_type and inferred_threat_type != "Unknown":
                result["threat_type"] = inferred_threat_type

        if "phishing" in text_low and not result.get("threat_type"):
            result["threat_type"] = "Phishing"

        if any(term in text_low for term in ["malware", "trojan", "payload", "backdoor"]) and not result.get("threat_type"):
            result["threat_type"] = "Malware"

        has_lateral = any(term in text_low for term in ["mimikatz", "pass-the-hash", "psexec"])
        has_c2 = any(term in text_low for term in ["cobalt strike", "beaconing", "exfiltrat"])
        if has_lateral and has_c2:
            score = max(score, 9.0)
            level = "critical"

        if any(term in text_low for term in ["powershell", "currentversion\\run", "beaconed", "c2", "command and control"]):
            score = max(score, 7.5)
            if level not in {"critical"}:
                level = "high"

        current_mitre = result.get("mitre_techniques")
        if not isinstance(current_mitre, list):
            current_mitre = []
        merged_mitre = self._merge_mitre_techniques(current=current_mitre, inferred=inferred_mitre)
        result["mitre_techniques"] = merged_mitre

        if len(merged_mitre) >= 2:
            confidence = max(confidence, 0.78)
            score = max(score, 7.0)
        if any(item.get("tactic") == "command-and-control" for item in merged_mitre if isinstance(item, dict)) and any(
            item.get("tactic") in {"persistence", "credential-access"} for item in merged_mitre if isinstance(item, dict)
        ):
            score = max(score, 8.4)
            if level != "critical":
                level = "high"
            confidence = max(confidence, 0.84)

        affected_systems = result.get("affected_systems")
        if not isinstance(affected_systems, list):
            affected_systems = []
        result["affected_systems"] = self._dedupe_strings(affected_systems + inferred_systems)

        if not result.get("kill_chain_phase") and inferred_kill_chain:
            result["kill_chain_phase"] = inferred_kill_chain

        cves = result.get("cve_ids")
        if not isinstance(cves, list):
            cves = []

        iocs = result.get("iocs")
        if not isinstance(iocs, dict):
            iocs = {}

        ioc_cves = iocs.get("cve_ids")
        if not isinstance(ioc_cves, list):
            ioc_cves = []

        merged_cves = self._validate_cves(cves + ioc_cves + extracted_iocs.get("cve_ids", []))
        result["cve_ids"] = merged_cves

        iocs.setdefault("ip_addresses", [])
        iocs.setdefault("domains", [])
        iocs.setdefault("file_hashes", [])
        iocs.setdefault("urls", [])
        iocs.setdefault("email_addresses", [])
        iocs.setdefault("registry_keys", [])
        iocs.setdefault("file_paths", [])
        iocs.setdefault("users", [])
        iocs.setdefault("processes", [])
        iocs["cve_ids"] = merged_cves
        iocs = self._merge_iocs(iocs, extracted_iocs)
        iocs["cve_ids"] = merged_cves
        result["iocs"] = iocs

        detection_rules = result.get("detection_rules")
        if not isinstance(detection_rules, dict):
            detection_rules = {}

        fallback_rules = self._build_fallback_detection_rules(iocs=iocs, input_text=input_text)
        for key, value in fallback_rules.items():
            if detection_rules.get(key) in [None, "", []] and value:
                detection_rules[key] = value
        result["detection_rules"] = detection_rules

        if not result.get("summary") or len(str(result.get("summary", "")).strip()) < 40:
            result["summary"] = self._build_fallback_summary(
                input_text=input_text,
                threat_type=result.get("threat_type"),
                iocs=iocs,
                mitre_techniques=merged_mitre,
            )

        if not result.get("title"):
            first_indicator = (
                (iocs.get("domains") or [])
                or (iocs.get("ip_addresses") or [])
                or (iocs.get("file_paths") or [])
            )
            indicator = first_indicator[0] if first_indicator else "detected indicators"
            title_prefix = result.get("threat_type") or "Threat"
            result["title"] = f"{title_prefix} activity involving {indicator}"

        dynamic_severity = self._dynamic_severity_from_evidence(
            input_text=input_text,
            iocs=iocs,
            mitre_techniques=merged_mitre,
        )
        score = dynamic_severity["score"]
        level = dynamic_severity["level"]
        confidence = dynamic_severity["confidence"] if dynamic_severity.get("score_drivers") else min(confidence, dynamic_severity["confidence"])
        severity["score_drivers"] = dynamic_severity["score_drivers"]
        severity["score_debug"] = dynamic_severity.get("score_debug", {})
        drivers_text = ", ".join(dynamic_severity["score_drivers"][:5])
        severity["justification"] = (
            f"Severity dynamically scored from observed evidence: {drivers_text}."
            if drivers_text
            else "Severity dynamically scored as informational because no meaningful attack evidence was observed."
        )

        score = max(0.0, min(score, 10.0))
        confidence = max(0.0, min(confidence, 1.0))
        level = self._level_from_score(score)

        severity["score"] = score
        severity["confidence"] = confidence
        severity["level"] = level
        if not severity.get("justification"):
            key_tactics = [
                item.get("tactic", "")
                for item in merged_mitre[:3]
                if isinstance(item, dict) and item.get("tactic")
            ]
            tactics_text = ", ".join(key_tactics) if key_tactics else "execution, persistence, network, and credential-access"
            severity["justification"] = f"Severity inferred from observed {tactics_text} indicators and extracted observables."
        result["severity"] = severity

        actions = result.get("recommended_actions")
        result["recommended_actions"] = self._augment_recommended_actions(
            actions=actions,
            level=level,
            threat_type=result.get("threat_type"),
            iocs=iocs,
            mitre_techniques=merged_mitre,
        )

        return result

    async def analyze(self, project, input_text, input_type="alert"):
        analysis_input = input_text
        if hasattr(self.generation_client, "process_text"):
            analysis_input = self.generation_client.process_text(input_text)

        if analysis_input != input_text:
            self.logger.info(
                "SOC analysis input truncated from %s to %s characters for %s",
                len(input_text or ""),
                len(analysis_input or ""),
                input_type,
            )

        try:
            rag_documents = await self.nlp_controller.retrieve_relevant_context(
                project=project,
                text=analysis_input,
                limit=self.app_settings.RAG_TOP_K,
            )
        except Exception as exc:
            self.logger.warning("RAG retrieval failed for %s: %s", input_type, exc)
            rag_documents = []

        if not isinstance(rag_documents, list):
            rag_documents = []

        rag_sources = [
            {
                "text": doc.text,
                "score": self._safe_float(doc.score, 0.0)
            }
            for doc in rag_documents
        ]

        system_prompt = self._build_system_prompt()
        user_prompt = self._build_user_prompt(
            input_text=analysis_input,
            input_type=input_type,
            rag_sources=rag_sources,
        )

        chat_history = [
            self.generation_client.construct_prompt(
                prompt=system_prompt,
                role=self.generation_client.enums.SYSTEM.value,
            )
        ]

        llm_response = self.generation_client.generate_text(
            prompt=user_prompt,
            chat_history=chat_history,
            max_output_tokens=2000,
            temperature=0.05,
        )

        parsed = self._parse_json(llm_response)
        validated = self._validate(parsed, input_text=analysis_input)
        validated["rag_sources"] = rag_sources

        return validated

    async def analyze_security_input(self, project, input_text: str,
                                     input_type: str = "alert", limit: int = 5):
        result = await self.analyze(project=project, input_text=input_text, input_type=input_type)
        return result, None

    def build_db_record(self, result, input_text, input_type):
        severity = result.get("severity", {})

        return ThreatAnalysis(
            input_text=input_text,
            input_type=input_type,
            title=result.get("title"),
            threat_type=result.get("threat_type"),
            risk_level=severity.get("level", "info"),
            risk_score=self._safe_float(severity.get("score"), 0.0),
            confidence=self._safe_float(severity.get("confidence"), 0.0),
            analysis_result=result,
            mitre_techniques=result.get("mitre_techniques", []),
            iocs=result.get("iocs", {}),
            detection_rules=result.get("detection_rules", {}),
        )
