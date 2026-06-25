from .BaseController import BaseController
from modules.threat_intel import ThreatIntelAnalyzer
import json
import re


class InvestigationController(BaseController):

    def __init__(self, generation_client):
        super().__init__()
        self.generation_client = generation_client
        self.intel_analyzer = ThreatIntelAnalyzer()

    def _investigation_schema(self):
        return {
            "investigation_title": "",
            "attack_story": "narrative paragraph",
            "overall_severity": {"score": 0.0, "level": "info", "confidence": 0.0},
            "threat_actor": None,
            "malware_family": None,
            "pivot_points": [],
            "timeline": [],
            "kill_chain": [],
            "current_stage": "",
            "current_stage_description": "",
            "next_steps_prediction": [],
            "recommended_actions": [],
            "iocs": {"ip_addresses": [], "domains": [], "file_hashes": [], "urls": [], "users": [], "processes": []},
            "detection_rules": {"splunk_spl": None, "elk_query": None, "sigma_rule": None},
            "total_events_analyzed": 0,
            "false_positive_likelihood": 0.0,
            "false_positive_reasons": [],
        }

    def _build_system_prompt(self):
        return (
            "You are SOC Copilot Investigation Analyst. Return ONLY valid JSON with this exact schema and keys:\n"
            "{\n"
            "  \"investigation_title\": \"...\",\n"
            "  \"attack_story\": \"narrative paragraph\",\n"
            "  \"overall_severity\": {\"score\": 0.0, \"level\": \"...\", \"confidence\": 0.0},\n"
            "  \"threat_actor\": null,\n"
            "  \"malware_family\": null,\n"
            "  \"pivot_points\": [{\"type\": \"ip|user|hash|domain|process\", \"value\": \"...\", \"seen_in_events\": [1,2]}],\n"
            "  \"timeline\": [{\"event_number\": 1, \"timestamp\": \"...\", \"description\": \"...\", \"tactic\": \"...\", \"technique_id\": \"TXXXX\", \"technique_name\": \"...\", \"confidence\": 0.0, \"evidence\": \"...\"}],\n"
            "  \"kill_chain\": [{\"phase\": \"...\", \"techniques\": [\"TXXXX\"], \"completed\": true}],\n"
            "  \"current_stage\": \"...\",\n"
            "  \"current_stage_description\": \"...\",\n"
            "  \"next_steps_prediction\": [{\"technique_id\": \"TXXXX\", \"technique_name\": \"...\", \"description\": \"...\"}],\n"
            "  \"recommended_actions\": [{\"priority\": 1, \"action\": \"...\", \"description\": \"...\", \"responsible_team\": \"...\"}],\n"
            "  \"iocs\": {\"ip_addresses\": [], \"domains\": [], \"file_hashes\": [], \"urls\": [], \"users\": [], \"processes\": []},\n"
            "  \"detection_rules\": {\"splunk_spl\": null, \"elk_query\": null, \"sigma_rule\": null},\n"
            "  \"total_events_analyzed\": 0\n"
            "}\n"
            "Always populate detection_rules.sigma_rule when process, command-line, network, domain, URL, or registry evidence exists. "
            "Make the Sigma YAML valid and suitable for deployment to detect or block recurrence of the correlated attack."
        )

    def _build_user_prompt(self, events: list):
        event_text = "\n\n".join([
            f"=== EVENT {idx + 1} ===\n{event}"
            for idx, event in enumerate(events)
        ])

        return f"Analyze these correlated security events and respond as JSON only:\n\n{event_text}"

    def _sanitize_response(self, text: str):

        if not text:
            return ""

        cleaned = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL | re.IGNORECASE).strip()

        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```[a-zA-Z0-9_\-]*", "", cleaned).strip()
            cleaned = re.sub(r"```$", "", cleaned).strip()

        return cleaned

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

    def _safe_float(self, value, default: float = 0.0):
        try:
            return float(value)
        except Exception:
            return default

    def _normalize_level(self, level: str, score: float):
        valid_levels = {"critical", "high", "medium", "low", "info"}
        if score >= 9.0:
            score_level = "critical"
        elif score >= 7.0:
            score_level = "high"
        elif score >= 4.0:
            score_level = "medium"
        elif score >= 1.0:
            score_level = "low"
        else:
            score_level = "info"

        if isinstance(level, str) and level.lower() in valid_levels:
            level = level.lower()
            severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            return score_level if severity_rank[score_level] > severity_rank[level] else level

        return score_level

    def _dedupe_strings(self, values):
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
            for value in re.findall(r"\b(?:https?|ftp)://[^\s\"'<>]+", normalized, flags=re.IGNORECASE)
        ])
        ip_addresses = self._dedupe_strings(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", normalized))
        file_hashes = self._dedupe_strings(re.findall(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b", normalized))

        users = self._dedupe_strings(
            [match[1] for match in re.findall(r"\b(user|username)[=:]\s*['\"]?([A-Za-z0-9._\\-]+)['\"]?\b", normalized, flags=re.IGNORECASE)]
            + re.findall(r"\buser\s+['\"]([A-Za-z0-9._\\-]+)['\"]", normalized, flags=re.IGNORECASE)
            + re.findall(r"\bof user\s+['\"]?([A-Za-z0-9._\\-]+)['\"]?", normalized, flags=re.IGNORECASE)
        )

        process_candidates = re.findall(r"\b[A-Za-z0-9._-]+\.exe\b", normalized, flags=re.IGNORECASE)
        processes = self._dedupe_strings([
            self._clean_indicator_value(value)
            for value in process_candidates
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
            if value.lower().rstrip(".") not in {user.lower().rstrip(".") for user in users}
        ]

        return {
            "ip_addresses": ip_addresses,
            "domains": domains,
            "file_hashes": file_hashes,
            "urls": urls,
            "users": users,
            "processes": processes,
        }

    def _merge_iocs(self, current_iocs: dict, extracted_iocs: dict):
        merged = {}
        keys = ["ip_addresses", "domains", "file_hashes", "urls", "users", "processes"]

        for key in keys:
            current_values = current_iocs.get(key, []) if isinstance(current_iocs, dict) else []
            extracted_values = extracted_iocs.get(key, []) if isinstance(extracted_iocs, dict) else []

            if not isinstance(current_values, list):
                current_values = []
            if not isinstance(extracted_values, list):
                extracted_values = []

            merged[key] = self._dedupe_strings(current_values + extracted_values)

        user_values = {value.lower().rstrip(".") for value in merged.get("users", [])}
        merged["domains"] = [
            value for value in merged.get("domains", [])
            if not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value.lower().rstrip("."))
            and value.lower().split(".")[-1] not in {"php", "asp", "aspx", "jsp", "cgi", "pl", "exe", "dll", "ps1", "bat", "cmd", "zip", "rar", "7z", "pdf", "doc", "docx", "bin"}
            and not re.search(r"\b(?:shell|payload|dropper|loader|beacon|stage|update|install|setup|backup)\.[a-z0-9]{2,5}$", value.lower().rstrip("."))
            and value.lower().rstrip(".") not in user_values
        ]

        return merged

    def _sigma_values(self, values, limit=5, max_length=180):
        cleaned = []
        for value in values or []:
            if value in [None, "", []]:
                continue
            value = self._clean_indicator_value(str(value))
            if not value:
                continue
            if len(value) > max_length:
                value = value[:max_length].rstrip()
            cleaned.append(value)

        deduped = self._dedupe_strings(cleaned)[:limit]
        return "\n".join([f"      - '{value.replace(chr(39), chr(39) + chr(39))}'" for value in deduped])

    def _build_sigma_rule(self, iocs: dict, events: list = None):
        events = events or []
        selections = []
        conditions = []

        processes = list(iocs.get("processes", []) or [])
        parent_processes = []
        ips = list(iocs.get("ip_addresses", []) or [])
        domains = list(iocs.get("domains", []) or [])
        urls = list(iocs.get("urls", []) or [])
        command_lines = []
        registry_keys = []

        for event in events:
            if not isinstance(event, dict):
                continue
            if event.get("process"):
                processes.append(event["process"])
            if event.get("parent_process"):
                parent_processes.append(event["parent_process"])
            if event.get("destination_ip"):
                ips.append(event["destination_ip"])
            if event.get("destination_host"):
                domains.append(event["destination_host"])
            if event.get("http_path"):
                urls.append(event["http_path"])
            if event.get("command_line"):
                command_lines.append(event["command_line"])
            if event.get("registry_key"):
                registry_keys.append(event["registry_key"])

        process_values = self._sigma_values(processes)
        if process_values:
            selections.append(f"  selection_process:\n    Image|endswith:\n{process_values}")
            conditions.append("selection_process")

        parent_values = self._sigma_values(parent_processes)
        if parent_values:
            selections.append(f"  selection_parent:\n    ParentImage|endswith:\n{parent_values}")
            conditions.append("selection_parent")

        command_values = self._sigma_values(command_lines, limit=4)
        if command_values:
            selections.append(f"  selection_command:\n    CommandLine|contains:\n{command_values}")
            conditions.append("selection_command")

        ip_values = self._sigma_values(ips)
        if ip_values:
            selections.append(f"  selection_ip:\n    DestinationIp|contains:\n{ip_values}")
            conditions.append("selection_ip")

        domain_values = self._sigma_values(domains)
        if domain_values:
            selections.append(f"  selection_domain:\n    DestinationHostname|contains:\n{domain_values}")
            conditions.append("selection_domain")

        url_values = self._sigma_values(urls)
        if url_values:
            selections.append(f"  selection_url:\n    CommandLine|contains:\n{url_values}")
            conditions.append("selection_url")

        registry_values = self._sigma_values(registry_keys)
        if registry_values:
            selections.append(f"  selection_registry:\n    TargetObject|contains:\n{registry_values}")
            conditions.append("selection_registry")

        if len(selections) == 0:
            return None

        if len(conditions) == 1:
            condition = conditions[0]
        elif "selection_process" in conditions and len(conditions) > 1:
            remaining = [item for item in conditions if item != "selection_process"]
            condition = f"selection_process and ({' or '.join(remaining)})"
        else:
            condition = " or ".join(conditions)

        return (
            "title: Investigation Chain Detection and Prevention\n"
            "id: soc-copilot-generated-investigation-chain\n"
            "status: experimental\n"
            "description: Detects the correlated process, command, network, and persistence indicators from this investigation so recurrence can be blocked or hunted.\n"
            "tags:\n"
            "  - attack.execution\n"
            "  - attack.defense-evasion\n"
            "  - attack.command-and-control\n"
            "logsource:\n"
            "  product: windows\n"
            "detection:\n"
            f"{chr(10).join(selections)}\n"
            f"  condition: {condition}\n"
            "fields:\n"
            "  - Image\n"
            "  - ParentImage\n"
            "  - CommandLine\n"
            "  - DestinationIp\n"
            "  - DestinationHostname\n"
            "  - TargetObject\n"
            "falsepositives:\n"
            "  - Authorized administration, testing, or software deployment activity matching the same indicators.\n"
            "level: high"
        )

    def _build_splunk_rule(self, iocs: dict):
        predicates = []

        for process_name in iocs.get("processes", [])[:2]:
            predicates.append(f'process_name="{process_name}"')

        for ip in iocs.get("ip_addresses", [])[:2]:
            predicates.append(f'dest_ip="{ip}"')

        for domain in iocs.get("domains", [])[:2]:
            predicates.append(f'dns_query="{domain}"')

        if len(predicates) == 0:
            return None

        return "search index=* sourcetype=* (" + " OR ".join(predicates) + ") | stats count by host user process_name dest_ip dns_query"

    def _build_elk_rule(self, iocs: dict):
        clauses = []

        for process_name in iocs.get("processes", [])[:2]:
            clauses.append(f'process.name:"{process_name}"')

        for domain in iocs.get("domains", [])[:2]:
            clauses.append(f'dns.question.name:"{domain}"')

        for ip in iocs.get("ip_addresses", [])[:2]:
            clauses.append(f'destination.ip:"{ip}"')

        if len(clauses) == 0:
            return None

        return " or ".join(clauses)

    def _build_fallback_detection_rules(self, iocs: dict, events: list = None):
        return {
            "splunk_spl": self._build_splunk_rule(iocs=iocs),
            "elk_query": self._build_elk_rule(iocs=iocs),
            "sigma_rule": self._build_sigma_rule(iocs=iocs, events=events),
        }

    def _extract_field(self, text: str, patterns):
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                return self._clean_indicator_value(match.group(1))
        return ""

    def _parse_event_record(self, event_number: int, event_text: str):
        observables = self.intel_analyzer.extract_observables(event_text)
        technique_matches = self.intel_analyzer.infer_mitre_techniques(event_text)

        timestamp = self._extract_field(event_text, [
            r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})?)",
        ])
        event_id = self._extract_field(event_text, [r"\bEventID[=:]\s*([A-Za-z0-9_-]+)"])
        user = self._extract_field(event_text, [
            r"\b(?:User|Username|Account|TargetUserName|SubjectUserName)[=:]\s*([^\s,;]+)",
            r"\bAccepted password for\s+([A-Za-z0-9._\\-]+)\b",
        ])
        process = self._extract_field(event_text, [
            r"\b(?:Image|Process|NewProcessName|ProcessName)[=:]\s*([^\s,;]+)",
        ])
        parent_process = self._extract_field(event_text, [
            r"\b(?:ParentImage|ParentProcessName)[=:]\s*([^\s,;]+)",
        ])
        destination_ip = self._extract_field(event_text, [
            r"\b(?:DestinationIp|DestinationIP|DestIp|RemoteAddress|IpAddress)[=:]\s*([^\s,;]+)",
        ])
        destination_host = self._extract_field(event_text, [
            r"\b(?:DestinationHostname|DestinationHost|DnsQuery|Domain|Host)[=:]\s*([^\s,;]+)",
        ])
        destination_port = self._extract_field(event_text, [
            r"\b(?:DestinationPort|DestPort|Port)[=:]\s*([^\s,;]+)",
        ])
        registry_key = self._extract_field(event_text, [
            r"\b(?:TargetObject|RegistryPath|RegKey)[=:]\s*(.+?)(?=$|\s[A-Za-z]+[=:])",
        ])
        command_line = self._extract_field(event_text, [
            r"\b(?:CommandLine|CmdLine|Command)[=:]\s*(.+?)(?=$|\s[A-Za-z]+[=:])",
        ])
        http_method = ""
        http_path = ""
        http_match = re.search(
            r"\"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\"\s]+)\s+HTTP/[0-9.]+\"",
            event_text,
            flags=re.IGNORECASE,
        )
        if http_match:
            http_method = http_match.group(1).upper()
            http_path = self._clean_indicator_value(http_match.group(2))

        source_ip = self._extract_field(event_text, [
            r"\b(?:SourceIp|SourceIP|SrcIp|ClientIp|RemoteHost)[=:]\s*([^\s,;]+)",
        ])
        if not source_ip and http_match and observables.get("ip_addresses"):
            source_ip = observables["ip_addresses"][0]

        if not user and observables.get("users"):
            user = observables["users"][0]
        if not process and observables.get("processes"):
            process = observables["processes"][0]
        if not destination_ip and observables.get("ip_addresses"):
            destination_ip = observables["ip_addresses"][0]
        if source_ip and destination_ip == source_ip and http_match:
            destination_ip = ""
        if not destination_host and observables.get("domains"):
            destination_host = observables["domains"][0]
        if not registry_key and observables.get("registry_keys"):
            registry_key = observables["registry_keys"][0]

        return {
            "event_number": event_number,
            "raw": event_text,
            "timestamp": timestamp or None,
            "event_id": event_id or None,
            "user": user or None,
            "source_ip": source_ip or None,
            "process": process or None,
            "parent_process": parent_process or None,
            "destination_ip": destination_ip or None,
            "destination_host": destination_host or None,
            "destination_port": destination_port or None,
            "http_method": http_method or None,
            "http_path": http_path or None,
            "registry_key": registry_key or None,
            "command_line": command_line or None,
            "observables": observables,
            "techniques": technique_matches,
        }

    def _describe_event(self, record: dict):
        event_id = str(record.get("event_id") or "")
        process = record.get("process")
        parent_process = record.get("parent_process")
        destination_ip = record.get("destination_ip")
        destination_host = record.get("destination_host")
        destination_port = record.get("destination_port")
        registry_key = record.get("registry_key")
        user = record.get("user")
        source_ip = record.get("source_ip")
        http_method = record.get("http_method")
        http_path = record.get("http_path")

        if http_method and http_path:
            source = f" from {source_ip}" if source_ip else ""
            lowered_path = http_path.lower()
            if "cmd=" in lowered_path:
                return f"Web shell command execution{source} via {http_path}"
            if any(term in lowered_path for term in ["upload", "shell", "phpmyadmin"]):
                return f"Suspicious inbound web request{source} to {http_path}"
            return f"Inbound web request{source} to {http_path}"

        raw_low = str(record.get("raw") or "").lower()
        if "accepted password" in raw_low:
            source = f" from {source_ip or destination_ip}" if (source_ip or destination_ip) else ""
            account = f" for {user}" if user else ""
            return f"Successful SSH login{account}{source}"

        if "/etc/shadow" in raw_low or "/etc/passwd" in raw_low:
            return "Credential file access observed on Linux host"

        if event_id == "4688" or (process and parent_process):
            description = "Process execution observed"
            if parent_process and process:
                description = f"{parent_process} spawned {process}"
            elif process:
                description = f"Process creation for {process}"
            if user:
                description += f" under user {user}"
            return description

        if event_id == "3" or destination_ip or destination_host:
            target = destination_host or destination_ip or "remote destination"
            description = f"Outbound network communication to {target}"
            if process:
                description = f"{process} initiated outbound communication to {target}"
            if destination_port:
                description += f" over port {destination_port}"
            return description

        if event_id == "13" or registry_key:
            description = f"Registry persistence change on {registry_key}" if registry_key else "Registry modification observed"
            if process:
                description += f" associated with {process}"
            return description

        if record.get("command_line"):
            return f"Command execution observed: {record['command_line'][:160]}"

        return record.get("raw", "")[:180]

    def _select_primary_technique(self, record: dict):
        techniques = record.get("techniques") or []
        if len(techniques) == 0:
            return {}

        event_id = str(record.get("event_id") or "")
        http_path = str(record.get("http_path") or "").lower()

        def first_by_tactic(*tactics):
            for tactic in tactics:
                for item in techniques:
                    if item.get("tactic") == tactic:
                        return item
            return {}

        if event_id == "13" or record.get("registry_key"):
            match = first_by_tactic("persistence")
            if match:
                return match

        if http_path:
            if "cmd=" in http_path:
                match = first_by_tactic("execution", "persistence", "initial-access")
                if match:
                    return match
            if any(term in http_path for term in ["upload", "shell", "phpmyadmin"]):
                match = first_by_tactic("persistence", "initial-access", "execution")
                if match:
                    return match
            match = first_by_tactic("initial-access")
            if match:
                return match

        if event_id == "3":
            match = first_by_tactic("command-and-control")
            if match:
                return match

        if record.get("process") or record.get("parent_process") or record.get("command_line"):
            match = first_by_tactic("credential-access", "execution")
            if match:
                return match

        if record.get("destination_ip") or record.get("destination_host"):
            match = first_by_tactic("command-and-control")
            if match:
                return match

        return techniques[0]

    def _build_fallback_timeline(self, events: list):
        timeline = []

        for record in events:
            primary = self._select_primary_technique(record)
            timeline.append({
                "event_number": record.get("event_number"),
                "timestamp": record.get("timestamp"),
                "description": self._describe_event(record),
                "tactic": primary.get("tactic", "unknown"),
                "technique_id": primary.get("technique_id", ""),
                "technique_name": primary.get("technique_name", ""),
                "confidence": 0.88 if primary else 0.6,
                "evidence": record.get("raw", "")[:220],
            })

        return timeline

    def _build_fallback_kill_chain(self, timeline: list):
        kill_chain = []
        seen = set()

        for item in timeline:
            if not isinstance(item, dict):
                continue

            phase = str(item.get("tactic") or "").strip()
            technique_id = str(item.get("technique_id") or "").strip()
            if not phase or phase == "unknown":
                continue

            if phase not in seen:
                seen.add(phase)
                kill_chain.append({
                    "phase": phase,
                    "techniques": [technique_id] if technique_id else [],
                    "completed": True,
                })
                continue

            for chain_item in kill_chain:
                if chain_item.get("phase") == phase and technique_id:
                    techniques = chain_item.get("techniques", [])
                    if technique_id not in techniques:
                        techniques.append(technique_id)
                        chain_item["techniques"] = techniques
                    break

        return kill_chain

    def _build_pivot_points_from_events(self, events: list):
        pivot_map = {}

        def add_pivot(pivot_type: str, value: str, event_number: int):
            cleaned = self._clean_indicator_value(value)
            if not cleaned:
                return
            key = (pivot_type, cleaned.lower())
            if key not in pivot_map:
                pivot_map[key] = {"type": pivot_type, "value": cleaned, "seen_in_events": set()}
            pivot_map[key]["seen_in_events"].add(event_number)

        for record in events:
            event_number = record.get("event_number")
            observables = record.get("observables") or {}

            for value in observables.get("ip_addresses", [])[:4]:
                add_pivot("ip", value, event_number)
            for value in observables.get("domains", [])[:4]:
                add_pivot("domain", value, event_number)
            for value in observables.get("file_hashes", [])[:3]:
                add_pivot("hash", value, event_number)
            for value in observables.get("processes", [])[:3]:
                add_pivot("process", value, event_number)
            for value in observables.get("users", [])[:3]:
                add_pivot("user", value, event_number)

            if record.get("process"):
                add_pivot("process", record["process"], event_number)
            if record.get("user"):
                add_pivot("user", record["user"], event_number)
            if record.get("destination_ip"):
                add_pivot("ip", record["destination_ip"], event_number)
            if record.get("destination_host"):
                add_pivot("domain", record["destination_host"], event_number)

        pivot_points = []
        for item in pivot_map.values():
            pivot_points.append({
                "type": item["type"],
                "value": item["value"],
                "seen_in_events": sorted(item["seen_in_events"]),
            })

        pivot_points.sort(key=lambda item: (-len(item["seen_in_events"]), item["type"], item["value"].lower()))
        return pivot_points[:12]

    def _derive_current_stage(self, kill_chain: list, timeline: list):
        if isinstance(kill_chain, list) and len(kill_chain):
            phase = str(kill_chain[-1].get("phase") or "").strip()
            if phase:
                return phase, f"The most recent correlated phase in the chain is {phase}."

        if isinstance(timeline, list) and len(timeline):
            phase = str(timeline[-1].get("tactic") or "").strip()
            if phase:
                return phase, f"The latest event aligns with the {phase} stage."

        return "", ""

    def _predict_next_steps(self, current_stage: str):
        mapping = {
            "initial-access": [
                {"technique_id": "T1059.001", "technique_name": "PowerShell", "description": "The actor may move into script-based execution after initial delivery."},
                {"technique_id": "T1105", "technique_name": "Ingress Tool Transfer", "description": "Additional payload retrieval may follow the initial access step."},
            ],
            "execution": [
                {"technique_id": "T1547.001", "technique_name": "Registry Run Keys / Startup Folder", "description": "Persistence is a common next step after execution."},
                {"technique_id": "T1071.001", "technique_name": "Web Protocols", "description": "The actor may establish command-and-control over web protocols."},
            ],
            "persistence": [
                {"technique_id": "T1003.001", "technique_name": "LSASS Memory", "description": "Credential access may follow successful persistence."},
                {"technique_id": "T1071.001", "technique_name": "Web Protocols", "description": "The actor may maintain communication with external infrastructure."},
            ],
            "credential-access": [
                {"technique_id": "T1021.002", "technique_name": "SMB/Windows Admin Shares", "description": "Harvested credentials may enable lateral movement."},
            ],
            "command-and-control": [
                {"technique_id": "T1041", "technique_name": "Exfiltration Over C2 Channel", "description": "Established C2 may be used for data staging or exfiltration."},
                {"technique_id": "T1021.002", "technique_name": "SMB/Windows Admin Shares", "description": "The actor may pivot to additional systems after maintaining C2."},
            ],
            "lateral-movement": [
                {"technique_id": "T1041", "technique_name": "Exfiltration Over C2 Channel", "description": "Lateral movement may be followed by collection and exfiltration."},
            ],
        }

        return mapping.get(current_stage, [])

    def _augment_actions(self, actions: list, level: str, iocs: dict, events: list):
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
                "Isolate impacted endpoints and preserve evidence",
                "Contain the affected systems, capture volatile data, and preserve logs for deeper forensic review.",
                "SOC",
            )
        if iocs.get("ip_addresses") or iocs.get("domains"):
            add_action(
                2,
                "Block observed network indicators",
                "Push temporary blocks for the observed domains and IP addresses and review related proxy, DNS, and firewall telemetry.",
                "Network",
            )
        if iocs.get("users") and any("credential" in (event.get("raw", "").lower()) or "mimikatz" in (event.get("raw", "").lower()) for event in events):
            add_action(
                2,
                "Reset affected credentials and review privileged access",
                "Force password resets for the impacted identities and review authentication activity around the same time window.",
                "IR",
            )
        if iocs.get("processes"):
            add_action(
                3,
                "Hunt for the same process chain across endpoints",
                "Search EDR and Windows event telemetry for the same parent-child process chain and associated command lines.",
                "IR",
            )
        if any(iocs.get(key) for key in ["ip_addresses", "domains", "urls", "processes"]) or any(
            event.get("command_line") or event.get("registry_key") for event in events
        ):
            add_action(
                2,
                "Deploy the generated Sigma prevention rule",
                "Convert the Investigation Chain Sigma rule to the target SIEM or EDR policy and use it to alert on or block the same attack pattern.",
                "Detection Engineering",
            )
        if any(event.get("registry_key") for event in events):
            add_action(
                3,
                "Review autorun persistence locations",
                "Check registry autorun keys and startup locations for related persistence on similar hosts.",
                "Endpoint",
            )

        actions.sort(key=lambda item: (item.get("priority", 99), item.get("action", "")))
        return actions[:6]

    def _parse_json(self, llm_response: str):

        cleaned = self._sanitize_response(llm_response)

        if not cleaned:
            return None

        try:
            return json.loads(cleaned)
        except Exception:
            pass

        json_obj = self._extract_first_json_object(cleaned)
        if not json_obj:
            return None

        try:
            return json.loads(json_obj)
        except Exception:
            return None

    def _validate(self, data: dict, events: list):

        if not isinstance(data, dict):
            data = {}

        base = self._investigation_schema()
        base.update(data)
        data = base

        if not isinstance(data.get("overall_severity"), dict):
            data["overall_severity"] = {}

        severity = data["overall_severity"]
        score = self._safe_float(severity.get("score"), 0.0)
        confidence = self._safe_float(severity.get("confidence"), 0.0)
        level = str(severity.get("level") or "").lower().strip()

        joined_events = "\n".join(events)
        event_text = joined_events.lower()
        heuristic_iocs = self.intel_analyzer.extract_observables(joined_events)
        extracted_iocs = self._merge_iocs(
            current_iocs=self._extract_iocs_from_text(joined_events),
            extracted_iocs={
                "ip_addresses": heuristic_iocs.get("ip_addresses", []),
                "domains": heuristic_iocs.get("domains", []),
                "file_hashes": heuristic_iocs.get("file_hashes", []),
                "urls": heuristic_iocs.get("urls", []),
                "users": heuristic_iocs.get("users", []),
                "processes": heuristic_iocs.get("processes", []),
            },
        )
        parsed_events = [
            self._parse_event_record(event_number=idx + 1, event_text=event)
            for idx, event in enumerate(events)
        ]
        fallback_timeline = self._build_fallback_timeline(parsed_events)
        fallback_kill_chain = self._build_fallback_kill_chain(fallback_timeline)
        fallback_pivots = self._build_pivot_points_from_events(parsed_events)

        iocs = data.get("iocs")
        if not isinstance(iocs, dict):
            iocs = {}
        iocs = self._merge_iocs(current_iocs=iocs, extracted_iocs=extracted_iocs)
        data["iocs"] = iocs

        if any(term in event_text for term in ["test", "sandbox", "poc", "demo"]):
            fp = self._safe_float(data.get("false_positive_likelihood"), 0.0)
            data["false_positive_likelihood"] = max(fp, 0.7)

            reasons = data.get("false_positive_reasons")
            if not isinstance(reasons, list):
                reasons = []
            reasons.append("Investigation includes test/sandbox/poc/demo indicators")
            data["false_positive_reasons"] = list(dict.fromkeys(reasons))

        if any(term in event_text for term in ["encrypted", "ransom", ".locked", "bitcoin", "decrypt"]):
            score = max(score, 8.5)
            level = "critical"

        has_webshell = any(term in event_text for term in ["webshell", "web shell", "shell.php", "upload.php", "cmd=", "www-data"])
        has_remote_command = any(term in event_text for term in ["cmd=whoami", "cmd=id", "command=/bin/bash", "/bin/bash", "bash -i", " sh -i"])
        has_reverse_shell = any(term in event_text for term in ["reverse shell", "outbound connection", ":4444", "/dev/tcp/", "nc -e"])
        has_sensitive_access = any(term in event_text for term in ["/etc/shadow", "/etc/passwd", "config.php", "database dump", "mysqldump"])
        has_successful_login = any(term in event_text for term in ["accepted password", "login successful", "ssh2"])
        has_privilege_escalation = any(term in event_text for term in ["sudo:", "user=root", "tty=pts", "privilege escalation"])

        has_lateral = any(term in event_text for term in ["mimikatz", "pass-the-hash", "psexec"])
        has_c2 = any(term in event_text for term in ["cobalt strike", "beaconing", "exfiltrat", "outbound connection", ":4444", "/dev/tcp/"])
        if has_lateral and has_c2:
            score = max(score, 9.0)
            level = "critical"

        if has_webshell:
            score = max(score, 7.8)
            if level not in {"critical"}:
                level = "high"
            confidence = max(confidence, 0.78)

        if has_webshell and has_remote_command:
            score = max(score, 8.6)
            if level not in {"critical"}:
                level = "high"
            confidence = max(confidence, 0.84)

        if has_webshell and (has_reverse_shell or has_c2):
            score = max(score, 8.9)
            if level not in {"critical"}:
                level = "high"
            confidence = max(confidence, 0.86)

        if has_webshell and (has_sensitive_access or has_privilege_escalation or has_successful_login):
            score = max(score, 9.2)
            level = "critical"
            confidence = max(confidence, 0.88)

        if any(term in event_text for term in ["powershell", "currentversion\\run", "destinationip", "destinationhostname", "beacon"]):
            score = max(score, 7.5)
            if level not in {"critical"}:
                level = "high"
            confidence = max(confidence, 0.65)

        if len(fallback_kill_chain) >= 3:
            score = max(score, 8.2)
            confidence = max(confidence, 0.8)
        if len(fallback_pivots) >= 3:
            confidence = max(confidence, 0.82)

        if not data.get("investigation_title"):
            lead_indicator = (
                (iocs.get("processes") or [])
                or (iocs.get("domains") or [])
                or (iocs.get("ip_addresses") or [])
            )
            indicator = lead_indicator[0] if lead_indicator else "correlated events"
            data["investigation_title"] = f"Investigation chain involving {indicator}"

        attack_story = data.get("attack_story")
        if not isinstance(attack_story, str) or not attack_story.strip() or attack_story.strip().lower() == "narrative paragraph":
            parts = [f"Analyzed {len(events)} correlated event(s)."]
            if iocs.get("processes"):
                parts.append(f"Observed process execution involving {', '.join(iocs['processes'][:3])}.")
            if iocs.get("ip_addresses") or iocs.get("domains"):
                network_values = (iocs.get("ip_addresses") or []) + (iocs.get("domains") or [])
                parts.append(f"Network indicators included {', '.join(network_values[:3])}.")
            if "currentversion\\run" in event_text:
                parts.append("Persistence behavior was identified via registry autorun changes.")
            if fallback_kill_chain:
                parts.append(
                    "Observed attack phases: " + ", ".join([
                        item.get("phase", "")
                        for item in fallback_kill_chain[:4]
                        if isinstance(item, dict) and item.get("phase")
                    ]) + "."
                )
            data["attack_story"] = " ".join(parts).strip()

        if len(fallback_timeline):
            data["timeline"] = fallback_timeline

        if len(fallback_kill_chain):
            data["kill_chain"] = fallback_kill_chain

        if len(fallback_pivots):
            data["pivot_points"] = fallback_pivots

        current_stage, current_stage_description = self._derive_current_stage(
            kill_chain=data.get("kill_chain"),
            timeline=data.get("timeline"),
        )
        if current_stage:
            data["current_stage"] = current_stage
        if current_stage_description:
            data["current_stage_description"] = current_stage_description

        next_steps = data.get("next_steps_prediction")
        if not isinstance(next_steps, list) or len(next_steps) == 0:
            data["next_steps_prediction"] = self._predict_next_steps(data.get("current_stage", ""))

        score = max(0.0, min(score, 10.0))
        confidence = max(0.0, min(confidence, 1.0))
        level = self._normalize_level(level=level, score=score)

        severity["score"] = score
        severity["level"] = level
        severity["confidence"] = confidence
        data["overall_severity"] = severity

        detection_rules = data.get("detection_rules")
        if not isinstance(detection_rules, dict):
            detection_rules = {}

        fallback_rules = self._build_fallback_detection_rules(iocs=iocs, events=parsed_events)
        for key, value in fallback_rules.items():
            if detection_rules.get(key) in [None, "", []] and value:
                detection_rules[key] = value
        data["detection_rules"] = detection_rules

        actions = data.get("recommended_actions")
        data["recommended_actions"] = self._augment_actions(
            actions=actions,
            level=level,
            iocs=iocs,
            events=parsed_events,
        )
        data["total_events_analyzed"] = len(events)

        return data

    async def investigate(self, events):
        system_prompt = self._build_system_prompt()
        user_prompt = self._build_user_prompt(events=events)

        chat_history = [
            self.generation_client.construct_prompt(
                prompt=system_prompt,
                role=self.generation_client.enums.SYSTEM.value,
            )
        ]

        llm_response = self.generation_client.generate_text(
            prompt=user_prompt,
            chat_history=chat_history,
            max_output_tokens=3000,
            temperature=0.05,
        )

        parsed = self._parse_json(llm_response=llm_response)
        validated = self._validate(data=parsed, events=events)

        return validated

    async def analyze_investigation_chain(self, events: list):
        result = await self.investigate(events=events)
        return result, None
