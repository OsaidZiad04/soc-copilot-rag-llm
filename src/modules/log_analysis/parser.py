import re
from typing import List
from modules.event import Event


class LogParser:

    def __init__(self):
        self.ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        self.ts_pattern = re.compile(
            r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})?)"
        )
        self.user_pattern = re.compile(r"\buser(?:name)?[=: ]+([A-Za-z0-9._-]+)", re.IGNORECASE)
        self.action_keywords = {
            "login_failed": ["failed login", "authentication failed", "invalid password"],
            "login_success": ["login success", "authentication success", "accepted password"],
            "command_execution": ["cmd=", "command executed", "powershell", "bash -c", "wget ", "curl "],
        }

    def _extract_action(self, line: str) -> str:
        lower_line = line.lower()
        for action, keys in self.action_keywords.items():
            if any(k in lower_line for k in keys):
                return action
        return "unknown"

    def _extract_status(self, line: str, action: str) -> str:
        lower_line = line.lower()
        if action == "login_failed":
            return "failed"
        if action == "login_success":
            return "success"
        if "failed" in lower_line:
            return "failed"
        if "success" in lower_line or "accepted" in lower_line:
            return "success"
        return "unknown"

    def _extract_command(self, line: str) -> str:
        command_match = re.search(r"(?:cmd=|command=)(.+)$", line, flags=re.IGNORECASE)
        if command_match:
            return command_match.group(1).strip()

        for marker in ["powershell", "bash -c", "wget ", "curl "]:
            idx = line.lower().find(marker)
            if idx >= 0:
                return line[idx:].strip()

        return ""

    def parse_line(self, line: str) -> Event:
        ip_match = self.ip_pattern.search(line)
        ts_match = self.ts_pattern.search(line)
        user_match = self.user_pattern.search(line)

        action = self._extract_action(line=line)
        status = self._extract_status(line=line, action=action)
        command = self._extract_command(line=line)

        return Event(
            ip=ip_match.group(0) if ip_match else None,
            timestamp=ts_match.group(1) if ts_match else None,
            action=action,
            status=status,
            user=user_match.group(1) if user_match else None,
            command=command if len(command) else None,
            raw=line,
            metadata={"parser": "regex_v1"},
        )

    def parse_text(self, raw_logs: str) -> List[Event]:
        lines = [line.strip() for line in raw_logs.splitlines() if line.strip()]
        return [self.parse_line(line=line) for line in lines]

