from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any
from modules.event import Event


class CorrelationEngine:

    def __init__(self, failed_threshold: int = 3, window_minutes: int = 15):
        self.failed_threshold = failed_threshold
        self.window_minutes = window_minutes

    def _parse_ts(self, ts: str):
        if not ts:
            return None

        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                return datetime.strptime(ts, fmt)
            except Exception:
                continue

        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return None

    def _group_key(self, event: Event):
        return (event.ip or "unknown_ip", event.user or "unknown_user")

    def _event_to_dict(self, event: Event):
        if hasattr(event, "model_dump"):
            return event.model_dump()
        return event.dict()

    def _within_window(self, start: datetime, now: datetime):
        if not start or not now:
            return False
        return (now - start) <= timedelta(minutes=self.window_minutes)

    def correlate(self, events: List[Event]) -> Dict[str, Any]:
        grouped = defaultdict(list)
        patterns = []

        for event in events:
            grouped[self._group_key(event)].append(event)

        for key, group_events in grouped.items():
            group_events.sort(key=lambda e: self._parse_ts(e.timestamp) or datetime.min)

            failed_login_times = []
            has_success_after_failed = False
            has_command_after_success = False
            first_failure_ts = None
            success_ts = None

            for event in group_events:
                ts = self._parse_ts(event.timestamp)

                if event.action == "login_failed" or event.status == "failed":
                    failed_login_times.append(ts)
                    if first_failure_ts is None:
                        first_failure_ts = ts

                if event.action == "login_success" and len(failed_login_times):
                    has_success_after_failed = True
                    success_ts = ts

                if has_success_after_failed and event.action == "command_execution":
                    if success_ts and ts and ts >= success_ts:
                        has_command_after_success = True

            if len([x for x in failed_login_times if x is not None]) >= self.failed_threshold:
                recent_failed = [
                    x for x in failed_login_times
                    if x is not None and first_failure_ts and self._within_window(first_failure_ts, x)
                ]
                if len(recent_failed) >= self.failed_threshold:
                    patterns.append({
                        "pattern": "multiple_failed_logins",
                        "group": {"ip": key[0], "user": key[1]},
                        "count": len(recent_failed),
                        "window_minutes": self.window_minutes,
                    })

            if has_success_after_failed and has_command_after_success:
                patterns.append({
                    "pattern": "failed_success_command_chain",
                    "group": {"ip": key[0], "user": key[1]},
                    "window_minutes": self.window_minutes,
                })

        return {
            "groups": {
                f"{ip}|{user}": [self._event_to_dict(event) for event in group_events]
                for (ip, user), group_events in grouped.items()
            },
            "patterns": patterns,
            "total_groups": len(grouped),
        }
