import base64
import hashlib
import re
from abc import ABC, abstractmethod
from itertools import combinations
from typing import Any, Dict, List, Optional

try:
    import yaml
except Exception:
    yaml = None


SUPPORTED_OPERATORS = {
    "contains",
    "startswith",
    "endswith",
    "regex",
    "base64",
    "wildcard",
    "exact",
}

OPERATOR_ALIASES = {
    "re": "regex",
    "base64offset": "base64",
}

CONTROL_MODIFIERS = {"all"}


class SigmaConversionEngine:

    def __init__(self):
        self.converters = {
            converter.platform: converter
            for converter in [
                SplunkConverter(),
                SentinelKQLConverter(),
                ElasticKQLConverter(),
                ElasticEQLConverter(),
                OpenSearchDQLConverter(),
                QRadarAQLConverter(),
                SumoLogicConverter(),
                GraylogConverter(),
                LogScaleConverter(),
                SnortConverter(),
                SuricataConverter(),
                CrowdStrikeConverter(),
                DefenderXDRConverter(),
                SentinelOneConverter(),
                CarbonBlackConverter(),
                GoogleSecOpsConverter(),
                OsquerySQLConverter(),
            ]
        }

    def supported_platforms(self):
        return [
            {
                "platform": platform,
                "name": converter.name,
                "category": converter.category,
            }
            for platform, converter in self.converters.items()
        ]

    def validate(self, sigma_rule: str, filename: Optional[str] = None):
        parsed = self.parse(sigma_rule=sigma_rule, filename=filename)
        return {
            "valid": len(parsed["errors"]) == 0,
            "rule": parsed["rule"],
            "selectors": parsed["selectors"],
            "errors": parsed["errors"],
            "warnings": parsed["warnings"],
            "supported_platforms": self.supported_platforms(),
        }

    def convert(self, sigma_rule: str, platforms: Optional[List[str]] = None,
                filename: Optional[str] = None):
        parsed = self.parse(sigma_rule=sigma_rule, filename=filename)
        selected_platforms = self._select_platforms(platforms=platforms)
        conversions = []

        for platform in selected_platforms:
            converter = self.converters.get(platform)
            if converter is None:
                parsed["errors"].append({
                    "field": "platforms",
                    "code": "unsupported_platform",
                    "message": f"Unsupported platform: {platform}",
                })
                continue

            try:
                query = converter.convert(parsed)
                conversions.append({
                    "platform": converter.platform,
                    "name": converter.name,
                    "category": converter.category,
                    "query": query,
                    "errors": [],
                })
            except Exception as exc:
                conversions.append({
                    "platform": converter.platform,
                    "name": converter.name,
                    "category": converter.category,
                    "query": "",
                    "errors": [{
                        "field": converter.platform,
                        "code": "conversion_failed",
                        "message": str(exc),
                    }],
                })

        return {
            "valid": len(parsed["errors"]) == 0,
            "rule": parsed["rule"],
            "selectors": parsed["selectors"],
            "conversions": conversions,
            "errors": parsed["errors"],
            "warnings": parsed["warnings"],
            "supported_platforms": self.supported_platforms(),
        }

    def bulk_convert(self, rules: List[dict], platforms: Optional[List[str]] = None):
        results = []

        for index, item in enumerate(rules or []):
            sigma_rule = item.get("sigma_rule") or item.get("content") or ""
            filename = item.get("filename")
            item_platforms = item.get("platforms") or platforms
            result = self.convert(
                sigma_rule=sigma_rule,
                platforms=item_platforms,
                filename=filename,
            )
            result["index"] = index
            result["filename"] = filename
            results.append(result)

        return {
            "total": len(results),
            "converted": len([item for item in results if item.get("valid")]),
            "results": results,
            "supported_platforms": self.supported_platforms(),
        }

    def parse(self, sigma_rule: str, filename: Optional[str] = None):
        errors = []
        warnings = []
        sigma_rule = sigma_rule or ""

        if filename:
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            if ext not in {"yml", "yaml"}:
                errors.append({
                    "field": "filename",
                    "code": "unsupported_extension",
                    "message": "Sigma files must use .yml or .yaml.",
                })

        if not sigma_rule.strip():
            errors.append({
                "field": "sigma_rule",
                "code": "empty_rule",
                "message": "Sigma rule content is required.",
            })
            return self._empty_parse(errors=errors, warnings=warnings)

        try:
            raw = self._load_yaml(sigma_rule)
        except Exception as exc:
            errors.append({
                "field": "sigma_rule",
                "code": "yaml_parse_failed",
                "message": str(exc),
            })
            return self._empty_parse(errors=errors, warnings=warnings)

        if not isinstance(raw, dict):
            errors.append({
                "field": "sigma_rule",
                "code": "invalid_schema",
                "message": "Sigma YAML must parse into an object.",
            })
            return self._empty_parse(errors=errors, warnings=warnings)

        rule = {
            "title": raw.get("title") or "",
            "id": raw.get("id") or "",
            "description": raw.get("description") or "",
            "tags": raw.get("tags") if isinstance(raw.get("tags"), list) else [],
            "logsource": raw.get("logsource") if isinstance(raw.get("logsource"), dict) else {},
            "detection": raw.get("detection") if isinstance(raw.get("detection"), dict) else {},
            "condition": "",
            "level": raw.get("level") or "",
        }

        if not rule["title"]:
            errors.append({
                "field": "title",
                "code": "missing_title",
                "message": "Sigma rule title is required.",
            })

        if not rule["detection"]:
            errors.append({
                "field": "detection",
                "code": "missing_detection",
                "message": "Sigma detection block is required.",
            })

        condition = rule["detection"].get("condition") if isinstance(rule["detection"], dict) else None
        if not isinstance(condition, str) or not condition.strip():
            errors.append({
                "field": "detection.condition",
                "code": "missing_condition",
                "message": "Sigma detection condition is required.",
            })
            condition = ""
        rule["condition"] = condition.strip()

        selectors = self._extract_selectors(rule["detection"], errors, warnings)

        if not selectors and rule["detection"]:
            errors.append({
                "field": "detection",
                "code": "missing_selectors",
                "message": "At least one detection selector is required.",
            })

        self._validate_condition(rule["condition"], selectors, errors, warnings)

        return {
            "raw": raw,
            "rule": rule,
            "selectors": selectors,
            "errors": errors,
            "warnings": warnings,
        }

    def _empty_parse(self, errors: list, warnings: list):
        return {
            "raw": {},
            "rule": {
                "title": "",
                "id": "",
                "description": "",
                "tags": [],
                "logsource": {},
                "detection": {},
                "condition": "",
                "level": "",
            },
            "selectors": {},
            "errors": errors,
            "warnings": warnings,
        }

    def _select_platforms(self, platforms: Optional[List[str]]):
        if not platforms:
            return list(self.converters.keys())

        selected = []
        for platform in platforms:
            platform = str(platform or "").strip().lower()
            if platform and platform not in selected:
                selected.append(platform)
        return selected

    def _load_yaml(self, sigma_rule: str):
        if yaml is not None:
            return yaml.safe_load(sigma_rule)
        return self._fallback_yaml_load(sigma_rule)

    def _fallback_yaml_load(self, sigma_rule: str):
        data = {}
        current_top = None
        current_selector = None
        current_field = None

        for raw_line in sigma_rule.splitlines():
            if not raw_line.strip() or raw_line.lstrip().startswith("#"):
                continue

            indent = len(raw_line) - len(raw_line.lstrip(" "))
            text = raw_line.strip()

            if indent == 0:
                key, value = self._split_yaml_pair(text)
                current_top = key
                current_selector = None
                current_field = None
                if value == "":
                    data[key] = [] if key == "tags" else {}
                else:
                    data[key] = self._parse_yaml_scalar(value)
                continue

            if current_top == "tags" and text.startswith("- "):
                data.setdefault("tags", []).append(self._parse_yaml_scalar(text[2:]))
                continue

            if current_top == "logsource" and indent >= 2:
                key, value = self._split_yaml_pair(text)
                data.setdefault("logsource", {})[key] = self._parse_yaml_scalar(value)
                continue

            if current_top == "detection" and indent == 2:
                key, value = self._split_yaml_pair(text)
                if key == "condition":
                    data.setdefault("detection", {})["condition"] = self._parse_yaml_scalar(value)
                else:
                    data.setdefault("detection", {})[key] = {}
                    current_selector = key
                    current_field = None
                continue

            if current_top == "detection" and indent == 4 and current_selector:
                key, value = self._split_yaml_pair(text)
                current_field = key
                if value == "":
                    data["detection"][current_selector][key] = []
                else:
                    data["detection"][current_selector][key] = self._parse_yaml_scalar(value)
                continue

            if current_top == "detection" and indent >= 6 and current_selector and current_field and text.startswith("- "):
                value = self._parse_yaml_scalar(text[2:])
                current_values = data["detection"][current_selector].setdefault(current_field, [])
                if not isinstance(current_values, list):
                    current_values = [current_values]
                current_values.append(value)
                data["detection"][current_selector][current_field] = current_values

        return data

    def _split_yaml_pair(self, text: str):
        if ":" not in text:
            return text.strip(), ""
        key, value = text.split(":", 1)
        return key.strip(), value.strip()

    def _parse_yaml_scalar(self, value: Any):
        if not isinstance(value, str):
            return value

        value = value.strip()
        if value.startswith(("'", '"')) and value.endswith(("'", '"')) and len(value) >= 2:
            return value[1:-1]

        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            if not inner:
                return []
            return [self._parse_yaml_scalar(item.strip()) for item in inner.split(",")]

        if value.lower() == "true":
            return True
        if value.lower() == "false":
            return False
        return value

    def _extract_selectors(self, detection: dict, errors: list, warnings: list):
        selectors = {}

        for selector, body in (detection or {}).items():
            if selector == "condition":
                continue

            if isinstance(body, list):
                keyword_values = [
                    value for value in body
                    if value not in [None, ""] and not isinstance(value, dict)
                ]
                selectors[selector] = []
                if keyword_values:
                    selectors[selector].append(self._build_criterion(
                        selector=selector,
                        field_expression="message|contains",
                        values=keyword_values,
                        errors=errors,
                        warnings=warnings,
                    ))

                dict_values = [value for value in body if isinstance(value, dict)]
                if dict_values:
                    warnings.append({
                        "field": f"detection.{selector}",
                        "code": "list_selector_approximated",
                        "message": "List-based map selectors are flattened for conversion.",
                    })
                    for item in dict_values:
                        for field_expression, values in item.items():
                            criterion = self._build_criterion(
                                selector=selector,
                                field_expression=field_expression,
                                values=values,
                                errors=errors,
                                warnings=warnings,
                            )
                            if criterion:
                                selectors[selector].append(criterion)
                continue

            if not isinstance(body, dict):
                errors.append({
                    "field": f"detection.{selector}",
                    "code": "invalid_selector",
                    "message": "Detection selector must be an object.",
                })
                continue

            criteria = []
            for field_expression, values in body.items():
                criterion = self._build_criterion(
                    selector=selector,
                    field_expression=field_expression,
                    values=values,
                    errors=errors,
                    warnings=warnings,
                )
                if criterion:
                    criteria.append(criterion)

            selectors[selector] = criteria

        return selectors

    def _build_criterion(self, selector: str, field_expression: str, values: Any,
                         errors: list, warnings: list):
        parts = str(field_expression or "").split("|")
        field = parts[0].strip()
        modifiers = [OPERATOR_ALIASES.get(part.strip().lower(), part.strip().lower()) for part in parts[1:] if part.strip()]

        unsupported = [
            modifier for modifier in modifiers
            if modifier not in SUPPORTED_OPERATORS and modifier not in CONTROL_MODIFIERS
        ]
        for modifier in unsupported:
            errors.append({
                "field": f"detection.{selector}.{field_expression}",
                "code": "unsupported_operator",
                "message": f"Unsupported Sigma operator: {modifier}",
            })

        operators = [modifier for modifier in modifiers if modifier in SUPPORTED_OPERATORS]
        operator = operators[0] if operators else "exact"
        value_list = self._normalize_values(values)
        if operator == "exact" and any("*" in value or "?" in value for value in value_list):
            operator = "wildcard"

        if not value_list:
            warnings.append({
                "field": f"detection.{selector}.{field_expression}",
                "code": "empty_values",
                "message": "Detection field has no values.",
            })

        return {
            "selector": selector,
            "field": field,
            "field_expression": field_expression,
            "operator": operator,
            "modifiers": modifiers,
            "all": "all" in modifiers,
            "values": value_list,
        }

    def _normalize_values(self, values: Any):
        if values is None:
            return []
        if isinstance(values, list):
            return [str(value) for value in values if value not in [None, ""]]
        if isinstance(values, dict):
            return [str(value) for value in values.values() if value not in [None, ""]]
        return [str(values)]

    def _validate_condition(self, condition: str, selectors: dict, errors: list, warnings: list):
        if not condition:
            return

        selector_names = set(selectors.keys())

        def validate_of_expression(match):
            amount = match.group(1).lower()
            target = match.group(2)
            if amount.isdigit() and int(amount) > 1:
                warnings.append({
                    "field": "detection.condition",
                    "code": "numeric_of_condition",
                    "message": f"Condition '{amount} of {target}' is expanded into equivalent boolean combinations.",
                })

            if target.lower() == "them":
                if amount.isdigit() and int(amount) > len(selector_names):
                    errors.append({
                        "field": "detection.condition",
                        "code": "condition_count_exceeds_selectors",
                        "message": f"Condition requires {amount} selectors but only {len(selector_names)} exist.",
                    })
                return " "

            prefix = target.replace("*", "")
            matched = [name for name in selector_names if name.startswith(prefix)]
            if not matched:
                errors.append({
                    "field": "detection.condition",
                    "code": "unknown_condition_selector",
                    "message": f"Condition selector pattern does not match any selector: {target}",
                })
            elif amount.isdigit() and int(amount) > len(matched):
                errors.append({
                    "field": "detection.condition",
                    "code": "condition_count_exceeds_selectors",
                    "message": f"Condition requires {amount} selectors for {target} but only {len(matched)} match.",
                })
            return " "

        scrubbed = re.sub(
            r"(?<![A-Za-z0-9_.-])(all|\d+)\s+of\s+(them|[A-Za-z0-9_*.-]+)",
            validate_of_expression,
            condition,
            flags=re.IGNORECASE,
        )
        scrubbed = re.sub(r"\b(and|or|not)\b", " ", scrubbed, flags=re.IGNORECASE)
        scrubbed = re.sub(r"[()]", " ", scrubbed)

        for token in re.findall(r"[A-Za-z0-9_.-]+", scrubbed):
            if token in selector_names:
                continue
            if token.isdigit():
                continue
            errors.append({
                "field": "detection.condition",
                "code": "unknown_condition_selector",
                "message": f"Condition references an unknown selector: {token}",
            })


class BaseSigmaConverter(ABC):
    platform = ""
    name = ""
    category = ""
    field_map = {}
    equality = ":"
    and_token = "AND"
    or_token = "OR"
    not_token = "NOT"

    def convert(self, parsed: dict):
        selectors = {}
        for selector, criteria in parsed.get("selectors", {}).items():
            selectors[selector] = self._criteria_expression(criteria)

        expression = self._condition_expression(parsed.get("rule", {}).get("condition", ""), selectors)
        return self._wrap_query(parsed, expression)

    def _criteria_expression(self, criteria: list):
        expressions = []
        for criterion in criteria:
            values = [
                self._criterion_expression(criterion, value)
                for value in criterion.get("values", [])
            ]
            values = [value for value in values if value]
            if not values:
                continue

            joiner = f" {self.and_token} " if criterion.get("all") else f" {self.or_token} "
            expressions.append(self._group(joiner.join(values)))

        return f" {self.and_token} ".join(expressions) if expressions else ""

    def _condition_expression(self, condition: str, selectors: dict):
        condition = condition or ""
        if not condition:
            return f" {self.or_token} ".join([self._group(value) for value in selectors.values() if value])

        expression = condition
        expression = self._expand_of_expression(expression, selectors)

        for selector in sorted(selectors.keys(), key=len, reverse=True):
            expression = re.sub(
                rf"(?<![A-Za-z0-9_.-]){re.escape(selector)}(?![A-Za-z0-9_.-])",
                lambda _match, selector=selector: self._group(selectors[selector] or "*"),
                expression,
            )

        expression = re.sub(r"\band\b", self.and_token, expression, flags=re.IGNORECASE)
        expression = re.sub(r"\bor\b", self.or_token, expression, flags=re.IGNORECASE)
        expression = re.sub(r"\bnot\b", self.not_token, expression, flags=re.IGNORECASE)
        return expression

    def _expand_of_expression(self, expression: str, selectors: dict):
        all_values = [self._group(value) for value in selectors.values() if value]

        def join_expressions(values: list, amount: str):
            if not values:
                return "*"
            amount = str(amount).lower()
            if amount == "all":
                return f" {self.and_token} ".join(values)
            count = int(amount)
            if count <= 1:
                return f" {self.or_token} ".join(values)
            if count >= len(values):
                return f" {self.and_token} ".join(values)

            groups = [
                self._group(f" {self.and_token} ".join(combo))
                for combo in combinations(values, count)
            ]
            return f" {self.or_token} ".join(groups)

        expression = re.sub(
            r"(?<![A-Za-z0-9_.-])(all|\d+)\s+of\s+them(?![A-Za-z0-9_.-])",
            lambda match: join_expressions(all_values, match.group(1)),
            expression,
            flags=re.IGNORECASE,
        )

        def replace_match(match):
            amount = match.group(1).lower()
            prefix = match.group(2).replace("*", "")
            matched = [
                self._group(value)
                for name, value in selectors.items()
                if name.startswith(prefix) and value
            ]
            return join_expressions(matched, amount)

        return re.sub(
            r"(?<![A-Za-z0-9_.-])(all|\d+)\s+of\s+([A-Za-z0-9_*.-]+)",
            replace_match,
            expression,
            flags=re.IGNORECASE,
        )

    def _criterion_expression(self, criterion: dict, value: str):
        field = self.field_name(criterion.get("field"))
        return self.operator_expression(field, criterion.get("operator"), value)

    def field_name(self, field: str):
        key = re.sub(r"[^a-z0-9]", "", str(field or "").lower())
        return self.field_map.get(key, field or "message")

    @abstractmethod
    def operator_expression(self, field: str, operator: str, value: str):
        raise NotImplementedError

    def _wrap_query(self, parsed: dict, expression: str):
        return expression or "*"

    def _group(self, expression: str):
        if not expression:
            return ""
        return f"({expression})"

    def quote(self, value: str):
        return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'

    def wildcard_value(self, operator: str, value: str):
        if operator == "contains":
            return f"*{value}*"
        if operator == "startswith":
            return f"{value}*"
        if operator == "endswith":
            return f"*{value}"
        return value

    def regex_value(self, value: str):
        return str(value).replace("/", "\\/")

    def base64_value(self, value: str):
        return base64.b64encode(str(value).encode("utf-8")).decode("utf-8")


class SearchConverter(BaseSigmaConverter):

    def operator_expression(self, field: str, operator: str, value: str):
        if operator == "regex":
            return f"{field}=/.*{self.regex_value(value)}.*/"
        if operator == "base64":
            return f"{field}{self.equality}{self.quote(self.base64_value(value))}"
        if operator == "wildcard":
            return f"{field}{self.equality}{self.quote(value)}"
        return f"{field}{self.equality}{self.quote(self.wildcard_value(operator, value))}"


class SplunkConverter(SearchConverter):
    platform = "splunk"
    name = "Splunk SPL"
    category = "SIEM"
    equality = "="
    field_map = {
        "image": "process_path",
        "parentimage": "parent_process_path",
        "commandline": "process",
        "processcommandline": "process",
        "destinationip": "dest_ip",
        "sourceip": "src_ip",
        "destinationhostname": "dest_host",
        "queryname": "dns_query",
        "targetobject": "registry_path",
        "hashes": "file_hash",
        "user": "user",
        "username": "user",
        "eventid": "EventCode",
    }

    def _wrap_query(self, parsed: dict, expression: str):
        return f"search index=* sourcetype=* {expression or '*'}"


class ElasticKQLConverter(SearchConverter):
    platform = "elastic_kql"
    name = "Elastic KQL"
    category = "SIEM"
    equality = " : "
    field_map = {
        "image": "process.executable",
        "parentimage": "process.parent.executable",
        "commandline": "process.command_line",
        "processcommandline": "process.command_line",
        "destinationip": "destination.ip",
        "sourceip": "source.ip",
        "destinationhostname": "destination.domain",
        "queryname": "dns.question.name",
        "targetobject": "registry.path",
        "hashes": "file.hash",
        "user": "user.name",
        "username": "user.name",
        "eventid": "event.code",
    }


class ElasticEQLConverter(ElasticKQLConverter):
    platform = "elastic_eql"
    name = "Elastic EQL"
    category = "SIEM"
    equality = " == "

    def operator_expression(self, field: str, operator: str, value: str):
        if operator in {"contains", "startswith", "endswith", "wildcard"}:
            return f"{field} : {self.quote(self.wildcard_value(operator, value))}"
        if operator == "regex":
            return f"{field} regex~ {self.quote(value)}"
        if operator == "base64":
            return f"{field} == {self.quote(self.base64_value(value))}"
        return f"{field} == {self.quote(value)}"

    def _wrap_query(self, parsed: dict, expression: str):
        return f"any where {expression or 'true'}"


class OpenSearchDQLConverter(ElasticKQLConverter):
    platform = "opensearch_dql"
    name = "OpenSearch DQL"
    category = "SIEM"


class SentinelKQLConverter(SearchConverter):
    platform = "sentinel_kql"
    name = "Microsoft Sentinel KQL"
    category = "SIEM"
    equality = " == "
    field_map = {
        "image": "FileName",
        "parentimage": "InitiatingProcessFileName",
        "commandline": "ProcessCommandLine",
        "processcommandline": "ProcessCommandLine",
        "destinationip": "RemoteIP",
        "sourceip": "LocalIP",
        "destinationhostname": "RemoteUrl",
        "queryname": "RemoteUrl",
        "targetobject": "RegistryKey",
        "hashes": "SHA256",
        "user": "AccountName",
        "username": "AccountName",
        "eventid": "ActionType",
    }

    def operator_expression(self, field: str, operator: str, value: str):
        if operator == "regex":
            return f"{field} matches regex {self.quote(value)}"
        if operator == "base64":
            return f"{field} == {self.quote(self.base64_value(value))}"
        if operator in {"contains", "startswith", "endswith", "wildcard"}:
            return f"{field} contains {self.quote(value)}"
        return f"{field} == {self.quote(value)}"

    def _wrap_query(self, parsed: dict, expression: str):
        return f"DeviceEvents\n| where {expression or 'true'}"


class QRadarAQLConverter(SearchConverter):
    platform = "qradar_aql"
    name = "QRadar AQL"
    category = "SIEM"
    equality = " = "
    field_map = {
        "image": "processname",
        "parentimage": "parentprocessname",
        "commandline": "UTF8(payload)",
        "processcommandline": "UTF8(payload)",
        "destinationip": "destinationip",
        "sourceip": "sourceip",
        "destinationhostname": "hostname",
        "queryname": "hostname",
        "targetobject": "UTF8(payload)",
        "hashes": "UTF8(payload)",
        "user": "username",
        "username": "username",
        "eventid": "qid",
    }

    def quote_single(self, value: str):
        return "'" + str(value).replace("'", "''") + "'"

    def operator_expression(self, field: str, operator: str, value: str):
        if operator == "regex":
            return f"{field} MATCHES {self.quote_single(value)}"
        if operator == "base64":
            return f"{field} = {self.quote_single(self.base64_value(value))}"
        if operator in {"contains", "startswith", "endswith", "wildcard"} or field == "UTF8(payload)":
            return f"LOWER({field}) LIKE LOWER({self.quote_single('%' + value + '%')})"
        return f"{field} = {self.quote_single(value)}"

    def _wrap_query(self, parsed: dict, expression: str):
        return f"SELECT * FROM events WHERE {expression or '1=1'}"


class SumoLogicConverter(SearchConverter):
    platform = "sumologic"
    name = "Sumo Logic"
    category = "SIEM"
    equality = "="
    field_map = {
        "image": "process",
        "parentimage": "parent_process",
        "commandline": "command_line",
        "processcommandline": "command_line",
        "destinationip": "dest_ip",
        "sourceip": "src_ip",
        "destinationhostname": "dest_host",
        "queryname": "dns_query",
        "targetobject": "registry_path",
        "hashes": "file_hash",
        "user": "user",
        "username": "user",
        "eventid": "event_id",
    }

    def operator_expression(self, field: str, operator: str, value: str):
        if operator == "regex":
            return f"{field} matches {self.quote(value)}"
        if operator == "base64":
            return f'{field}="{self.base64_value(value)}"'
        if operator in {"contains", "startswith", "endswith", "wildcard"}:
            return f'{field}="{self.wildcard_value(operator, value)}"'
        return f'{field}="{value}"'

    def _wrap_query(self, parsed: dict, expression: str):
        return f"_sourceCategory=*\n| where {expression or 'true'}"


class GraylogConverter(SearchConverter):
    platform = "graylog"
    name = "Graylog"
    category = "SIEM"
    equality = ":"
    field_map = {
        "image": "process_path",
        "parentimage": "parent_process_path",
        "commandline": "command_line",
        "processcommandline": "command_line",
        "destinationip": "dst_ip",
        "sourceip": "src_ip",
        "destinationhostname": "dst_host",
        "queryname": "dns_query",
        "targetobject": "registry_path",
        "hashes": "hash",
        "user": "user_name",
        "username": "user_name",
        "eventid": "event_id",
    }

    def operator_expression(self, field: str, operator: str, value: str):
        if operator == "regex":
            return f"{field}:/{self.regex_value(value)}/"
        if operator == "base64":
            return f"{field}:{self.quote(self.base64_value(value))}"
        return f"{field}:{self.quote(self.wildcard_value(operator, value))}"


class LogScaleConverter(SearchConverter):
    platform = "logscale"
    name = "CrowdStrike LogScale"
    category = "SIEM"
    equality = "="
    field_map = {
        "image": "ImageFileName",
        "parentimage": "ParentBaseFileName",
        "commandline": "CommandLine",
        "processcommandline": "CommandLine",
        "destinationip": "RemoteAddressIP4",
        "sourceip": "LocalAddressIP4",
        "destinationhostname": "DomainName",
        "queryname": "DomainName",
        "targetobject": "TargetObject",
        "hashes": "SHA256HashData",
        "user": "UserName",
        "username": "UserName",
        "eventid": "EventID",
    }

    def operator_expression(self, field: str, operator: str, value: str):
        if operator == "regex":
            return f"{field}=/{self.regex_value(value)}/i"
        if operator == "base64":
            return f"{field}={self.quote(self.base64_value(value))}"
        if operator in {"contains", "startswith", "endswith", "wildcard"}:
            regex_value = re.escape(value)
            if operator == "startswith":
                regex_value = f"^{regex_value}"
            elif operator == "endswith":
                regex_value = f"{regex_value}$"
            else:
                regex_value = f".*{regex_value}.*"
            return f"{field}=/{regex_value}/i"
        return f"{field}={self.quote(value)}"


class CrowdStrikeConverter(SearchConverter):
    platform = "crowdstrike"
    name = "CrowdStrike Falcon Query"
    category = "EDR/XDR"
    equality = ":"
    field_map = {
        "image": "ImageFileName",
        "parentimage": "ParentBaseFileName",
        "commandline": "CommandLine",
        "processcommandline": "CommandLine",
        "destinationip": "RemoteAddressIP4",
        "sourceip": "LocalAddressIP4",
        "destinationhostname": "DomainName",
        "queryname": "DomainName",
        "targetobject": "RegObjectName",
        "hashes": "SHA256HashData",
        "user": "UserName",
        "username": "UserName",
        "eventid": "EventType",
    }


class DefenderXDRConverter(SentinelKQLConverter):
    platform = "defender_xdr"
    name = "Microsoft Defender XDR"
    category = "EDR/XDR"

    def _wrap_query(self, parsed: dict, expression: str):
        return f"DeviceProcessEvents\n| where {expression or 'true'}"


class SentinelOneConverter(SearchConverter):
    platform = "sentinelone_dv"
    name = "SentinelOne Deep Visibility"
    category = "EDR/XDR"
    equality = " = "
    field_map = {
        "image": "TgtProcName",
        "parentimage": "SrcProcName",
        "commandline": "TgtProcCmdLine",
        "processcommandline": "TgtProcCmdLine",
        "destinationip": "DstIp",
        "sourceip": "SrcIp",
        "destinationhostname": "Url",
        "queryname": "DnsRequest",
        "targetobject": "RegistryKeyPath",
        "hashes": "TgtFileSha256",
        "user": "SrcProcUser",
        "username": "SrcProcUser",
        "eventid": "EventType",
    }

    def operator_expression(self, field: str, operator: str, value: str):
        if operator == "regex":
            return f"{field} RegExp {self.quote(value)}"
        if operator == "base64":
            return f"{field} = {self.quote(self.base64_value(value))}"
        if operator in {"contains", "startswith", "endswith", "wildcard"}:
            return f"{field} Contains Anycase {self.quote(value)}"
        return f"{field} = {self.quote(value)}"


class CarbonBlackConverter(SearchConverter):
    platform = "carbon_black"
    name = "VMware Carbon Black"
    category = "EDR/XDR"
    equality = ":"
    field_map = {
        "image": "process_name",
        "parentimage": "parent_name",
        "commandline": "process_cmdline",
        "processcommandline": "process_cmdline",
        "destinationip": "netconn_ipv4",
        "sourceip": "sensor_ip",
        "destinationhostname": "domain",
        "queryname": "domain",
        "targetobject": "regmod_name",
        "hashes": "process_sha256",
        "user": "username",
        "username": "username",
        "eventid": "type",
    }

    def operator_expression(self, field: str, operator: str, value: str):
        if operator == "regex":
            return f"{field}:/{self.regex_value(value)}/"
        if operator == "base64":
            return f"{field}:{self.quote(self.base64_value(value))}"
        return f"{field}:{self.quote(self.wildcard_value(operator, value))}"


class GoogleSecOpsConverter(SearchConverter):
    platform = "google_secops"
    name = "Google SecOps YARA-L"
    category = "XDR"
    field_map = {
        "image": "target.process.file.full_path",
        "parentimage": "principal.process.file.full_path",
        "commandline": "target.process.command_line",
        "processcommandline": "target.process.command_line",
        "destinationip": "target.ip",
        "sourceip": "principal.ip",
        "destinationhostname": "target.hostname",
        "queryname": "network.dns.questions.name",
        "targetobject": "target.registry.registry_key",
        "hashes": "target.file.sha256",
        "user": "principal.user.userid",
        "username": "principal.user.userid",
        "eventid": "metadata.product_event_type",
    }

    def convert(self, parsed: dict):
        title = parsed.get("rule", {}).get("title") or "Sigma converted rule"
        rule_name = re.sub(r"[^a-z0-9_]+", "_", title.lower()).strip("_") or "sigma_converted_rule"
        events = []

        for criteria in parsed.get("selectors", {}).values():
            for criterion in criteria:
                for value in criterion.get("values", []):
                    field = self.field_name(criterion.get("field"))
                    events.append(f"    $e.{field} = {self.quote(value)}")

        if not events:
            events.append(f"    $e.metadata.description = {self.quote(title)}")

        return (
            f"rule {rule_name} {{\n"
            "  meta:\n"
            '    author = "SOC Copilot"\n'
            "  events:\n"
            f"{chr(10).join(events)}\n"
            "  condition:\n"
            "    $e\n"
            "}"
        )

    def operator_expression(self, field: str, operator: str, value: str):
        return f"$e.{field} = {self.quote(value)}"


class OsquerySQLConverter(BaseSigmaConverter):
    platform = "osquery_sql"
    name = "osquery SQL"
    category = "EDR/XDR"
    equality = " = "
    field_map = {
        "image": "path",
        "parentimage": "parent",
        "commandline": "cmdline",
        "processcommandline": "cmdline",
        "destinationip": "remote_address",
        "sourceip": "local_address",
        "destinationhostname": "remote_address",
        "queryname": "remote_address",
        "targetobject": "path",
        "hashes": "sha256",
        "user": "username",
        "username": "username",
        "eventid": "eventid",
    }

    def quote_single(self, value: str):
        return "'" + str(value).replace("'", "''") + "'"

    def operator_expression(self, field: str, operator: str, value: str):
        if operator == "regex":
            return f"{field} REGEXP {self.quote_single(value)}"
        if operator == "base64":
            return f"{field} = {self.quote_single(self.base64_value(value))}"
        if operator in {"contains", "startswith", "endswith", "wildcard"}:
            pattern = self.wildcard_value(operator, value).replace("*", "%")
            return f"{field} LIKE {self.quote_single(pattern)}"
        return f"{field} = {self.quote_single(value)}"

    def _wrap_query(self, parsed: dict, expression: str):
        return f"SELECT * FROM process_events WHERE {expression or '1=1'};"


class NetworkRuleConverter(BaseSigmaConverter):
    action = "alert"
    protocol = "tcp"
    name = ""
    platform = ""
    category = "IDS"

    def convert(self, parsed: dict):
        contents = []
        for criteria in parsed.get("selectors", {}).values():
            for criterion in criteria:
                for value in criterion.get("values", []):
                    if self._network_relevant(criterion.get("field"), value):
                        contents.append(value)

        if not contents:
            contents = [parsed.get("rule", {}).get("title") or "sigma rule"]

        return self._build_rule(parsed, contents[:6])

    def _network_relevant(self, field: str, value: str):
        field = str(field or "").lower()
        if any(key in field for key in ["ip", "host", "domain", "url", "dns", "commandline"]):
            return True
        return bool(re.search(r"(?:\d{1,3}\.){3}\d{1,3}|https?://|[a-z0-9.-]+\.[a-z]{2,}", value, flags=re.IGNORECASE))

    def _build_rule(self, parsed: dict, contents: list):
        title = parsed.get("rule", {}).get("title") or "Sigma converted detection"
        sid_seed = parsed.get("rule", {}).get("id") or title
        sid = int(hashlib.sha1(str(sid_seed).encode("utf-8")).hexdigest()[:8], 16) % 100000 + 9000000
        content_text = " ".join([f'content:"{self._escape_content(value)}"; nocase;' for value in contents])
        return f'{self.action} {self.protocol} any any -> any any (msg:"Sigma: {self._escape_content(title)}"; {content_text} sid:{sid}; rev:1;)'

    def _escape_content(self, value: str):
        return str(value).replace('"', '\\"')

    def operator_expression(self, field: str, operator: str, value: str):
        return value


class SnortConverter(NetworkRuleConverter):
    platform = "snort"
    name = "Snort"


class SuricataConverter(NetworkRuleConverter):
    platform = "suricata"
    name = "Suricata"
