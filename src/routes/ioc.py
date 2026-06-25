from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional
from urllib.parse import urlparse
import asyncio
import httpx
import ipaddress
import math
import re


ioc_router = APIRouter(
    prefix="/api/v1/ioc",
    tags=["ioc_enrichment"],
)


class IOCItem(BaseModel):
    value: str
    type: Optional[str] = None


class EnrichRequest(BaseModel):
    iocs: List[IOCItem]
    virustotal_key: Optional[str] = None
    abuseipdb_key: Optional[str] = None
    shodan_key: Optional[str] = None


DOMAIN_PATTERN = re.compile(r"^(?=.{4,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$")
HASH_PATTERN = re.compile(r"^(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})$")


def _normalize_value(value: str) -> str:
    value = (value or "").strip()
    return (
        value.replace("[.]", ".")
        .replace("(.)", ".")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
        .strip()
    )


def detect_type(value: str) -> str:
    value = _normalize_value(value)
    if not value:
        return "unknown"

    try:
        ipaddress.ip_address(value)
        return "ip"
    except Exception:
        pass

    if HASH_PATTERN.match(value):
        return "hash"

    parsed = urlparse(value)
    if parsed.scheme in {"http", "https", "ftp"} and parsed.netloc:
        return "url"

    if DOMAIN_PATTERN.match(value):
        return "domain"

    return "unknown"


def verdict_from_stats(malicious: int, suspicious: int, total: int) -> str:
    if total == 0:
        return "unknown"
    ratio = (malicious + suspicious * 0.5) / total
    if malicious >= 5 or ratio >= 0.1:
        return "malicious"
    if malicious >= 1 or suspicious >= 3:
        return "suspicious"
    return "clean"


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    probabilities = [value.count(ch) / len(value) for ch in set(value)]
    return -sum(p * math.log(p, 2) for p in probabilities if p > 0)


def _apex_domain(domain: str) -> str:
    labels = [label for label in domain.split(".") if label]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return domain


def _async_value(value):
    async def _inner():
        return value
    return _inner()


def _hash_algorithm(value: str) -> str:
    length = len(value)
    if length == 32:
        return "md5"
    if length == 40:
        return "sha1"
    if length == 64:
        return "sha256"
    return "unknown"


def _hash_local_context(value: str) -> dict:
    algorithm = _hash_algorithm(value)
    known_empty = value.lower() in {
        "d41d8cd98f00b204e9800998ecf8427e",
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    notes = []
    if known_empty:
        notes.append("Hash matches a well-known empty-content digest.")

    return {
        "algorithm": algorithm,
        "length": len(value),
        "known_empty_hash": known_empty,
        "notes": notes,
    }


def _domain_local_context(value: str) -> dict:
    value = value.lower().strip(".")
    labels = [label for label in value.split(".") if label]
    apex = _apex_domain(value)
    subdomain = ".".join(labels[:-2]) if len(labels) > 2 else ""
    digit_ratio = sum(ch.isdigit() for ch in value) / max(len(value), 1)
    hyphen_count = value.count("-")
    entropy = round(_entropy(value.replace(".", "")), 3)
    risky_terms = [term for term in ["update", "login", "secure", "verify", "cdn", "download", "account", "c2", "evil", "payload", "beacon"] if term in value]
    looks_dga = entropy >= 3.5 or digit_ratio >= 0.2 or hyphen_count >= 3

    notes = []
    if looks_dga:
        notes.append("Domain has characteristics often seen in algorithmic or throwaway naming.")
    if risky_terms:
        notes.append("Domain contains lure or delivery-oriented keywords: " + ", ".join(risky_terms) + ".")

    return {
        "fqdn": value,
        "apex_domain": apex,
        "subdomain": subdomain,
        "tld": labels[-1] if labels else "",
        "label_count": len(labels),
        "digit_ratio": round(digit_ratio, 3),
        "hyphen_count": hyphen_count,
        "entropy": entropy,
        "looks_dga_like": looks_dga,
        "risky_terms": risky_terms,
        "notes": notes,
    }


def _ip_local_context(value: str) -> dict:
    ip = ipaddress.ip_address(value)
    classification = []
    if ip.is_private:
        classification.append("private")
    if ip.is_global:
        classification.append("global")
    if ip.is_loopback:
        classification.append("loopback")
    if ip.is_reserved:
        classification.append("reserved")
    if ip.is_multicast:
        classification.append("multicast")

    return {
        "version": ip.version,
        "is_private": ip.is_private,
        "is_global": ip.is_global,
        "is_loopback": ip.is_loopback,
        "is_reserved": ip.is_reserved,
        "is_multicast": ip.is_multicast,
        "reverse_pointer": ip.reverse_pointer,
        "classification": classification,
        "notes": [
            "Public IP observable." if ip.is_global else "Non-public address range."
        ],
    }


def _url_local_context(value: str) -> dict:
    parsed = urlparse(value)
    host = parsed.hostname or ""
    filename = parsed.path.rsplit("/", 1)[-1] if parsed.path else ""
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    query_keys = sorted({
        part.split("=", 1)[0]
        for part in parsed.query.split("&")
        if part
    })
    risky_terms = [
        term for term in ["download", "update", "payload", "login", "verify", "token", "cmd", "ps1", "exe"]
        if term in value.lower()
    ]

    related = []
    if host:
        related.append({"type": detect_type(host), "value": host})

    return {
        "scheme": parsed.scheme,
        "host": host,
        "path": parsed.path,
        "query_keys": query_keys[:10],
        "port": parsed.port,
        "filename": filename,
        "file_extension": extension,
        "risky_terms": risky_terms,
        "notes": [
            "URL path suggests downloadable content." if extension in {"exe", "dll", "js", "ps1", "zip", "rar"} else "",
            "URL contains suspicious lure keywords." if risky_terms else "",
        ],
        "related_observables": [item for item in related if item.get("type") != "unknown"],
    }


def _build_local_context(ioc_type: str, value: str) -> dict:
    if ioc_type == "ip":
        return _ip_local_context(value)
    if ioc_type == "domain":
        return _domain_local_context(value)
    if ioc_type == "url":
        return _url_local_context(value)
    if ioc_type == "hash":
        return _hash_local_context(value)
    return {"notes": []}


def _local_verdict(ioc_type: str, local_context: dict, shodan: dict = None, ipwhois: dict = None) -> str:
    shodan = shodan or {}
    ipwhois = ipwhois or {}

    if ioc_type == "domain":
        if local_context.get("looks_dga_like") or local_context.get("risky_terms"):
            return "suspicious"
        return "unknown"

    if ioc_type == "url":
        if local_context.get("file_extension") in {"exe", "dll", "js", "ps1", "zip", "rar"}:
            return "suspicious"
        if local_context.get("risky_terms"):
            return "suspicious"
        return "unknown"

    if ioc_type == "ip":
        if shodan.get("vulns") or shodan.get("ports"):
            return "suspicious"
        if ipwhois.get("connection", {}).get("is_tor"):
            return "suspicious"
        if local_context.get("is_private"):
            return "clean"
        return "unknown"

    if ioc_type == "hash":
        if local_context.get("known_empty_hash"):
            return "suspicious"
        return "unknown"

    return "unknown"


def _combined_verdict(vt: dict, abuse: dict, local_verdict: str) -> str:
    verdicts = []
    if isinstance(vt, dict) and vt.get("verdict"):
        verdicts.append(vt["verdict"])
    if isinstance(abuse, dict) and abuse.get("verdict"):
        verdicts.append(abuse["verdict"])
    if local_verdict and local_verdict != "unknown":
        verdicts.append(local_verdict)

    if "malicious" in verdicts:
        return "malicious"
    if "suspicious" in verdicts:
        return "suspicious"
    if "clean" in verdicts:
        return "clean"
    return "unknown"


def _confidence(vt: dict, abuse: dict, shodan: dict, local_verdict: str) -> float:
    confidence = 0.35
    if isinstance(vt, dict) and vt.get("verdict") and "error" not in vt:
        confidence = max(confidence, 0.9)
    if isinstance(abuse, dict) and abuse.get("verdict") and "error" not in abuse:
        confidence = max(confidence, 0.88)
    if isinstance(shodan, dict) and ("vulns" in shodan or "ports" in shodan):
        confidence = max(confidence, 0.72)
    if local_verdict != "unknown":
        confidence = max(confidence, 0.65)
    return round(confidence, 2)


def _result_summary(ioc_type: str, value: str, verdict: str, local_context: dict, vt: dict, abuse: dict, shodan: dict, extra_sources: dict) -> str:
    parts = [f"{ioc_type.upper()} observable {value} is currently assessed as {verdict}."]

    if ioc_type == "ip":
        if local_context.get("is_private"):
            parts.append("It belongs to a private address range.")
        elif extra_sources.get("ipwhois", {}).get("country"):
            country = extra_sources["ipwhois"].get("country")
            asn = extra_sources["ipwhois"].get("connection", {}).get("asn")
            parts.append(f"Geo/ASN context points to {country}{f' via AS{asn}' if asn else ''}.")
        if shodan.get("ports"):
            parts.append("Observed exposed ports: " + ", ".join([str(port) for port in shodan.get("ports", [])[:5]]) + ".")

    if ioc_type == "domain":
        if local_context.get("looks_dga_like"):
            parts.append("The naming pattern looks algorithmic or disposable.")
        registrar = extra_sources.get("rdap", {}).get("registrar")
        if registrar:
            parts.append(f"Registrar context: {registrar}.")

    if ioc_type == "url":
        extension = local_context.get("file_extension")
        if extension:
            parts.append(f"The path ends with a likely payload extension: .{extension}.")
        if local_context.get("host"):
            parts.append(f"Host component: {local_context['host']}.")

    if ioc_type == "hash":
        parts.append(f"Hash algorithm inferred as {local_context.get('algorithm', 'unknown')}.")
        if local_context.get("known_empty_hash"):
            parts.append("It matches a well-known empty-content digest and should be validated in context.")

    if isinstance(vt, dict) and vt.get("verdict") and "error" not in vt:
        parts.append(f"VirusTotal verdict: {vt.get('verdict')} ({vt.get('malicious', 0)} malicious / {vt.get('suspicious', 0)} suspicious).")
    if isinstance(abuse, dict) and abuse.get("abuse_score") is not None and "error" not in abuse:
        parts.append(f"AbuseIPDB confidence score: {abuse.get('abuse_score', 0)}.")

    return " ".join([part for part in parts if part]).strip()


def _source_state(name: str, result: dict, applies: bool = True) -> dict:
    if not applies:
        return {"name": name, "status": "not_applicable", "detail": "not_applicable"}
    if not isinstance(result, dict):
        return {"name": name, "status": "error", "detail": "invalid_response"}
    if result.get("available") is False:
        return {"name": name, "status": "missing", "detail": result.get("reason", "not_available")}
    if result.get("error"):
        return {"name": name, "status": "error", "detail": result.get("error")}
    return {"name": name, "status": "checked", "detail": "checked"}


def _source_coverage(ioc_type: str, vt: dict, abuse: dict, shodan: dict, ipwhois: dict, rdap: dict, local_context: dict) -> list:
    return [
        _source_state("VirusTotal", vt, applies=ioc_type in {"ip", "domain", "url", "hash"}),
        _source_state("AbuseIPDB", abuse, applies=ioc_type == "ip"),
        _source_state("Shodan", shodan, applies=ioc_type == "ip"),
        _source_state("IP Whois", ipwhois, applies=ioc_type == "ip" and not local_context.get("is_private")),
        _source_state("RDAP", rdap, applies=ioc_type == "domain"),
    ]


def _add_fact(facts: list, label: str, value):
    if value is None or value == "" or value == []:
        return
    if isinstance(value, bool):
        value = "yes" if value else "no"
    elif isinstance(value, list):
        value = ", ".join([str(item) for item in value if item])
    facts.append({"label": label, "value": str(value)})


def _key_facts(ioc_type: str, local_context: dict, vt: dict, abuse: dict, shodan: dict, ipwhois: dict, rdap: dict) -> list:
    facts = []

    if ioc_type == "ip":
        _add_fact(facts, "IP version", local_context.get("version"))
        _add_fact(facts, "Scope", ", ".join(local_context.get("classification", [])) or ("global" if local_context.get("is_global") else "non-public"))
        _add_fact(facts, "Country", ipwhois.get("country") or vt.get("country") or abuse.get("country"))
        _add_fact(facts, "ASN / Org", ipwhois.get("connection", {}).get("org") or vt.get("asn"))
        _add_fact(facts, "Open ports", len(shodan.get("ports", []) or []))
        _add_fact(facts, "Shodan CVEs", len(shodan.get("vulns", []) or []))
        _add_fact(facts, "Abuse score", abuse.get("abuse_score"))

    elif ioc_type == "domain":
        _add_fact(facts, "Apex domain", local_context.get("apex_domain"))
        _add_fact(facts, "TLD", local_context.get("tld"))
        _add_fact(facts, "DGA-like", local_context.get("looks_dga_like"))
        _add_fact(facts, "Registrar", rdap.get("registrar"))
        _add_fact(facts, "Nameservers", (rdap.get("nameservers") or [])[:3])
        _add_fact(facts, "VT detections", f"{vt.get('malicious', 0)}/{vt.get('total', 0)}" if vt.get("total") is not None else "")

    elif ioc_type == "url":
        _add_fact(facts, "Host", local_context.get("host"))
        _add_fact(facts, "Scheme", local_context.get("scheme"))
        _add_fact(facts, "Port", local_context.get("port"))
        _add_fact(facts, "File extension", local_context.get("file_extension"))
        _add_fact(facts, "Query keys", local_context.get("query_keys"))
        _add_fact(facts, "VT detections", f"{vt.get('malicious', 0)}/{vt.get('total', 0)}" if vt.get("total") is not None else "")

    elif ioc_type == "hash":
        _add_fact(facts, "Algorithm", local_context.get("algorithm"))
        _add_fact(facts, "Length", local_context.get("length"))
        _add_fact(facts, "Known empty hash", local_context.get("known_empty_hash"))
        _add_fact(facts, "VT name", vt.get("name"))
        _add_fact(facts, "VT tags", vt.get("tags"))
        _add_fact(facts, "VT detections", f"{vt.get('malicious', 0)}/{vt.get('total', 0)}" if vt.get("total") is not None else "")

    return facts[:8]


def _risk_reasons(ioc_type: str, verdict: str, local_context: dict, vt: dict, abuse: dict, shodan: dict) -> list:
    reasons = []

    if isinstance(vt, dict) and vt.get("malicious", 0) > 0:
        reasons.append(f"VirusTotal reports {vt.get('malicious', 0)} malicious engine(s)")
    if isinstance(vt, dict) and vt.get("suspicious", 0) > 0:
        reasons.append(f"VirusTotal reports {vt.get('suspicious', 0)} suspicious engine(s)")
    if isinstance(abuse, dict) and abuse.get("abuse_score", 0) >= 10:
        reasons.append(f"AbuseIPDB score is {abuse.get('abuse_score')}")
    if isinstance(shodan, dict) and shodan.get("vulns"):
        reasons.append(f"Shodan lists {len(shodan.get('vulns', []))} CVE(s)")
    if isinstance(shodan, dict) and shodan.get("ports"):
        reasons.append(f"Public services exposed on {len(shodan.get('ports', []))} port(s)")
    if ioc_type == "domain" and local_context.get("looks_dga_like"):
        reasons.append("Domain pattern looks DGA-like or disposable")
    if local_context.get("risky_terms"):
        reasons.append("Contains lure, payload, or C2-oriented terms")
    if ioc_type == "url" and local_context.get("file_extension") in {"exe", "dll", "js", "ps1", "zip", "rar"}:
        reasons.append(f"URL points to a potentially risky .{local_context.get('file_extension')} payload")
    if ioc_type == "hash" and local_context.get("known_empty_hash"):
        reasons.append("Hash is a known empty-content digest")
    if verdict == "clean" and ioc_type == "ip" and local_context.get("is_private"):
        reasons.append("Private address range")

    return list(dict.fromkeys(reasons))[:6]


def _priority(verdict: str, confidence: float, risk_reasons: list) -> dict:
    if verdict == "malicious":
        return {
            "level": "P1",
            "label": "Immediate containment",
            "reason": "Malicious verdict from enrichment sources or strong local indicators.",
        }
    if verdict == "suspicious":
        return {
            "level": "P2",
            "label": "Validate and hunt",
            "reason": "Suspicious signals were found and should be checked against telemetry.",
        }
    if confidence >= 0.75 and risk_reasons:
        return {
            "level": "P2",
            "label": "Review with context",
            "reason": "Signals exist, but the final verdict needs analyst context.",
        }
    return {
        "level": "P3",
        "label": "Monitor",
        "reason": "No strong malicious signal was confirmed in the available enrichment.",
    }


def _recommended_actions(ioc_type: str, verdict: str, local_context: dict, related: list) -> list:
    actions = []

    def add(priority: int, action: str, description: str):
        actions.append({"priority": priority, "action": action, "description": description})

    if verdict == "malicious":
        add(1, "Contain matching activity", "Block or isolate matches after confirming business impact.")
    elif verdict == "suspicious":
        add(2, "Hunt across telemetry", "Search SIEM, EDR, DNS, proxy, and firewall logs for the same indicator.")
    else:
        add(3, "Track as context", "Keep the indicator available for correlation with related alerts.")

    if ioc_type in {"ip", "domain", "url"}:
        add(2, "Review network controls", "Check DNS, proxy, firewall, and egress telemetry for observed connections.")
    if ioc_type == "hash":
        add(2, "Search endpoints by hash", "Look for file execution, quarantine events, and neighboring process activity.")
    if ioc_type == "url" and related:
        add(3, "Pivot on related host", "Enrich the extracted host/domain relationship separately.")
    if local_context.get("risky_terms"):
        add(3, "Inspect lure context", "Review surrounding email, web, or command-line content for delivery intent.")

    deduped = []
    seen = set()
    for action in actions:
        key = action["action"].lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(action)
    return deduped[:4]


def _dedupe_related(items: list) -> list:
    results = []
    seen = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        key = (str(item.get("type", "")).strip().lower(), str(item.get("value", "")).strip().lower())
        if not key[0] or not key[1] or key in seen:
            continue
        seen.add(key)
        results.append({"type": item.get("type"), "value": item.get("value")})
    return results


async def vt_lookup(client: httpx.AsyncClient, ioc_type: str, value: str, api_key: str) -> dict:
    headers = {"x-apikey": api_key}
    try:
        if ioc_type == "ip":
            response = await client.get(f"https://www.virustotal.com/api/v3/ip_addresses/{value}", headers=headers, timeout=15)
        elif ioc_type == "domain":
            response = await client.get(f"https://www.virustotal.com/api/v3/domains/{value}", headers=headers, timeout=15)
        elif ioc_type == "hash":
            response = await client.get(f"https://www.virustotal.com/api/v3/files/{value}", headers=headers, timeout=15)
        elif ioc_type == "url":
            import base64 as b64
            url_id = b64.urlsafe_b64encode(value.encode()).decode().strip("=")
            response = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=15)
        else:
            return {"error": "unsupported_type"}

        if response.status_code == 404:
            return {"error": "not_found"}
        if response.status_code == 401:
            return {"error": "invalid_api_key"}
        if response.status_code != 200:
            return {"error": f"http_{response.status_code}"}

        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total = malicious + suspicious + harmless + undetected

        return {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "total": total,
            "verdict": verdict_from_stats(malicious, suspicious, total),
            "country": attributes.get("country", ""),
            "asn": f"AS{attributes.get('asn', '')} {attributes.get('as_owner', '')}".strip() if attributes.get("asn") else "",
            "tags": attributes.get("tags", [])[:6],
            "name": attributes.get("meaningful_name", "") or attributes.get("title", ""),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "link": f"https://www.virustotal.com/gui/{'ip-address' if ioc_type == 'ip' else ioc_type}/{value}",
        }
    except Exception as exc:
        return {"error": str(exc)[:120]}


async def abuseipdb_lookup(client: httpx.AsyncClient, ip: str, api_key: str) -> dict:
    headers = {"Key": api_key, "Accept": "application/json"}
    try:
        response = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
            headers=headers,
            timeout=12,
        )
        if response.status_code == 401:
            return {"error": "invalid_api_key"}
        if response.status_code != 200:
            return {"error": f"http_{response.status_code}"}

        data = response.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        return {
            "abuse_score": score,
            "verdict": "malicious" if score >= 50 else "suspicious" if score >= 10 else "clean",
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", ""),
            "isp": data.get("isp", ""),
            "usage_type": data.get("usageType", ""),
            "domain": data.get("domain", ""),
            "is_tor": data.get("isTor", False),
            "is_public": data.get("isPublic", True),
            "last_reported_at": data.get("lastReportedAt"),
            "link": f"https://www.abuseipdb.com/check/{ip}",
        }
    except Exception as exc:
        return {"error": str(exc)[:120]}


async def shodan_lookup(client: httpx.AsyncClient, ip: str) -> dict:
    try:
        response = await client.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if response.status_code == 404:
            return {"ports": [], "vulns": [], "cpes": [], "hostnames": [], "tags": []}
        if response.status_code != 200:
            return {"error": f"http_{response.status_code}"}
        data = response.json()
        return {
            "ports": data.get("ports", [])[:10],
            "vulns": data.get("vulns", [])[:8],
            "cpes": data.get("cpes", [])[:5],
            "hostnames": data.get("hostnames", [])[:5],
            "tags": data.get("tags", [])[:5],
            "link": f"https://www.shodan.io/host/{ip}",
        }
    except Exception as exc:
        return {"error": str(exc)[:120]}


async def ipwhois_lookup(client: httpx.AsyncClient, ip: str) -> dict:
    try:
        response = await client.get(f"https://ipwho.is/{ip}", timeout=10)
        if response.status_code != 200:
            return {"error": f"http_{response.status_code}"}
        data = response.json()
        if data.get("success") is False:
            return {"error": data.get("message", "lookup_failed")}
        return {
            "continent": data.get("continent", ""),
            "country": data.get("country", ""),
            "region": data.get("region", ""),
            "city": data.get("city", ""),
            "connection": {
                "asn": data.get("connection", {}).get("asn"),
                "org": data.get("connection", {}).get("org", ""),
                "isp": data.get("connection", {}).get("isp", ""),
                "domain": data.get("connection", {}).get("domain", ""),
            },
        }
    except Exception as exc:
        return {"error": str(exc)[:120]}


async def rdap_lookup(client: httpx.AsyncClient, domain: str) -> dict:
    try:
        response = await client.get(f"https://rdap.org/domain/{domain}", timeout=12)
        if response.status_code != 200:
            return {"error": f"http_{response.status_code}"}
        data = response.json()
        registrar = ""
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [None, []])[1]
                for entry in vcard:
                    if isinstance(entry, list) and len(entry) >= 4 and entry[0] == "fn":
                        registrar = entry[3]
                        break
                if registrar:
                    break

        nameservers = [
            ns.get("ldhName", "")
            for ns in data.get("nameservers", [])
            if isinstance(ns, dict) and ns.get("ldhName")
        ]
        statuses = data.get("status", [])[:6]

        return {
            "registrar": registrar,
            "handle": data.get("handle", ""),
            "statuses": statuses,
            "nameservers": nameservers[:6],
        }
    except Exception as exc:
        return {"error": str(exc)[:120]}


@ioc_router.post("/enrich")
async def enrich_iocs(request: Request, body: EnrichRequest):
    try:
        settings = request.app.settings
        vt_key = body.virustotal_key or getattr(settings, "VIRUSTOTAL_API_KEY", None) or ""
        abuse_key = body.abuseipdb_key or getattr(settings, "ABUSEIPDB_API_KEY", None) or ""
    except Exception:
        vt_key = body.virustotal_key or ""
        abuse_key = body.abuseipdb_key or ""

    results = []

    async with httpx.AsyncClient(verify=False, follow_redirects=True) as client:
        tasks = []

        for item in body.iocs[:20]:
            raw_value = _normalize_value(item.value)
            if not raw_value:
                continue

            ioc_type = item.type or detect_type(raw_value)
            local_context = _build_local_context(ioc_type=ioc_type, value=raw_value)

            coroutines = {
                "virustotal": vt_lookup(client, ioc_type, raw_value, vt_key) if vt_key else _async_value({"available": False, "reason": "missing_api_key"}),
                "abuseipdb": abuseipdb_lookup(client, raw_value, abuse_key) if ioc_type == "ip" and abuse_key else _async_value({"available": ioc_type == "ip" and bool(abuse_key), "reason": "missing_api_key" if ioc_type == "ip" and not abuse_key else "not_applicable"}),
                "shodan": shodan_lookup(client, raw_value) if ioc_type == "ip" else _async_value({"available": False, "reason": "not_applicable"}),
                "ipwhois": ipwhois_lookup(client, raw_value) if ioc_type == "ip" and not local_context.get("is_private") else _async_value({"available": False, "reason": "not_applicable" if ioc_type != "ip" else "private_ip"}),
                "rdap": rdap_lookup(client, raw_value) if ioc_type == "domain" else _async_value({"available": False, "reason": "not_applicable"}),
            }
            tasks.append((raw_value, ioc_type, local_context, coroutines))

        for raw_value, ioc_type, local_context, coroutines in tasks:
            vt_res, abuse_res, shodan_res, ipwhois_res, rdap_res = await asyncio.gather(
                coroutines["virustotal"],
                coroutines["abuseipdb"],
                coroutines["shodan"],
                coroutines["ipwhois"],
                coroutines["rdap"],
            )

            local_verdict = _local_verdict(
                ioc_type=ioc_type,
                local_context=local_context,
                shodan=shodan_res if isinstance(shodan_res, dict) else {},
                ipwhois=ipwhois_res if isinstance(ipwhois_res, dict) else {},
            )
            verdict = _combined_verdict(vt_res if isinstance(vt_res, dict) else {}, abuse_res if isinstance(abuse_res, dict) else {}, local_verdict)
            confidence = _confidence(
                vt=vt_res if isinstance(vt_res, dict) else {},
                abuse=abuse_res if isinstance(abuse_res, dict) else {},
                shodan=shodan_res if isinstance(shodan_res, dict) else {},
                local_verdict=local_verdict,
            )

            related = list(local_context.get("related_observables", []))
            if ioc_type == "domain":
                related.append({"type": "apex_domain", "value": local_context.get("apex_domain", "")})
            if ioc_type == "url" and local_context.get("host"):
                related.append({"type": detect_type(local_context["host"]), "value": local_context["host"]})

            related_observables = _dedupe_related([item for item in related if item.get("value")])
            risk_reasons = _risk_reasons(
                ioc_type=ioc_type,
                verdict=verdict,
                local_context=local_context,
                vt=vt_res if isinstance(vt_res, dict) else {},
                abuse=abuse_res if isinstance(abuse_res, dict) else {},
                shodan=shodan_res if isinstance(shodan_res, dict) else {},
            )

            results.append({
                "value": raw_value,
                "type": ioc_type,
                "verdict": verdict,
                "confidence": confidence,
                "priority": _priority(verdict=verdict, confidence=confidence, risk_reasons=risk_reasons),
                "summary": _result_summary(
                    ioc_type=ioc_type,
                    value=raw_value,
                    verdict=verdict,
                    local_context=local_context,
                    vt=vt_res if isinstance(vt_res, dict) else {},
                    abuse=abuse_res if isinstance(abuse_res, dict) else {},
                    shodan=shodan_res if isinstance(shodan_res, dict) else {},
                    extra_sources={"ipwhois": ipwhois_res if isinstance(ipwhois_res, dict) else {}, "rdap": rdap_res if isinstance(rdap_res, dict) else {}},
                ),
                "key_facts": _key_facts(
                    ioc_type=ioc_type,
                    local_context=local_context,
                    vt=vt_res if isinstance(vt_res, dict) else {},
                    abuse=abuse_res if isinstance(abuse_res, dict) else {},
                    shodan=shodan_res if isinstance(shodan_res, dict) else {},
                    ipwhois=ipwhois_res if isinstance(ipwhois_res, dict) else {},
                    rdap=rdap_res if isinstance(rdap_res, dict) else {},
                ),
                "risk_reasons": risk_reasons,
                "local_context": local_context,
                "related_observables": related_observables,
                "recommended_actions": _recommended_actions(
                    ioc_type=ioc_type,
                    verdict=verdict,
                    local_context=local_context,
                    related=related_observables,
                ),
                "virustotal": vt_res,
                "abuseipdb": abuse_res,
                "shodan": shodan_res,
                "ipwhois": ipwhois_res,
                "rdap": rdap_res,
                "source_coverage": _source_coverage(
                    ioc_type=ioc_type,
                    vt=vt_res if isinstance(vt_res, dict) else {},
                    abuse=abuse_res if isinstance(abuse_res, dict) else {},
                    shodan=shodan_res if isinstance(shodan_res, dict) else {},
                    ipwhois=ipwhois_res if isinstance(ipwhois_res, dict) else {},
                    rdap=rdap_res if isinstance(rdap_res, dict) else {},
                    local_context=local_context,
                ),
                "sources_checked": {
                    "virustotal": isinstance(vt_res, dict) and vt_res.get("available", True) is not False,
                    "abuseipdb": isinstance(abuse_res, dict) and abuse_res.get("available", True) is not False,
                    "shodan": ioc_type == "ip",
                    "ipwhois": ioc_type == "ip" and not local_context.get("is_private"),
                    "rdap": ioc_type == "domain",
                },
            })

    return JSONResponse(content={"signal": "ioc_enrichment_success", "results": results})


@ioc_router.post("/detect-type")
async def detect_ioc_type(body: dict):
    value = body.get("value", "")
    normalized = _normalize_value(value)
    return {
        "value": value,
        "normalized_value": normalized,
        "type": detect_type(normalized),
    }
