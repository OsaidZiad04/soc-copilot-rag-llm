from fastapi import APIRouter, Request, UploadFile, File, Form, status
from fastapi.responses import JSONResponse
from sqlalchemy.future import select
from models.ProjectModel import ProjectModel
from models.db_schemes import Asset, DataChunk
from models.enums.AssetTypeEnum import AssetTypeEnum
import asyncio
import base64
import codecs
import hashlib
import re
import time


yara_scanner_router = APIRouter(
    prefix="/api/v1/yara",
    tags=["api_v1", "yara_scanner"],
)

FAST_SCAN_LIMIT = 50
MAX_SCAN_BYTES = 25 * 1024 * 1024
SCAN_TIMEOUT_SECONDS = 8


def _extract_rule_blocks(text: str):
    blocks = []
    rule_start = re.compile(r"\b((?:private\s+|global\s+)*)rule\s+([A-Za-z_][A-Za-z0-9_]*)\s*([^{]*)\{", re.IGNORECASE)
    pos = 0
    while True:
        match = rule_start.search(text or "", pos)
        if not match:
            break
        depth = 0
        end = None
        in_quote = False
        in_regex = False
        in_hex = False
        escape = False
        for idx in range(match.end() - 1, len(text)):
            char = text[idx]
            prev = text[idx - 1] if idx else ""
            if escape:
                escape = False
                continue
            if char == "\\" and (in_quote or in_regex):
                escape = True
                continue
            if in_quote:
                if char == '"':
                    in_quote = False
                continue
            if in_regex:
                if char == "/" and prev != "\\":
                    in_regex = False
                continue
            if in_hex:
                if char == "}":
                    in_hex = False
                continue
            if char == '"':
                in_quote = True
                continue
            if char == "/" and re.search(r"=\s*$", text[max(match.start(), idx - 12):idx]):
                in_regex = True
                continue
            if char == "{" and re.search(r"=\s*$", text[max(match.start(), idx - 12):idx]):
                in_hex = True
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = idx + 1
                    break
        if end is None:
            pos = match.end()
            continue
        blocks.append({
            "name": match.group(2),
            "header": f"{match.group(1) or ''} {match.group(3) or ''}",
            "text": text[match.start():end],
        })
        pos = end
    return blocks


def _parse_meta(rule_text: str):
    meta = {}
    meta_match = re.search(r"\bmeta\s*:(.*?)(?:\n\s*(?:strings|condition)\s*:)", rule_text, re.IGNORECASE | re.DOTALL)
    if not meta_match:
        return meta
    for key, value in re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\"(?:\\.|[^\"])*\"|[^\r\n]+)", meta_match.group(1)):
        clean = value.strip().rstrip(",")
        if clean.startswith('"') and clean.endswith('"'):
            clean = clean[1:-1]
        meta[key] = clean
    return meta


def _decode_yara_string(value: str):
    try:
        return codecs.decode(value, "unicode_escape").encode("latin-1", errors="ignore")
    except Exception:
        return value.encode("utf-8", errors="ignore")


def _parse_strings(rule_text: str):
    strings = []
    strings_match = re.search(r"\bstrings\s*:(.*?)(?:\n\s*condition\s*:)", rule_text, re.IGNORECASE | re.DOTALL)
    if not strings_match:
        return strings
    for match in re.finditer(r"(\$[A-Za-z0-9_*]+)\s*=\s*\"((?:\\.|[^\"])*)\"([^\r\n]*)", strings_match.group(1)):
        modifiers = match.group(3).lower()
        strings.append({
            "identifier": match.group(1),
            "value": match.group(2),
            "bytes": _decode_yara_string(match.group(2)),
            "nocase": "nocase" in modifiers,
            "wide": "wide" in modifiers,
            "ascii": "ascii" in modifiers or "wide" not in modifiers,
            "fullword": "fullword" in modifiers,
        })
    return strings


def _strings_section(rule_text: str):
    match = re.search(r"\bstrings\s*:(.*?)(?:\n\s*condition\s*:)", rule_text or "", re.IGNORECASE | re.DOTALL)
    return match.group(1) if match else ""


def _condition_text(rule_text: str):
    match = re.search(r"\bcondition\s*:(.*?)}\s*$", rule_text or "", re.IGNORECASE | re.DOTALL)
    return match.group(1).strip() if match else ""


def _severity_from_rule(tags, meta):
    text = " ".join([*(tags or []), *(str(v) for v in (meta or {}).values())]).lower()
    if "critical" in text:
        return "critical"
    if "high" in text:
        return "high"
    if "medium" in text or "moderate" in text:
        return "medium"
    if "low" in text:
        return "low"
    return meta.get("severity") or meta.get("level") or "unknown"


def _parse_rules_from_source(source):
    rules = []
    seen = set()
    for block in _extract_rule_blocks(source["text"]):
        if block["name"] in seen:
            continue
        seen.add(block["name"])
        tags = [tag for tag in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", block["header"]) if tag not in {"private", "global"}]
        meta = _parse_meta(block["text"])
        strings = _parse_strings(block["text"])
        rules.append({
            "rule_name": block["name"],
            "source_file": source["file_name"],
            "source_name": source["source_name"],
            "tags": tags,
            "private": bool(re.search(r"\bprivate\b", block["header"], re.IGNORECASE)),
            "metadata": meta,
            "severity": _severity_from_rule(tags, meta),
            "strings": strings,
            "condition": _condition_text(block["text"]),
            "rule_text": block["text"],
        })
    return rules


def _extract_imports(text: str):
    seen = set()
    imports = []
    for match in re.finditer(r"^\s*import\s+\"[^\"]+\"\s*$", text or "", re.IGNORECASE | re.MULTILINE):
        line = match.group(0).strip()
        key = line.lower()
        if key in seen:
            continue
        seen.add(key)
        imports.append(line)
    return imports


def _build_reconstructed_yara_source(text: str, rules: list):
    imports = _extract_imports(text)
    blocks = []
    seen = set()
    for rule in rules:
        name = rule.get("rule_name")
        body = rule.get("rule_text") or ""
        if not name or name in seen or not body.strip():
            continue
        if not re.search(r"\bcondition\s*:", body, re.IGNORECASE):
            continue
        seen.add(name)
        blocks.append(body.strip())
    return "\n".join([*imports, "", "\n\n".join(blocks)]).strip()


def _compile_error_for_text(scan_text: str):
    try:
        import yara
    except Exception:
        return "yara-python unavailable"
    try:
        yara.compile(source=scan_text)
        return None
    except Exception as exc:
        return str(exc)


def _validate_rules_for_source(source, rules):
    imports = _extract_imports(source.get("text") or "")
    valid_rules = []
    skipped = []
    seen = set()

    for rule in rules:
        name = rule.get("rule_name")
        body = rule.get("rule_text") or ""
        if not name or name in seen:
            continue
        seen.add(name)
        if not re.search(r"\bcondition\s*:", body, re.IGNORECASE):
            skipped.append({"rule_name": name or "unknown", "error": "missing condition section"})
            continue
        single_source = "\n".join([*imports, "", body]).strip()
        error = _compile_error_for_text(single_source)
        if error == "yara-python unavailable":
            return rules, _build_reconstructed_yara_source(source.get("text") or "", rules), [], error
        if error:
            skipped.append({"rule_name": name, "error": error})
            continue
        valid_rules.append(rule)

    scan_text = _build_reconstructed_yara_source(source.get("text") or "", valid_rules)
    source_error = _compile_error_for_text(scan_text) if scan_text else "no valid rules"
    if source_error and valid_rules:
        skipped.extend({"rule_name": rule.get("rule_name"), "error": f"source assembly failed: {source_error}"} for rule in valid_rules)
        return [], "", skipped, source_error
    return valid_rules, scan_text, skipped, source_error


def _prioritize_rules(rules):
    def score(rule):
        haystack = " ".join([rule.get("source_name") or "", rule.get("source_file") or "", " ".join(rule.get("tags") or []), str(rule.get("metadata") or {})]).lower()
        value = 0
        if any(word in haystack for word in ["apt", "malware", "trojan", "ransom", "critical", "high"]):
            value += 5
        value += min(len(rule.get("strings") or []), 10)
        return value
    return sorted(rules, key=score, reverse=True)


def _reconstruct_chunked_text(parts):
    cleaned = [part for part in parts if isinstance(part, str) and part.strip()]
    if not cleaned:
        return ""
    text = cleaned[0]
    for part in cleaned[1:]:
        max_overlap = min(len(text), len(part), 800)
        overlap = 0
        for size in range(max_overlap, 0, -1):
            if text[-size:] == part[:size]:
                overlap = size
                break
        if overlap:
            text += part[overlap:]
        else:
            text += "\n" + part
    return text


def _safe_preview(value: bytes):
    text = value.decode("utf-8", errors="ignore")
    return text[:90] if text else value.hex()[:90]


def _fallback_match(rule, data: bytes):
    matches = []
    lower_data = data.lower()
    for string_def in rule.get("strings") or []:
        needle = string_def["bytes"]
        if not needle:
            continue
        found = needle.lower() in lower_data if string_def.get("nocase") else needle in data
        if not found and string_def.get("wide"):
            wide = b"".join(bytes([b, 0]) for b in needle)
            found = wide.lower() in lower_data if string_def.get("nocase") else wide in data
        if found:
            matches.append({
                "identifier": string_def["identifier"],
                "value": _safe_preview(needle),
            })
    return matches


def _yara_python_match_source(source, data: bytes):
    try:
        import yara
    except Exception:
        return None, "yara-python unavailable"
    try:
        compiled = yara.compile(source=source["scan_text"])
        result = compiled.match(data=data, timeout=SCAN_TIMEOUT_SECONDS)
        if not result:
            return [], None
        matched_rules = []
        for item in result:
            matched_strings = []
            for string_match in getattr(item, "strings", []) or []:
                identifier = getattr(string_match, "identifier", "")
                instances = getattr(string_match, "instances", []) or []
                if instances:
                    for inst in instances[:5]:
                        raw = bytes(getattr(inst, "matched_data", b"") or b"")
                        matched_strings.append({"identifier": identifier, "value": _safe_preview(raw)})
                else:
                    matched_strings.append({"identifier": identifier, "value": ""})
            if not matched_strings:
                matched_strings.append({"identifier": "condition", "value": "rule condition matched"})
            matched_rules.append({
                "rule_name": getattr(item, "rule", ""),
                "tags": list(getattr(item, "tags", []) or []),
                "metadata": dict(getattr(item, "meta", {}) or {}),
                "matched_strings": matched_strings,
            })
        return matched_rules, None
    except Exception as exc:
        return None, str(exc)


def _yara_python_compile_source(source):
    try:
        import yara
    except Exception:
        return False, "yara-python unavailable"
    try:
        yara.compile(source=source["scan_text"])
        return True, None
    except Exception as exc:
        return False, str(exc)


def _yara_python_rule_matches(source, data: bytes, rule_name: str):
    matches, error = _yara_python_match_source(source, data)
    if error:
        return False, error
    return any(match.get("rule_name") == rule_name for match in matches or []), None


def _confidence(rule, matched_strings):
    total = max(len(rule.get("strings") or []), 1)
    ratio = min(len(matched_strings) / total, 1.0)
    sev_boost = {"critical": .18, "high": .14, "medium": .08, "low": .04}.get(str(rule.get("severity")).lower(), 0)
    return round(min(.55 + ratio * .35 + sev_boost, .99), 2)


def _is_safe_sample_string(string_def):
    value = string_def.get("value") or ""
    raw = string_def.get("bytes") or b""
    if len(raw) < 4 or len(raw) > 120:
        return False
    if not value or any(ord(ch) < 32 and ch not in "\t\r\n" for ch in value):
        return False
    if re.search(r"\\x[0-9a-fA-F]{2}", value):
        return False
    return True


def _is_pe_only_rule(rule):
    condition = (rule.get("condition") or "").lower()
    if not condition:
        return False
    has_strings = bool(rule.get("strings"))
    pe_terms = ["pe.", "uint16(0)", "uint32(0)", "mz", "pefile"]
    return any(term in condition for term in pe_terms) and not has_strings


def _rule_imports_for_source(source):
    return _extract_imports(source.get("text") or "")


def _single_rule_source(source, rule):
    return {
        "file_name": source.get("file_name"),
        "source_name": source.get("source_name"),
        "rules": [rule],
        "scan_text": "\n".join([*_rule_imports_for_source(source), "", rule.get("rule_text") or ""]).strip(),
    }


def _has_only_quoted_strings(rule):
    section = _strings_section(rule.get("rule_text") or "")
    if not section.strip():
        return False
    assignments = re.findall(r"^\s*\$[A-Za-z0-9_*]+\s*=", section, re.MULTILINE)
    quoted = re.findall(r"^\s*\$[A-Za-z0-9_*]+\s*=\s*\"", section, re.MULTILINE)
    return bool(assignments) and len(assignments) == len(quoted)


def _safe_condition_kind(rule):
    condition = re.sub(r"\s+", " ", (rule.get("condition") or "").strip().lower())
    rule_text = rule.get("rule_text") or ""
    if rule.get("private") or not condition or not rule.get("strings") or not _has_only_quoted_strings(rule):
        return None
    blocked = [
        "pe.imphash", "filesize", "entrypoint", "externals", " for ", " at ", " in ",
        "uint8", "uint16", "uint32", "uint64", "int8", "int16", "int32", "int64",
        " of ($", " and ", " or ", " not ", "defined ", "math.", "elf.", "dotnet.",
    ]
    if any(token in condition for token in blocked):
        return None
    if re.search(r"^\s*\$[A-Za-z0-9_*]+\s*=\s*(?:/|\{)", _strings_section(rule_text), re.MULTILINE):
        return None
    if re.search(r"\b(?:any|1)\s+of\s+them\b", condition):
        return "any"
    if re.search(r"\ball\s+of\s+them\b", condition):
        return "all"
    return None


def _rule_sample_score(rule):
    kind = _safe_condition_kind(rule)
    if not kind:
        return None
    total_count = len(rule.get("strings") or [])
    safe_count = len([s for s in (rule.get("strings") or []) if _is_safe_sample_string(s)])
    if safe_count <= 0:
        return None
    if kind == "all" and safe_count != total_count:
        return None
    score = 10 if kind == "any" else 30
    score += min(safe_count, 50)
    return score


def _sample_bytes_for_rule(rule, kind):
    safe_strings = [s for s in (rule.get("strings") or []) if _is_safe_sample_string(s)]
    if not safe_strings:
        return None, []
    strings_for_sample = safe_strings[:1] if kind == "any" else safe_strings
    sample = bytearray()
    sample.extend(b"MZ\r\n")
    sample.extend(b"Safe synthetic sample for YARA validation\r\n")
    sample.extend(b"Matched safe validation sample\r\n")
    sample.extend(b"This harmless non-executable text is generated by SOC Copilot for static YARA validation only.\r\n")
    sample.extend(f"Validated rule: {rule['rule_name']}\r\n\r\n".encode("utf-8", errors="ignore"))
    for string_def in strings_for_sample:
        raw = string_def["bytes"]
        sample.extend(b" ")
        sample.extend(raw)
        sample.extend(b" \r\n")
        if string_def.get("wide"):
            sample.extend(b" ")
            sample.extend(raw.decode("latin-1", errors="ignore").encode("utf-16le", errors="ignore"))
            sample.extend(b" \r\n")
    return bytes(sample), strings_for_sample


def _build_safe_sample_from_sources(scan_sources):
    candidates = []

    for source in scan_sources:
        compiled, _ = _yara_python_compile_source(source)
        if not compiled:
            continue
        for rule in source.get("rules") or []:
            score = _rule_sample_score(rule)
            if score is None:
                continue
            candidates.append((score, source, rule, _safe_condition_kind(rule)))

    for _, source, rule, kind in sorted(candidates, key=lambda item: item[0]):
        sample_bytes, strings_for_sample = _sample_bytes_for_rule(rule, kind)
        if not sample_bytes:
            continue
        single_source = _single_rule_source(source, rule)
        matched, error = _yara_python_rule_matches(single_source, sample_bytes, rule["rule_name"])
        if not matched:
            continue
        return sample_bytes, [{
            "rule_name": rule["rule_name"],
            "source_file": source["file_name"],
            "source_name": source["source_name"],
            "strings_used": len(strings_for_sample),
            "condition_kind": kind,
            "validated": True,
            "validation_error": error,
        }]

    return None, []


async def _load_yara_rule_sources(request: Request, project_id: int):
    async with request.app.db_client() as session:
        asset_stmt = (
            select(Asset)
            .where(
                Asset.asset_project_id == project_id,
                Asset.asset_type == AssetTypeEnum.FILE.value,
            )
            .order_by(Asset.created_at.asc(), Asset.asset_id.asc())
        )
        asset_result = await session.execute(asset_stmt)
        assets = asset_result.scalars().all()

        stmt = (
            select(DataChunk)
            .where(DataChunk.chunk_project_id == project_id)
            .order_by(DataChunk.chunk_asset_id.asc(), DataChunk.chunk_order.asc())
        )
        result = await session.execute(stmt)
        chunks = result.scalars().all()

    raw_sources = {}
    for asset in assets:
        asset_config = asset.asset_config if isinstance(asset.asset_config, dict) else {}
        if asset_config.get("content_type") != "yara_rule":
            continue
        raw_source = asset_config.get("raw_source") if isinstance(asset_config.get("raw_source"), dict) else {}
        raw_text = raw_source.get("full_text")
        if not isinstance(raw_text, str) or not raw_text.strip():
            continue
        raw_sources[asset.asset_id] = {
            "file_name": raw_source.get("original_filename") or asset_config.get("file_name") or asset.asset_name or "yara_rules.yar",
            "source_name": asset_config.get("source_name") or "YARA Rules",
            "text": raw_text,
            "source_origin": "raw_source",
            "raw_uploaded_at": raw_source.get("uploaded_at") or asset_config.get("uploaded_at"),
        }

    sources = {}
    for chunk in chunks:
        metadata = chunk.chunk_metadata or {}
        if metadata.get("content_type") != "yara_rule":
            continue
        if chunk.chunk_asset_id in raw_sources:
            continue
        key = (chunk.chunk_asset_id, metadata.get("file_name") or "yara_rules.yar")
        if key not in sources:
            sources[key] = {
                "file_name": metadata.get("file_name") or "yara_rules.yar",
                "source_name": metadata.get("source_name") or "YARA Rules",
                "parts": [],
                "source_origin": "chunk_reconstruction",
            }
        sources[key]["parts"].append(chunk.chunk_text or "")

    chunk_sources = [
        {
            "file_name": item["file_name"],
            "source_name": item["source_name"],
            "text": _reconstruct_chunked_text(item["parts"]),
            "source_origin": item["source_origin"],
        }
        for item in sources.values()
    ]
    return [*raw_sources.values(), *chunk_sources]


def _prepare_scan_sources(sources, mode):
    prepared = []
    remaining = FAST_SCAN_LIMIT if mode == "fast" else None
    for source in sources:
        parsed_rules = _prioritize_rules(_parse_rules_from_source(source))
        rules = parsed_rules
        if not rules:
            continue
        if remaining is not None:
            if remaining <= 0:
                break
            rules = rules[:remaining]
            remaining -= len(rules)
        valid_rules, scan_text, skipped_rules, source_error = _validate_rules_for_source(source, rules)
        if not scan_text:
            if skipped_rules:
                prepared.append({
                    **source,
                    "rules": [],
                    "scan_text": "",
                    "parsed_rule_count": len(parsed_rules),
                    "skipped_rules": skipped_rules,
                    "compile_error": source_error,
                })
            continue
        prepared.append({
            **source,
            "rules": valid_rules,
            "scan_text": scan_text,
            "parsed_rule_count": len(parsed_rules),
            "skipped_rules": skipped_rules,
            "compile_error": source_error,
        })
    return prepared


@yara_scanner_router.get("/sample/{project_id}")
async def generate_yara_safe_sample(request: Request, project_id: int):
    try:
        project_model = await ProjectModel.create_instance(db_client=request.app.db_client)
        project = await project_model.get_project_or_create_one(project_id=project_id)
        sources = await _load_yara_rule_sources(request=request, project_id=project.project_id)
        scan_sources = _prepare_scan_sources(sources, "full")
        sample_bytes, selected_rules = _build_safe_sample_from_sources(scan_sources)
        skipped_corrupted = sum(len(source.get("skipped_rules") or []) for source in scan_sources)
        if not sample_bytes:
            return JSONResponse(content={
                "signal": "no_safe_yara_sample",
                "message": "No safely matchable YARA rule found.",
                "label": "Safe synthetic sample for YARA validation",
                "file_name": None,
                "mime_type": "text/plain",
                "sample_base64": "",
                "selected_rules": [],
                "diagnostics": {
                    "loaded_yara_sources": len(sources),
                    "usable_sources": len(scan_sources),
                    "skipped_corrupted_rules": skipped_corrupted,
                    "selected_rules": 0,
                },
            })
        return JSONResponse(content={
            "signal": "safe_yara_sample_generated",
            "label": "Matched safe validation sample",
            "file_name": "safe-yara-validation-sample.txt",
            "mime_type": "text/plain",
            "sample_base64": base64.b64encode(sample_bytes).decode("ascii"),
            "selected_rules": selected_rules,
            "diagnostics": {
                "loaded_yara_sources": len(sources),
                "usable_sources": len(scan_sources),
                "skipped_corrupted_rules": skipped_corrupted,
                "selected_rules": len(selected_rules),
            },
        })
    except Exception as exc:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "signal": "safe_yara_sample_failed",
                "detail": str(exc),
            },
        )


@yara_scanner_router.post("/scan/{project_id}")
async def scan_yara(request: Request, project_id: int, file: UploadFile = File(...), scan_mode: str = Form("fast")):
    started = time.perf_counter()
    raw = await file.read()
    if not raw:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"signal": "empty_scan_file"})
    if len(raw) > MAX_SCAN_BYTES:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content={"signal": "scan_file_too_large"})

    mode = "full" if str(scan_mode).lower() == "full" else "fast"
    try:
        project_model = await ProjectModel.create_instance(db_client=request.app.db_client)
        project = await project_model.get_project_or_create_one(project_id=project_id)
        sources = await _load_yara_rule_sources(request=request, project_id=project.project_id)
    except Exception as exc:
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "signal": "yara_scan_failed",
                "detail": str(exc),
                "file_name": file.filename or "uploaded.bin",
                "file_sha256": hashlib.sha256(raw).hexdigest(),
                "scan_mode": mode,
                "duration_ms": duration_ms,
                "scanned_rules": 0,
                "available_rules": 0,
                "matched_rules": 0,
                "matches": [],
                "errors": [{"error": str(exc)}],
                "diagnostics": {
                    "loaded_yara_sources": 0,
                    "compiled_rules": 0,
                    "failed_rules": 0,
                    "fallback_rules": 0,
                    "usable_rules": 0,
                },
            },
        )

    errors = []
    try:
        scan_sources = _prepare_scan_sources(sources, mode)
    except Exception as exc:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={
                "signal": "yara_scan_complete",
                "message": "No usable YARA rules found in this project.",
                "file_name": file.filename or "uploaded.bin",
                "file_sha256": hashlib.sha256(raw).hexdigest(),
                "scan_mode": mode,
                "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                "scanned_rules": 0,
                "available_rules": 0,
                "matched_rules": 0,
                "matches": [],
                "errors": [{"error": str(exc)}],
                "diagnostics": {
                    "loaded_yara_sources": len(sources),
                    "compiled_rules": 0,
                    "failed_rules": 0,
                    "fallback_rules": 0,
                    "usable_rules": 0,
                },
            },
        )

    usable_rules = sum(len(source["rules"]) for source in scan_sources)
    diagnostics = {
        "loaded_yara_sources": len(sources),
        "compiled_rules": 0,
        "failed_rules": 0,
        "fallback_rules": 0,
        "skipped_corrupted_rules": sum(len(source.get("skipped_rules") or []) for source in scan_sources),
        "usable_rules": usable_rules,
        "scanned_sources": len(scan_sources),
        "sources": [
            {
                "source_name": source["source_name"],
                "source_file": source["file_name"],
                "source_origin": source.get("source_origin") or "unknown",
                "rule_count": len(source["rules"]),
                "parsed_rule_count": source.get("parsed_rule_count", len(source["rules"])),
                "skipped_corrupted_rules": len(source.get("skipped_rules") or []),
                "skipped_rules": source.get("skipped_rules") or [],
                "compile_error": source.get("compile_error"),
                "reconstructed_source": source["scan_text"],
            }
            for source in scan_sources
        ],
    }

    if usable_rules == 0:
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        skipped_errors = [
            {
                "source_name": source["source_name"],
                "source_file": source["file_name"],
                "rule_name": skipped.get("rule_name"),
                "error": skipped.get("error") or "corrupted or incomplete rule skipped",
            }
            for source in scan_sources
            for skipped in (source.get("skipped_rules") or [])
        ]
        return JSONResponse(content={
            "signal": "yara_scan_complete",
            "message": "No usable YARA rules found in this project.",
            "file_name": file.filename or "uploaded.bin",
            "file_sha256": hashlib.sha256(raw).hexdigest(),
            "scan_mode": mode,
            "duration_ms": duration_ms,
            "scanned_rules": 0,
            "available_rules": 0,
            "matched_rules": 0,
            "matches": [],
            "errors": skipped_errors,
            "diagnostics": diagnostics,
        })

    for source in scan_sources:
        for skipped in source.get("skipped_rules") or []:
            errors.append({
                "source_name": source["source_name"],
                "source_file": source["file_name"],
                "rule_name": skipped.get("rule_name"),
                "error": skipped.get("error") or "corrupted or incomplete rule skipped",
            })

    matches = []
    scanned_rules = 0

    async def run_scan():
        nonlocal scanned_rules
        for source in scan_sources:
            source_rule_count = len(source["rules"])
            scanned_rules += source_rule_count
            rule_by_name = {rule["rule_name"]: rule for rule in source["rules"]}
            matched_rules, err = _yara_python_match_source(source, raw)
            if matched_rules is not None:
                diagnostics["compiled_rules"] += source_rule_count
                for matched in matched_rules:
                    rule = rule_by_name.get(matched.get("rule_name")) or {
                        "rule_name": matched.get("rule_name") or "UnknownRule",
                        "source_file": source["file_name"],
                        "source_name": source["source_name"],
                        "tags": matched.get("tags") or [],
                        "metadata": matched.get("metadata") or {},
                        "severity": _severity_from_rule(matched.get("tags") or [], matched.get("metadata") or {}),
                        "strings": [],
                    }
                    matches.append({
                        "rule_name": rule["rule_name"],
                        "source_rule_file": source["file_name"],
                        "source_name": source["source_name"],
                        "tags": matched.get("tags") or rule.get("tags") or [],
                        "severity": _severity_from_rule(matched.get("tags") or rule.get("tags") or [], matched.get("metadata") or rule.get("metadata") or {}),
                        "metadata": matched.get("metadata") or rule.get("metadata") or {},
                        "matched_strings": matched.get("matched_strings") or [],
                        "confidence": _confidence(rule, matched.get("matched_strings") or []),
                        "rule_type": "matched_uploaded_yara_rule",
                        "scan_engine": "yara-python",
                    })
                continue

            diagnostics["failed_rules"] += source_rule_count
            diagnostics["fallback_rules"] += source_rule_count
            if err and err != "yara-python unavailable":
                errors.append({"source_name": source["source_name"], "source_file": source["file_name"], "error": err})
                for item in diagnostics["sources"]:
                    if item["source_file"] == source["file_name"] and item["source_name"] == source["source_name"]:
                        item["compile_error"] = err
                        break

            for rule in source["rules"]:
                matched_strings = _fallback_match(rule, raw)
                if matched_strings:
                    matches.append({
                        "rule_name": rule["rule_name"],
                        "source_rule_file": source["file_name"],
                        "source_name": source["source_name"],
                        "tags": rule["tags"],
                        "severity": rule["severity"],
                        "metadata": rule["metadata"],
                        "matched_strings": matched_strings,
                        "confidence": _confidence(rule, matched_strings),
                        "rule_type": "matched_uploaded_yara_rule",
                        "scan_engine": "fallback",
                    })

    try:
        await asyncio.wait_for(run_scan(), timeout=SCAN_TIMEOUT_SECONDS + 2)
    except asyncio.TimeoutError:
        errors.append({"error": "scan timeout reached; partial results returned"})
    except Exception as exc:
        errors.append({"error": str(exc)})

    duration_ms = round((time.perf_counter() - started) * 1000, 2)
    return JSONResponse(content={
        "signal": "yara_scan_complete",
        "file_name": file.filename or "uploaded.bin",
        "file_sha256": hashlib.sha256(raw).hexdigest(),
        "scan_mode": mode,
        "duration_ms": duration_ms,
        "scanned_rules": scanned_rules,
        "available_rules": usable_rules,
        "matched_rules": len(matches),
        "matches": matches,
        "errors": errors,
        "diagnostics": diagnostics,
    })
