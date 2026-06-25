from fastapi import APIRouter, Request, UploadFile, File, Form, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from urllib.parse import urlparse
import aiofiles
import gzip
import httpx
import json
import logging
import os
import re

from controllers import DataController, ProcessController, NLPController, ProjectController
from models.ProjectModel import ProjectModel
from models.AssetModel import AssetModel
from models.ChunkModel import ChunkModel
from models.db_schemes import Asset, DataChunk
from models.enums.AssetTypeEnum import AssetTypeEnum
from models import ResponseSignal


logger = logging.getLogger("uvicorn.error")

admin_router = APIRouter(
    prefix="/api/v1/admin",
    tags=["api_v1", "admin"],
)


CHUNK_SIZES = {
    "malware_report": 1200,
    "cve": 100,
    "threat_intel": 120,
    "alert_sample": 80,
    "log_sample": 60,
    "sigma_rule": 100,
    "yara_rule": 1200,
    "mitre_data": 200,
}

ALLOWED_CONTENT_TYPES = set(CHUNK_SIZES.keys())
CONTENT_TYPE_LABELS = {
    "yara_rule": "YARA Rules",
    "sigma_rule": "Sigma Rules",
}
CONTENT_TYPE_ALIASES = {
    "yara rules": "yara_rule",
    "yara rule": "yara_rule",
    "yara": "yara_rule",
    "sigma rules": "sigma_rule",
    "sigma rule": "sigma_rule",
    "sigma": "sigma_rule",
}
ALLOWED_EXTENSIONS = {
    ".pdf",
    ".txt",
    ".log",
    ".json",
    ".sigma",
    ".yar",
    ".yara",
    ".gz",
    ".yaml",
    ".yml",
    ".html",
    ".htm",
}
INDEX_BATCH_SIZE = 128
PLAIN_TEXT_EXTENSIONS = {
    ".txt",
    ".log",
    ".sigma",
    ".yar",
    ".yara",
}


class FetchURLRequest(BaseModel):
    url: str
    content_type: str
    source_name: str
    description: Optional[str] = None


def _normalize_content_type(content_type: str):
    if not isinstance(content_type, str):
        return content_type

    normalized = content_type.strip()
    key = normalized.lower().replace("-", "_")
    label_key = normalized.lower().replace("_", " ")
    return CONTENT_TYPE_ALIASES.get(label_key, key)


def _is_supported_content_type(content_type: str):
    return _normalize_content_type(content_type) in ALLOWED_CONTENT_TYPES


def _content_type_label(content_type: str):
    return CONTENT_TYPE_LABELS.get(content_type, content_type)



def _normalize_description(description: Optional[str]):
    return (description or "").strip()


def _chunk_size_for(content_type: str):
    return CHUNK_SIZES.get(content_type, 100)


def _normalize_chunk_size(chunk_size: Optional[int], content_type: str):
    if chunk_size is None:
        return _chunk_size_for(content_type)

    try:
        return min(max(int(chunk_size), 50), 5000)
    except (TypeError, ValueError):
        return _chunk_size_for(content_type)


def _overlap_size_for(chunk_size: int):
    return max(20, chunk_size // 5)


def _base_metadata(content_type: str, source_name: str, description: str, file_name: str):
    return {
        "content_type": content_type,
        "source_name": source_name,
        "description": description,
        "file_name": file_name,
        "uploaded_at": datetime.utcnow().isoformat(),
    }


def _clean_file_name(file_name: str):
    return DataController().get_clean_file_name(file_name or "admin_asset.txt")


def _looks_like_gzip(file_name: str, header_content_type: str):
    lower_name = (file_name or "").lower()
    header_value = (header_content_type or "").lower()
    return lower_name.endswith(".gz") or "gzip" in header_value


def _decompress_if_needed(raw: bytes, file_name: str, header_content_type: str):
    if not _looks_like_gzip(file_name=file_name, header_content_type=header_content_type):
        return raw

    try:
        return gzip.decompress(raw)
    except Exception:
        return raw


def extract_text_from_json(data, content_type: str) -> str:
    texts = []

    if content_type == "mitre_data":
        objects = data.get("objects", []) if isinstance(data, dict) else []
        for obj in objects:
            if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
                continue

            name = obj.get("name", "")
            desc = obj.get("description", "")
            kill_chain = obj.get("kill_chain_phases", [])
            phases = ", ".join([
                phase.get("phase_name", "")
                for phase in kill_chain
                if isinstance(phase, dict)
            ])
            ext_refs = obj.get("external_references", [])
            technique_id = next(
                (
                    ref.get("external_id", "")
                    for ref in ext_refs
                    if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack"
                ),
                "",
            )
            texts.append(
                f"Technique: {technique_id} - {name}\n"
                f"Tactic: {phases}\n"
                f"Description: {desc}\n"
            )

    elif content_type == "cve":
        items = []
        if isinstance(data, dict):
            items = data.get("CVE_Items", data.get("vulnerabilities", []))

        for item in items[:500]:
            if not isinstance(item, dict):
                continue

            cve_data = item.get("cve", item)
            cve_id = ""
            if isinstance(cve_data, dict):
                cve_id = cve_data.get("id", cve_data.get("CVE_data_meta", {}).get("ID", ""))

            descriptions = []
            if isinstance(cve_data, dict):
                descriptions = cve_data.get("descriptions", cve_data.get("description", {}).get("description_data", []))

            description = next(
                (
                    desc.get("value", "")
                    for desc in descriptions
                    if isinstance(desc, dict) and desc.get("lang", "en") == "en"
                ),
                "",
            )

            metrics = {}
            if isinstance(cve_data, dict):
                metrics = cve_data.get("metrics", {})
            if not metrics and isinstance(item, dict):
                metrics = item.get("metrics", {})
            cvss_score = ""
            if isinstance(metrics, dict):
                cvss_data = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", metrics.get("cvssMetricV2", [])))
                if isinstance(cvss_data, list) and len(cvss_data):
                    cvss_score = str(cvss_data[0].get("cvssData", {}).get("baseScore", ""))

            texts.append(
                f"CVE: {cve_id}\n"
                f"Score: {cvss_score}\n"
                f"Description: {description}\n"
            )

    else:
        def flatten_json(obj, prefix=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    flatten_json(value, f"{prefix}{key}: ")
            elif isinstance(obj, list):
                for item in obj[:50]:
                    flatten_json(item, prefix)
            elif isinstance(obj, str) and len(obj.strip()) > 20:
                texts.append(f"{prefix}{obj.strip()}")

        flatten_json(data)

    return "\n\n".join([item for item in texts if isinstance(item, str) and len(item.strip())])


def extract_text_from_html(html: str) -> str:
    html = re.sub(r"<script[^>]*>.*?</script>", "", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:50000]


def extract_text_from_pdf_bytes(raw: bytes) -> str:
    try:
        import fitz

        doc = fitz.open(stream=raw, filetype="pdf")
        return "\n".join([page.get_text() for page in doc])
    except Exception:
        return raw.decode("utf-8", errors="ignore")[:50000]


def _extract_text_from_raw(raw: bytes, file_name: str, header_content_type: str, content_type: str):
    raw = _decompress_if_needed(raw=raw, file_name=file_name, header_content_type=header_content_type)
    lower_name = (file_name or "").lower()
    file_ext = os.path.splitext(lower_name)[1]
    content_header = (header_content_type or "").lower()

    if file_ext in PLAIN_TEXT_EXTENSIONS or content_type in {"sigma_rule", "yara_rule"}:
        return raw.decode("utf-8", errors="ignore")

    if "json" in content_header or lower_name.endswith(".json") or lower_name.endswith(".json.gz"):
        data = json.loads(raw.decode("utf-8", errors="ignore"))
        return extract_text_from_json(data, content_type)

    if "pdf" in content_header or lower_name.endswith(".pdf"):
        return extract_text_from_pdf_bytes(raw)

    if lower_name.endswith(".yml") or lower_name.endswith(".yaml"):
        return raw.decode("utf-8", errors="ignore")

    if "html" in content_header or lower_name.endswith(".html") or lower_name.endswith(".htm"):
        return extract_text_from_html(raw.decode("utf-8", errors="ignore"))

    return raw.decode("utf-8", errors="ignore")


def _chunk_log_like_text(text: str, metadata: dict):
    from controllers.ProcessController import Document

    return [
        Document(page_content=line.strip(), metadata=dict(metadata))
        for line in text.splitlines()
        if isinstance(line, str) and len(line.strip())
    ]


def _extract_yara_imports(text: str):
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


def _extract_yara_rule_blocks(text: str):
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
        block = text[match.start():end].strip()
        if re.search(r"\bmeta\s*:", block, re.IGNORECASE) or re.search(r"\bstrings\s*:", block, re.IGNORECASE) or re.search(r"\bcondition\s*:", block, re.IGNORECASE):
            blocks.append({"name": match.group(2), "text": block})
        pos = end
    return blocks


def _chunk_yara_text(text: str, metadata: dict, chunk_size: Optional[int] = None):
    from controllers.ProcessController import Document

    imports = _extract_yara_imports(text)
    rules = _extract_yara_rule_blocks(text)
    effective_chunk_size = _normalize_chunk_size(chunk_size, "yara_rule")
    documents = []
    current = "\n".join(imports).strip()
    current_names = []

    for rule in rules:
        rule_text = rule["text"].strip()
        candidate = "\n\n".join([part for part in [current, rule_text] if part.strip()])
        if current_names and len(candidate) > effective_chunk_size:
            chunk_metadata = dict(metadata)
            chunk_metadata["yara_rule_names"] = list(current_names)
            chunk_metadata["yara_chunk_strategy"] = "rule_boundary"
            documents.append(Document(page_content=current.strip(), metadata=chunk_metadata))
            current = "\n".join([*imports, "", rule_text]).strip()
            current_names = [rule["name"]]
        else:
            current = candidate
            current_names.append(rule["name"])

    if current.strip():
        chunk_metadata = dict(metadata)
        chunk_metadata["yara_rule_names"] = list(current_names)
        chunk_metadata["yara_chunk_strategy"] = "rule_boundary"
        documents.append(Document(page_content=current.strip(), metadata=chunk_metadata))

    return documents


async def _get_project(request: Request, project_id: int):
    project_model = await ProjectModel.create_instance(db_client=request.app.db_client)
    return await project_model.get_project_or_create_one(project_id=project_id)


async def _store_asset_file(project_id: int, file_name: str, raw: bytes):
    file_path, file_id = DataController().generate_unique_filepath(
        orig_file_name=file_name,
        project_id=project_id,
    )

    async with aiofiles.open(file_path, "wb") as f:
        await f.write(raw)

    return file_path, file_id


async def _create_asset_record(request: Request, project_id: int, file_id: str, file_size: int, asset_config: dict):
    asset_model = await AssetModel.create_instance(db_client=request.app.db_client)
    asset_resource = Asset(
        asset_project_id=project_id,
        asset_type=AssetTypeEnum.FILE.value,
        asset_name=file_id,
        asset_size=file_size,
        asset_config=asset_config,
    )
    return await asset_model.create_asset(asset=asset_resource)


async def _persist_and_index_chunks(request: Request, project, asset_record, chunks: list):
    chunk_model = await ChunkModel.create_instance(db_client=request.app.db_client)

    chunk_records = [
        DataChunk(
            chunk_text=chunk.page_content,
            chunk_metadata=chunk.metadata,
            chunk_order=index + 1,
            chunk_project_id=project.project_id,
            chunk_asset_id=asset_record.asset_id,
        )
        for index, chunk in enumerate(chunks)
    ]

    await chunk_model.insert_many_chunks(chunk_records)
    stored_chunks = await chunk_model.get_chunks_by_asset_id(asset_record.asset_id)

    nlp_controller = NLPController(
        vectordb_client=request.app.vectordb_client,
        generation_client=request.app.generation_client,
        embedding_client=request.app.embedding_client,
        template_parser=request.app.template_parser,
    )

    vectors_indexed = 0
    for index in range(0, len(stored_chunks), INDEX_BATCH_SIZE):
        batch = stored_chunks[index:index + INDEX_BATCH_SIZE]
        is_inserted = await nlp_controller.index_into_vector_db(
            project=project,
            chunks=batch,
            chunks_ids=[chunk.chunk_id for chunk in batch],
        )
        if not is_inserted:
            raise RuntimeError("vector_index_failed")
        vectors_indexed += len(batch)

    return len(stored_chunks), vectors_indexed


def _admin_chunks_from_text(text: str, content_type: str, metadata: dict, chunk_size: Optional[int] = None):
    if content_type == "log_sample":
        return _chunk_log_like_text(text=text, metadata=metadata)
    if content_type == "yara_rule":
        return _chunk_yara_text(text=text, metadata=metadata, chunk_size=chunk_size)

    process_controller = ProcessController(project_id=0)
    effective_chunk_size = _normalize_chunk_size(chunk_size, content_type)
    return process_controller.process_simpler_splitter(
        texts=[text],
        metadatas=[dict(metadata)],
        chunk_size=effective_chunk_size,
        overlap_size=_overlap_size_for(effective_chunk_size),
    )


def _sort_assets_for_status(assets: list):
    return sorted(
        assets,
        key=lambda item: getattr(item, "created_at", None) or datetime.min,
        reverse=True,
    )


@admin_router.post("/upload/{project_id}")
async def admin_upload(
    request: Request,
    project_id: int,
    file: UploadFile = File(...),
    content_type: str = Form(...),
    source_name: str = Form(...),
    description: str = Form(""),
    chunk_size: Optional[int] = Form(None),
):
    content_type = _normalize_content_type(content_type)
    if not _is_supported_content_type(content_type):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"signal": "invalid_content_type"},
        )

    source_name = (source_name or "").strip()
    if not source_name:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"signal": "invalid_source_name"},
        )

    description = _normalize_description(description)
    effective_chunk_size = _normalize_chunk_size(chunk_size, content_type)
    file_name = file.filename or "admin_asset.txt"
    file_ext = os.path.splitext(file_name)[1].lower()

    if file_ext not in ALLOWED_EXTENSIONS:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"signal": ResponseSignal.FILE_TYPE_NOT_SUPPORTED.value},
        )

    raw = await file.read()
    if len(raw) == 0:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"signal": ResponseSignal.FILE_UPLOAD_FAILED.value},
        )

    if len(raw) > 100 * 1024 * 1024:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"signal": ResponseSignal.FILE_SIZE_EXCEEDED.value},
        )

    project = await _get_project(request=request, project_id=project_id)

    try:
        text = _extract_text_from_raw(
            raw=raw,
            file_name=file_name,
            header_content_type=file.content_type or "",
            content_type=content_type,
        )
    except Exception as exc:
        logger.error("Admin upload text extraction failed for %s: %s", file_name, exc)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": "admin_text_extraction_failed",
                "file_name": file_name,
                "detail": f"text extraction failed for {file_name}",
            },
        )

    text = (text or "").strip()
    if not text:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": "empty_extracted_text",
                "file_name": file_name,
                "detail": f"no text could be extracted from {file_name}",
            },
        )

    file_path = None
    try:
        file_path, file_id = await _store_asset_file(project_id=project_id, file_name=file_name, raw=raw)
        metadata = _base_metadata(
            content_type=content_type,
            source_name=source_name,
            description=description,
            file_name=file_name,
        )
        metadata["chunk_size"] = effective_chunk_size
        metadata["overlap_size"] = _overlap_size_for(effective_chunk_size)
        if content_type == "yara_rule":
            metadata["raw_source"] = {
                "original_filename": file_name,
                "full_text": text,
                "uploaded_at": metadata["uploaded_at"],
            }
            metadata["yara_rules_detected"] = len(_extract_yara_rule_blocks(text))
        asset_record = await _create_asset_record(
            request=request,
            project_id=project.project_id,
            file_id=file_id,
            file_size=len(raw),
            asset_config=metadata,
        )
        chunk_metadata = dict(metadata)
        chunk_metadata.pop("raw_source", None)
        chunks = _admin_chunks_from_text(
            text=text,
            content_type=content_type,
            metadata=chunk_metadata,
            chunk_size=effective_chunk_size,
        )
        chunks_created, vectors_indexed = await _persist_and_index_chunks(
            request=request,
            project=project,
            asset_record=asset_record,
            chunks=chunks,
        )
    except Exception as exc:
        logger.error("Admin upload failed for %s: %s", file_name, exc)
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "signal": "admin_upload_failed",
                "file_name": file_name,
                "detail": f"indexing failed for {file_name}: {str(exc)}",
            },
        )

    return JSONResponse(
        content={
            "signal": "upload_success",
            "file_name": file_name,
            "content_type": content_type,
            "content_type_label": _content_type_label(content_type),
            "source_name": source_name,
            "chunk_size": effective_chunk_size,
            "chunks_created": chunks_created,
            "vectors_indexed": vectors_indexed,
            "ready_for_rag": True,
        }
    )


@admin_router.post("/fetch-url/{project_id}")
async def fetch_url(request: Request, project_id: int, body: FetchURLRequest):
    content_type = _normalize_content_type(body.content_type)
    if not _is_supported_content_type(content_type):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"signal": "invalid_content_type"},
        )

    if not isinstance(body.url, str) or not len(body.url.strip()):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"signal": "invalid_url"},
        )

    project = await _get_project(request=request, project_id=project_id)
    source_name = (body.source_name or "").strip() or "Fetched Source"
    description = _normalize_description(body.description)

    try:
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            response = await client.get(
                body.url,
                headers={"User-Agent": "SOC-Copilot/1.0"},
            )
            response.raise_for_status()
            raw = response.content
            content_type_header = response.headers.get("content-type", "")
    except Exception as exc:
        logger.error("Admin fetch failed for %s: %s", body.url, exc)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"signal": "fetch_failed"},
        )

    parsed_url = urlparse(body.url)
    original_name = os.path.basename(parsed_url.path) or f"{_clean_file_name(source_name)}.txt"

    try:
        text = _extract_text_from_raw(
            raw=raw,
            file_name=original_name,
            header_content_type=content_type_header,
            content_type=content_type,
        )
    except Exception as exc:
        logger.error("Admin fetch text extraction failed for %s: %s", body.url, exc)
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"signal": "fetch_text_extraction_failed"},
        )

    text = (text or "").strip()
    if not text:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"signal": "empty_fetched_text"},
        )

    saved_text_name = os.path.splitext(_clean_file_name(original_name))[0] + ".txt"
    file_path = None
    try:
        file_path, file_id = await _store_asset_file(
            project_id=project_id,
            file_name=saved_text_name,
            raw=text.encode("utf-8", errors="ignore"),
        )

        metadata = _base_metadata(
            content_type=content_type,
            source_name=source_name,
            description=description,
            file_name=saved_text_name,
        )
        metadata["source_url"] = body.url
        metadata["fetched_at"] = datetime.utcnow().isoformat()
        if content_type == "yara_rule":
            metadata["raw_source"] = {
                "original_filename": original_name,
                "full_text": text,
                "uploaded_at": metadata["fetched_at"],
            }
            metadata["yara_rules_detected"] = len(_extract_yara_rule_blocks(text))

        asset_record = await _create_asset_record(
            request=request,
            project_id=project.project_id,
            file_id=file_id,
            file_size=os.path.getsize(file_path),
            asset_config=metadata,
        )
        chunk_metadata = dict(metadata)
        chunk_metadata.pop("raw_source", None)
        chunks = _admin_chunks_from_text(text=text, content_type=content_type, metadata=chunk_metadata)
        chunks_created, vectors_indexed = await _persist_and_index_chunks(
            request=request,
            project=project,
            asset_record=asset_record,
            chunks=chunks,
        )
    except Exception as exc:
        logger.error("Admin fetch indexing failed for %s: %s", body.url, exc)
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"signal": "fetch_index_failed"},
        )

    return JSONResponse(
        content={
            "signal": "fetch_success",
            "url": body.url,
            "content_type": content_type,
            "content_type_label": _content_type_label(content_type),
            "source_name": source_name,
            "characters_fetched": len(text),
            "chunks_created": chunks_created,
            "vectors_indexed": vectors_indexed,
            "ready_for_rag": True,
        }
    )


@admin_router.get("/kb-status/{project_id}")
async def kb_status(request: Request, project_id: int):
    project = await _get_project(request=request, project_id=project_id)

    asset_model = await AssetModel.create_instance(db_client=request.app.db_client)
    chunk_model = await ChunkModel.create_instance(db_client=request.app.db_client)

    assets = await asset_model.get_all_project_assets(
        asset_project_id=project.project_id,
        asset_type=AssetTypeEnum.FILE.value,
    )

    by_content_type = {}
    sources = []
    total_chunks = 0

    for asset in _sort_assets_for_status(assets):
        asset_config = asset.asset_config if isinstance(asset.asset_config, dict) else {}
        content_type = asset_config.get("content_type", "uncategorized")
        source_name = asset_config.get("source_name", asset.asset_name)
        chunks = await chunk_model.get_chunks_by_asset_id(asset.asset_id)
        chunk_count = len(chunks)
        total_chunks += chunk_count
        by_content_type[content_type] = by_content_type.get(content_type, 0) + chunk_count

        sources.append({
            "asset_name": asset.asset_name,
            "source_name": source_name,
            "content_type": content_type,
            "description": asset_config.get("description", ""),
            "chunks": chunk_count,
            "created_at": str(asset.created_at) if getattr(asset, "created_at", None) else None,
        })

    nlp_controller = NLPController(
        vectordb_client=request.app.vectordb_client,
        generation_client=request.app.generation_client,
        embedding_client=request.app.embedding_client,
        template_parser=request.app.template_parser,
    )
    collection_info = None
    try:
        collection_info = await nlp_controller.get_vector_db_collection_info(project=project)
    except Exception as exc:
        logger.info(
            "KB status collection missing or unavailable for project %s: %s",
            project.project_id,
            exc,
        )
    total_vectors = 0
    if isinstance(collection_info, dict):
        total_vectors = collection_info.get("record_count", 0) or 0

    return JSONResponse(
        content={
            "signal": "kb_status_success",
            "project_id": project.project_id,
            "total_vectors": total_vectors,
            "documents": len(assets),
            "total_chunks": total_chunks,
            "by_content_type": by_content_type,
            "sources": sources[:10],
            "collection_info": collection_info,
        }
    )


@admin_router.post("/clear/{project_id}")
async def clear_kb(request: Request, project_id: int):
    project = await _get_project(request=request, project_id=project_id)

    chunk_model = await ChunkModel.create_instance(db_client=request.app.db_client)
    asset_model = await AssetModel.create_instance(db_client=request.app.db_client)

    nlp_controller = NLPController(
        vectordb_client=request.app.vectordb_client,
        generation_client=request.app.generation_client,
        embedding_client=request.app.embedding_client,
        template_parser=request.app.template_parser,
    )
    collection_name = nlp_controller.create_collection_name(project_id=project.project_id)

    await request.app.vectordb_client.delete_collection(collection_name=collection_name)
    deleted_chunks = await chunk_model.delete_chunks_by_project_id(project_id=project.project_id)
    deleted_assets = await asset_model.delete_assets_by_project_id(asset_project_id=project.project_id)

    project_path = ProjectController().get_project_path(project_id=project.project_id)
    deleted_files = 0
    for file_name in os.listdir(project_path):
        file_path = os.path.join(project_path, file_name)
        if os.path.isfile(file_path):
            os.remove(file_path)
            deleted_files += 1

    return JSONResponse(
        content={
            "signal": "kb_clear_success",
            "deleted_chunks": deleted_chunks,
            "deleted_assets": deleted_assets,
            "deleted_files": deleted_files,
        }
    )
