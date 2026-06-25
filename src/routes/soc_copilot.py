from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import List, Optional
import json

from controllers import NLPController
from models.ProjectModel import ProjectModel
from modules.log_analysis import LogParser
from modules.investigation import CorrelationEngine
from modules.threat_intel import ThreatIntelAnalyzer
from modules.output import OutputFormatter


soc_router = APIRouter(tags=["soc_copilot"])


class AnalyzeLogsRequest(BaseModel):
    logs: str
    project_id: Optional[int] = 1
    top_k: Optional[int] = 5


class AnalyzeCVERequest(BaseModel):
    cve_id: str
    cve_text: Optional[str] = ""
    project_id: Optional[int] = 1
    top_k: Optional[int] = 5


class InvestigateRequest(BaseModel):
    events: Optional[List[str]] = []
    logs: Optional[str] = ""
    project_id: Optional[int] = 1
    top_k: Optional[int] = 5


def _flatten_iocs(iocs: dict):
    values = []
    if not isinstance(iocs, dict):
        return values

    for _, items in iocs.items():
        if isinstance(items, list):
            values.extend(items)

    return list(dict.fromkeys(values))


def _event_to_dict(event):
    if hasattr(event, "model_dump"):
        return event.model_dump()
    return event.dict()


def _determine_risk_from_patterns(patterns: list):
    names = {item.get("pattern") for item in patterns if isinstance(item, dict)}
    if "failed_success_command_chain" in names:
        return "high", 0.92
    if "multiple_failed_logins" in names:
        return "medium", 0.78
    return "low", 0.65


async def _get_project(request: Request, project_id: int):
    project_model = await ProjectModel.create_instance(db_client=request.app.db_client)
    return await project_model.get_project_or_create_one(project_id=project_id)


def _build_context_docs(docs: list):
    context_docs = []
    for idx, doc in enumerate(docs):
        context_docs.append({
            "doc_num": idx + 1,
            "score": round(float(doc.score), 4),
            "text": doc.text,
        })
    return context_docs


def _prompt_with_context(payload: dict, context_docs: list):
    return (
        "You are a SOC analyst. Return ONLY JSON.\n"
        "Use retrieved context as supporting context only.\n"
        f"INPUT:\n{json.dumps(payload, ensure_ascii=True)}\n"
        f"RETRIEVED_CONTEXT:\n{json.dumps(context_docs, ensure_ascii=True)}"
    )


def _llm_or_fallback(formatter: OutputFormatter, llm_text: str, fallback: dict):
    parsed = formatter.parse_json_or_none(llm_text)
    if isinstance(parsed, dict):
        return formatter.to_structured(parsed)
    return formatter.to_structured(fallback)


def _safe_generate(request: Request, prompt: str):
    try:
        chat_history = [
            request.app.generation_client.construct_prompt(
                prompt="You are a SOC analyst. Return ONLY JSON.",
                role=request.app.generation_client.enums.SYSTEM.value,
            )
        ]
        return request.app.generation_client.generate_text(prompt=prompt, chat_history=chat_history) or ""
    except Exception:
        return ""


@soc_router.post("/analyze/logs")
async def analyze_logs(request: Request, body: AnalyzeLogsRequest):
    parser = LogParser()
    correlation = CorrelationEngine()
    intel = ThreatIntelAnalyzer()
    formatter = OutputFormatter()

    events = parser.parse_text(body.logs)
    correlation_result = correlation.correlate(events)
    intel_result = intel.extract_iocs(body.logs)

    risk_level, confidence = _determine_risk_from_patterns(correlation_result.get("patterns", []))
    recommendations = [
        "Enforce MFA and account lockout policy.",
        "Block suspicious IPs and monitor authentication logs.",
        "Run endpoint triage for hosts with command execution activity.",
    ]

    project = await _get_project(request=request, project_id=body.project_id)
    nlp_controller = NLPController(
        vectordb_client=request.app.vectordb_client,
        generation_client=request.app.generation_client,
        embedding_client=request.app.embedding_client,
        template_parser=request.app.template_parser,
    )

    """
    [MODIFICATION SUMMARY]
    What: Replaced the hardcoded 'events[:8]' query with a smart query derived from extracted IOCs and threat patterns.
    Why: Searching RAG using the first 8 lines is dangerous if the attack occurs later in the log. Using extracted IPs, domains, and attack patterns ensures we retrieve highly relevant context from the Vector DB.
    """
    # <-- MODIFIED: Build a smart search query based on actual findings, not random log lines
    extracted_iocs = _flatten_iocs(intel_result)
    threat_patterns = [item.get("pattern", "") for item in correlation_result.get("patterns", []) if isinstance(item, dict)]
    smart_query_parts = extracted_iocs + threat_patterns
    query = " ".join(smart_query_parts) if smart_query_parts else "suspicious login activity"

    docs = await nlp_controller.retrieve_relevant_context(project=project, text=query, limit=body.top_k)
    context_docs = _build_context_docs(docs if isinstance(docs, list) else [])

    """
    [MODIFICATION SUMMARY]
    What: Truncated the raw events list injected into the LLM payload to a maximum of 15 samples.
    Why: Injecting thousands of log lines into the LLM prompt via json.dumps() will trigger a Context Length (Token) Limit Exception. The correlation engine already processed the full log; the LLM only needs a sample to write the summary.
    """
    # <-- MODIFIED: Truncate events to prevent Token Limit Crash
    payload = {
        "events_sample": [_event_to_dict(event) for event in events[:15]], # Send max 15 lines as a sample
        "total_events_processed": len(events), # Let the LLM know how big the original file was
        "correlation": correlation_result,
        "iocs": intel_result,
    }

    prompt = _prompt_with_context(payload=payload, context_docs=context_docs)
    llm_text = _safe_generate(request=request, prompt=prompt)

    fallback = {
        "summary": f"Log analysis completed. Processed {len(events)} events with event correlation and IOC extraction.",
        "attack_type": "credential_access" if risk_level in ["high", "medium"] else "suspicious_activity",
        "risk_level": risk_level,
        "ioc": _flatten_iocs(intel_result),
        "recommendations": recommendations,
        "confidence": confidence,
    }

    output = _llm_or_fallback(formatter=formatter, llm_text=llm_text, fallback=fallback)
    return JSONResponse(content=output)


@soc_router.post("/analyze/cve")
async def analyze_cve(request: Request, body: AnalyzeCVERequest):
    intel = ThreatIntelAnalyzer()
    formatter = OutputFormatter()

    cve_text = f"{body.cve_id} {body.cve_text or ''}".strip()
    cve_result = intel.parse_cve(cve_text)

    project = await _get_project(request=request, project_id=body.project_id)
    nlp_controller = NLPController(
        vectordb_client=request.app.vectordb_client,
        generation_client=request.app.generation_client,
        embedding_client=request.app.embedding_client,
        template_parser=request.app.template_parser,
    )

    docs = await nlp_controller.retrieve_relevant_context(project=project, text=cve_text, limit=body.top_k)
    context_docs = _build_context_docs(docs if isinstance(docs, list) else [])

    prompt = _prompt_with_context(payload=cve_result, context_docs=context_docs)
    llm_text = _safe_generate(request=request, prompt=prompt)

    fallback = {
        "summary": f"CVE analysis generated for {body.cve_id.upper()}.",
        "attack_type": cve_result.get("attack_type", "unknown"),
        "risk_level": cve_result.get("severity", {}).get("level", "info"),
        "ioc": _flatten_iocs(cve_result.get("iocs", {})),
        "recommendations": [
            "Patch affected systems based on vendor guidance.",
            "Deploy temporary mitigation and hardening controls.",
            "Monitor exploit attempts linked to this CVE.",
        ],
        "confidence": 0.86,
    }

    output = _llm_or_fallback(formatter=formatter, llm_text=llm_text, fallback=fallback)
    return JSONResponse(content=output)


@soc_router.post("/investigate")
async def investigate(request: Request, body: InvestigateRequest):
    parser = LogParser()
    correlation = CorrelationEngine()
    intel = ThreatIntelAnalyzer()
    formatter = OutputFormatter()

    raw_events = [event.strip() for event in (body.events or []) if isinstance(event, str) and event.strip()]
    if body.logs and len(body.logs.strip()):
        raw_events.extend([line for line in body.logs.splitlines() if line.strip()])

    joined = "\n".join(raw_events)
    events = parser.parse_text(joined)
    correlation_result = correlation.correlate(events)
    cve_result = intel.parse_cve(joined)

    project = await _get_project(request=request, project_id=body.project_id)
    nlp_controller = NLPController(
        vectordb_client=request.app.vectordb_client,
        generation_client=request.app.generation_client,
        embedding_client=request.app.embedding_client,
        template_parser=request.app.template_parser,
    )

    docs = await nlp_controller.retrieve_relevant_context(project=project, text=joined, limit=body.top_k)
    context_docs = _build_context_docs(docs if isinstance(docs, list) else [])

    # <-- MODIFIED: Truncate events to prevent Token Limit Crash in Investigation endpoint as well
    payload = {
        "events_sample": [_event_to_dict(event) for event in events[:15]], 
        "total_events_processed": len(events),
        "correlation": correlation_result,
        "threat_intel": cve_result,
    }

    prompt = _prompt_with_context(payload=payload, context_docs=context_docs)
    llm_text = _safe_generate(request=request, prompt=prompt)

    risk_level, confidence = _determine_risk_from_patterns(correlation_result.get("patterns", []))
    fallback = {
        "summary": f"Investigation chain completed across {len(events)} events with correlation and threat intelligence enrichment.",
        "attack_type": cve_result.get("attack_type", "suspicious_activity"),
        "risk_level": risk_level,
        "ioc": _flatten_iocs(cve_result.get("iocs", {})),
        "recommendations": [
            "Contain affected hosts and preserve forensic evidence.",
            "Hunt across SIEM for matching IOC and behavior chain.",
            "Escalate to incident response if suspicious chain persists.",
        ],
        "confidence": confidence,
    }

    output = _llm_or_fallback(formatter=formatter, llm_text=llm_text, fallback=fallback)
    return JSONResponse(content=output)
