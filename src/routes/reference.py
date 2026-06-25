from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from models import ResponseSignal
import json
from pathlib import Path


reference_router = APIRouter(
    prefix="/api/v1/reference",
    tags=["api_v1", "reference"],
)


def load_event_ids():
    file_path = Path(__file__).resolve().parent.parent / "assets" / "event_ids.json"
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


@reference_router.get("/event-ids")
async def get_event_ids(platform: str = Query(None), relevance: str = Query(None), search: str = Query(None)):
    data = load_event_ids()

    platforms = ["windows", "sysmon"]
    if platform and platform in platforms:
        payload = {platform: data.get(platform, {})}
    else:
        payload = {k: data.get(k, {}) for k in platforms}

    if relevance:
        for key in list(payload.keys()):
            payload[key] = {
                event_id: details
                for event_id, details in payload[key].items()
                if str(details.get("relevance", "")).lower() == relevance.lower()
            }

    if search:
        s = search.lower().strip()
        for key in list(payload.keys()):
            payload[key] = {
                event_id: details
                for event_id, details in payload[key].items()
                if s in json.dumps(details).lower() or s in str(event_id).lower()
            }

    return JSONResponse(
        content={
            "signal": ResponseSignal.REFERENCE_SUCCESS.value,
            "event_ids": payload
        }
    )


@reference_router.get("/event-ids/{event_id}")
async def get_event_id_details(event_id: str):
    data = load_event_ids()

    for platform in ["windows", "sysmon"]:
        platform_data = data.get(platform, {})
        if event_id in platform_data:
            return JSONResponse(
                content={
                    "signal": ResponseSignal.REFERENCE_SUCCESS.value,
                    "platform": platform,
                    "event_id": event_id,
                    "details": platform_data[event_id],
                }
            )

    return JSONResponse(
        content={
            "signal": ResponseSignal.REFERENCE_SUCCESS.value,
            "platform": None,
            "event_id": event_id,
            "details": None,
        }
    )


@reference_router.get("/log-types")
async def get_log_types():
    data = load_event_ids()

    return JSONResponse(
        content={
            "signal": ResponseSignal.REFERENCE_SUCCESS.value,
            "log_types": data.get("log_types", {}),
        }
    )
