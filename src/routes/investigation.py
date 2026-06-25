from fastapi import APIRouter, Request, status, UploadFile, Query, Depends
from fastapi.responses import JSONResponse
from helpers.config import get_settings, Settings
from routes.schemes.investigation import InvestigationRequest
from controllers import InvestigationController, DataController, ProcessController
from models import ResponseSignal
from models.ThreatAnalysisModel import ThreatAnalysisModel
from models.db_schemes import ThreatAnalysis
import aiofiles
import uuid
import logging


investigation_router = APIRouter(
    prefix="/api/v1/investigation",
    tags=["api_v1", "investigation_chain"],
)

logger = logging.getLogger("uvicorn.error")


@investigation_router.post("/analyze")
async def analyze_investigation(request: Request, body: InvestigationRequest):

    events = [event.strip() for event in body.events if isinstance(event, str) and len(event.strip())]

    if len(events) < 2:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": ResponseSignal.INVESTIGATION_NO_EVENTS.value
            }
        )

    controller = InvestigationController(generation_client=request.app.generation_client)
    result = await controller.investigate(events=events)

    # Save to DB as threat analysis
    inv_uuid = str(uuid.uuid4())
    try:
        threat_model = await ThreatAnalysisModel.create_instance(db_client=request.app.db_client)
        db_record = ThreatAnalysis(
            analysis_uuid=uuid.UUID(inv_uuid),
            input_text="\n---\n".join(events)[:3000],
            input_type="investigation",
            title=result.get("investigation_title", "Investigation"),
            threat_type=result.get("overall_severity", {}).get("level", "unknown"),
            risk_level=result.get("overall_severity", {}).get("level", "info"),
            risk_score=float(result.get("overall_severity", {}).get("score", 0.0)),
            confidence=float(result.get("overall_severity", {}).get("confidence", 0.0)),
            analysis_result=result,
            iocs=result.get("iocs", {}),
        )
        saved = await threat_model.create_analysis(db_record)
        inv_uuid = str(saved.analysis_uuid)
    except Exception:
        pass

    return JSONResponse(
        content={
            "signal": ResponseSignal.INVESTIGATION_SUCCESS.value,
            "investigation_uuid": inv_uuid,
            "investigation": result
        }
    )


@investigation_router.post("/file")
async def analyze_investigation_file(request: Request,
                                     file: UploadFile,
                                     separator: str = Query("---"),
                                     app_settings: Settings = Depends(get_settings)):

    data_controller = DataController()
    is_valid, result_signal = data_controller.validate_uploaded_file(file=file)

    if not is_valid:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": result_signal
            }
        )

    file_path, file_id = data_controller.generate_unique_filepath(
        orig_file_name=file.filename,
        project_id=0,
    )

    try:
        async with aiofiles.open(file_path, "wb") as f:
            while chunk := await file.read(app_settings.FILE_DEFAULT_CHUNK_SIZE):
                await f.write(chunk)
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": ResponseSignal.INVESTIGATION_FAILED.value
            }
        )

    process_controller = ProcessController(project_id=0)
    file_content = process_controller.get_file_content(file_id=file_id)

    if not file_content or len(file_content) == 0:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": ResponseSignal.INVESTIGATION_FAILED.value
            }
        )

    full_text = "\n".join([doc.page_content for doc in file_content if doc.page_content])
    full_text = full_text[:app_settings.INPUT_DAFAULT_MAX_CHARACTERS].strip()
    separator = separator if isinstance(separator, str) and len(separator) else "---"

    events = [event.strip() for event in full_text.split(separator) if len(event.strip())]
    if len(events) < 2:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": ResponseSignal.INVESTIGATION_NO_EVENTS.value
            }
        )

    controller = InvestigationController(generation_client=request.app.generation_client)
    try:
        result = await controller.investigate(events=events)
    except Exception as exc:
        logger.error(f"Investigation file analysis failed for {file_id}: {exc}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": ResponseSignal.INVESTIGATION_FAILED.value
            }
        )

    return JSONResponse(
        content={
            "signal": ResponseSignal.INVESTIGATION_SUCCESS.value,
            "investigation": result,
            "events_count": len(events)
        }
    )
