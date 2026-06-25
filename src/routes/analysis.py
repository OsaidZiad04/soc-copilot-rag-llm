from fastapi import APIRouter, status, Request, UploadFile, Depends, Query
from fastapi.responses import JSONResponse
from helpers.config import get_settings, Settings
from routes.schemes.analysis import (
    AlertAnalysisRequest,
    CVEAnalysisRequest,
    FeedbackRequest,
    StoredFileAnalysisRequest,
)
from models import ResponseSignal
from models.ProjectModel import ProjectModel
from models.ThreatAnalysisModel import ThreatAnalysisModel
from models.AssetModel import AssetModel
from models.db_schemes import Asset
from models.enums.AssetTypeEnum import AssetTypeEnum
from controllers import SOCAnalysisController, DataController, ProcessController
import aiofiles
import os
import json
import logging


analysis_router = APIRouter(
    prefix="/api/v1/analysis",
    tags=["api_v1", "soc_analysis"],
)

logger = logging.getLogger("uvicorn.error")


def _limit_analysis_text(text: str, max_chars: int) -> str:
    text = text or ""
    if len(text) <= max_chars:
        return text
    return text[:max_chars].strip()


async def _analyze_project_file(request: Request,
                                project_id: int,
                                stored_file_id: str,
                                input_type: str,
                                max_chars: int):
    try:
        return await _analyze_project_file_impl(
            request=request,
            project_id=project_id,
            stored_file_id=stored_file_id,
            input_type=input_type,
            max_chars=max_chars,
        )
    except Exception as exc:
        logger.exception("Stored file analysis failed for %s in project %s", stored_file_id, project_id)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "signal": "file_analysis_internal_error",
                "endpoint": f"/api/v1/analysis/asset/{project_id}",
                "file_id": stored_file_id,
                "detail": str(exc),
            },
        )


async def _analyze_project_file_impl(request: Request,
                                     project_id: int,
                                     stored_file_id: str,
                                     input_type: str,
                                     max_chars: int):

    project_model = await ProjectModel.create_instance(db_client=request.app.db_client)
    project = await project_model.get_project_or_create_one(project_id=project_id)

    asset_model = await AssetModel.create_instance(db_client=request.app.db_client)
    asset_record = await asset_model.get_asset_record(
        asset_project_id=project.project_id,
        asset_name=stored_file_id,
    )

    if asset_record is None:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": ResponseSignal.FILE_ID_ERROR.value
            }
        )

    process_controller = ProcessController(project_id=project_id)
    file_content = process_controller.get_file_content(file_id=stored_file_id)

    if file_content is None or len(file_content) == 0:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": ResponseSignal.ANALYSIS_FAILED.value
            }
        )

    raw_text = "\n".join([doc.page_content for doc in file_content if doc.page_content])
    input_text = _limit_analysis_text(
        text=raw_text,
        max_chars=max_chars,
    )

    soc_controller = SOCAnalysisController(
        vectordb_client=request.app.vectordb_client,
        generation_client=request.app.generation_client,
        embedding_client=request.app.embedding_client,
        template_parser=request.app.template_parser,
    )

    try:
        result = await soc_controller.analyze(
            project=project,
            input_text=input_text,
            input_type=input_type or "malware_report",
        )
    except Exception as exc:
        logger.error(f"File analysis failed for {stored_file_id}: {exc}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": ResponseSignal.ANALYSIS_FAILED.value
            }
        )

    threat_model = await ThreatAnalysisModel.create_instance(db_client=request.app.db_client)
    db_record = soc_controller.build_db_record(
        result=result,
        input_text=input_text,
        input_type=input_type or "malware_report",
    )

    created = await threat_model.create_analysis(db_record)

    return JSONResponse(
        content={
            "signal": ResponseSignal.ANALYSIS_SUCCESS.value,
            "analysis": serialize_db_record(created),
            "file_id": stored_file_id,
            "file_size": asset_record.asset_size,
            "analysis_uuid": str(created.analysis_uuid),
        }
    )


def serialize_db_record(record):
    if record is None:
        return None

    return json.loads(json.dumps({
        "analysis_id": record.analysis_id,
        "analysis_uuid": record.analysis_uuid,
        "input_text": record.input_text,
        "input_type": record.input_type,
        "title": record.title,
        "threat_type": record.threat_type,
        "risk_level": record.risk_level,
        "risk_score": record.risk_score,
        "confidence": record.confidence,
        "analysis_result": record.analysis_result,
        "mitre_techniques": record.mitre_techniques,
        "iocs": record.iocs,
        "detection_rules": record.detection_rules,
        "investigation_id": record.investigation_id,
        "analyst_feedback": record.analyst_feedback,
        "analyst_notes": record.analyst_notes,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    }, default=str))


@analysis_router.post("/alert/{project_id}")
async def analyze_alert(request: Request, project_id: int, body: AlertAnalysisRequest):

    project_model = await ProjectModel.create_instance(db_client=request.app.db_client)
    project = await project_model.get_project_or_create_one(project_id=project_id)

    soc_controller = SOCAnalysisController(
        vectordb_client=request.app.vectordb_client,
        generation_client=request.app.generation_client,
        embedding_client=request.app.embedding_client,
        template_parser=request.app.template_parser,
    )

    result = await soc_controller.analyze(
        project=project,
        input_text=body.alert_text,
        input_type=body.input_type,
    )

    threat_model = await ThreatAnalysisModel.create_instance(db_client=request.app.db_client)
    db_record = soc_controller.build_db_record(
        result=result,
        input_text=body.alert_text,
        input_type=body.input_type,
    )

    created = await threat_model.create_analysis(db_record)

    return JSONResponse(
        content={
            "signal": ResponseSignal.ANALYSIS_SUCCESS.value,
            "analysis": serialize_db_record(created),
            "analysis_uuid": str(created.analysis_uuid),
        }
    )


@analysis_router.post("/file/{project_id}")
async def analyze_file(request: Request, project_id: int, file: UploadFile,
                       app_settings: Settings = Depends(get_settings)):

    project_model = await ProjectModel.create_instance(db_client=request.app.db_client)
    project = await project_model.get_project_or_create_one(project_id=project_id)

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
        project_id=project_id
    )

    try:
        async with aiofiles.open(file_path, "wb") as f:
            while chunk := await file.read(app_settings.FILE_DEFAULT_CHUNK_SIZE):
                await f.write(chunk)
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": ResponseSignal.ANALYSIS_FAILED.value
            }
        )

    asset_model = await AssetModel.create_instance(db_client=request.app.db_client)
    existing_asset = await asset_model.get_asset_record(
        asset_project_id=project.project_id,
        asset_name=file_id,
    )

    if existing_asset is None:
        asset_resource = Asset(
            asset_project_id=project.project_id,
            asset_type=AssetTypeEnum.FILE.value,
            asset_name=file_id,
            asset_size=os.path.getsize(file_path)
        )
        _ = await asset_model.create_asset(asset=asset_resource)

    return await _analyze_project_file(
        request=request,
        project_id=project_id,
        stored_file_id=file_id,
        input_type="malware_report",
        max_chars=app_settings.INPUT_DAFAULT_MAX_CHARACTERS,
    )


@analysis_router.post("/asset/{project_id}")
async def analyze_uploaded_asset(request: Request,
                                 project_id: int,
                                 body: StoredFileAnalysisRequest,
                                 app_settings: Settings = Depends(get_settings)):

    return await _analyze_project_file(
        request=request,
        project_id=project_id,
        stored_file_id=body.file_id,
        input_type=body.input_type or "malware_report",
        max_chars=app_settings.INPUT_DAFAULT_MAX_CHARACTERS,
    )


@analysis_router.post("/cve/{project_id}")
async def analyze_cve(request: Request, project_id: int, body: CVEAnalysisRequest):

    project_model = await ProjectModel.create_instance(db_client=request.app.db_client)
    project = await project_model.get_project_or_create_one(project_id=project_id)

    input_text = f"CVE: {body.cve_id}"

    soc_controller = SOCAnalysisController(
        vectordb_client=request.app.vectordb_client,
        generation_client=request.app.generation_client,
        embedding_client=request.app.embedding_client,
        template_parser=request.app.template_parser,
    )

    result = await soc_controller.analyze(
        project=project,
        input_text=input_text,
        input_type="cve",
    )

    threat_model = await ThreatAnalysisModel.create_instance(db_client=request.app.db_client)
    db_record = soc_controller.build_db_record(
        result=result,
        input_text=input_text,
        input_type="cve",
    )

    created = await threat_model.create_analysis(db_record)

    return JSONResponse(
        content={
            "signal": ResponseSignal.ANALYSIS_SUCCESS.value,
            "analysis": serialize_db_record(created),
            "analysis_uuid": str(created.analysis_uuid),
        }
    )


@analysis_router.get("/history")
async def analysis_history(request: Request,
                           page: int = Query(1, ge=1),
                           page_size: int = Query(10, ge=1, le=100),
                           risk_level: str = None,
                           input_type: str = None):

    threat_model = await ThreatAnalysisModel.create_instance(db_client=request.app.db_client)
    records, total_pages, total = await threat_model.get_all_analyses(
        page=page,
        page_size=page_size,
        risk_level=risk_level,
        input_type=input_type,
    )

    return JSONResponse(
        content={
            "signal": ResponseSignal.ANALYSIS_LIST_SUCCESS.value,
            "items": [serialize_db_record(record) for record in records],
            "pagination": {
                "page": page,
                "page_size": page_size,
                "total_pages": total_pages,
                "total": total
            }
        }
    )


@analysis_router.get("/history/{analysis_uuid}")
async def analysis_details(request: Request, analysis_uuid: str):

    threat_model = await ThreatAnalysisModel.create_instance(db_client=request.app.db_client)
    record = await threat_model.get_analysis_by_uuid(analysis_uuid=analysis_uuid)

    if record is None:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "signal": ResponseSignal.ANALYSIS_NOT_FOUND.value
            }
        )

    return JSONResponse(
        content={
            "signal": ResponseSignal.ANALYSIS_SUCCESS.value,
            "analysis": serialize_db_record(record)
        }
    )


@analysis_router.patch("/history/{analysis_uuid}/feedback")
async def analysis_feedback(request: Request, analysis_uuid: str, body: FeedbackRequest):

    threat_model = await ThreatAnalysisModel.create_instance(db_client=request.app.db_client)
    record = await threat_model.update_analyst_feedback(
        analysis_uuid=analysis_uuid,
        feedback=body.feedback,
        notes=body.notes,
    )

    if record is None:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "signal": ResponseSignal.ANALYSIS_NOT_FOUND.value
            }
        )

    return JSONResponse(
        content={
            "signal": ResponseSignal.ANALYSIS_SUCCESS.value,
            "analysis": serialize_db_record(record)
        }
    )


@analysis_router.get("/stats")
async def analysis_stats(request: Request):

    threat_model = await ThreatAnalysisModel.create_instance(db_client=request.app.db_client)
    stats = await threat_model.get_stats()

    return JSONResponse(
        content={
            "signal": ResponseSignal.ANALYSIS_LIST_SUCCESS.value,
            "stats": stats
        }
    )
