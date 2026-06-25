from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from routes.schemes.sigma import (
    SigmaBulkConvertRequest,
    SigmaConvertRequest,
    SigmaValidateRequest,
)
from controllers import SigmaController
from models import ResponseSignal
import logging


sigma_router = APIRouter(
    prefix="/api/v1/sigma",
    tags=["api_v1", "sigma_converter"],
)

sigma_compat_router = APIRouter(
    prefix="/sigma",
    tags=["sigma_converter"],
)

logger = logging.getLogger("uvicorn.error")


def _result_response(result: dict, success_signal: str, failed_signal: str):
    if result.get("valid") is False:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": failed_signal,
                **result,
            },
        )

    return JSONResponse(
        content={
            "signal": success_signal,
            **result,
        }
    )


async def _convert(body: SigmaConvertRequest):
    controller = SigmaController()
    try:
        result = controller.convert(
            sigma_rule=body.sigma_rule,
            platforms=body.platforms,
            filename=body.filename,
        )
    except Exception as exc:
        logger.error(f"Sigma conversion failed: {exc}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": ResponseSignal.SIGMA_CONVERSION_FAILED.value,
                "errors": [{
                    "field": "sigma_rule",
                    "code": "conversion_failed",
                    "message": str(exc),
                }],
            }
        )

    return _result_response(
        result=result,
        success_signal=ResponseSignal.SIGMA_CONVERSION_SUCCESS.value,
        failed_signal=ResponseSignal.SIGMA_CONVERSION_FAILED.value,
    )


async def _validate(body: SigmaValidateRequest):
    controller = SigmaController()
    try:
        result = controller.validate(
            sigma_rule=body.sigma_rule,
            filename=body.filename,
        )
    except Exception as exc:
        logger.error(f"Sigma validation failed: {exc}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": ResponseSignal.SIGMA_VALIDATION_FAILED.value,
                "errors": [{
                    "field": "sigma_rule",
                    "code": "validation_failed",
                    "message": str(exc),
                }],
            }
        )

    return _result_response(
        result=result,
        success_signal=ResponseSignal.SIGMA_VALIDATION_SUCCESS.value,
        failed_signal=ResponseSignal.SIGMA_VALIDATION_FAILED.value,
    )


async def _bulk_convert(body: SigmaBulkConvertRequest):
    controller = SigmaController()
    try:
        rules = [
            item.model_dump() if hasattr(item, "model_dump") else item.dict()
            for item in body.rules
        ]
        result = controller.bulk_convert(
            rules=rules,
            platforms=body.platforms,
        )
    except Exception as exc:
        logger.error(f"Sigma bulk conversion failed: {exc}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": ResponseSignal.SIGMA_CONVERSION_FAILED.value,
                "errors": [{
                    "field": "rules",
                    "code": "bulk_conversion_failed",
                    "message": str(exc),
                }],
            }
        )

    return JSONResponse(
        content={
            "signal": ResponseSignal.SIGMA_CONVERSION_SUCCESS.value,
            **result,
        }
    )


@sigma_router.post("/convert")
async def convert_sigma(body: SigmaConvertRequest):
    return await _convert(body=body)


@sigma_router.post("/validate")
async def validate_sigma(body: SigmaValidateRequest):
    return await _validate(body=body)


@sigma_router.post("/bulk-convert")
async def bulk_convert_sigma(body: SigmaBulkConvertRequest):
    return await _bulk_convert(body=body)


@sigma_compat_router.post("/convert")
async def convert_sigma_compat(body: SigmaConvertRequest):
    return await _convert(body=body)


@sigma_compat_router.post("/validate")
async def validate_sigma_compat(body: SigmaValidateRequest):
    return await _validate(body=body)


@sigma_compat_router.post("/bulk-convert")
async def bulk_convert_sigma_compat(body: SigmaBulkConvertRequest):
    return await _bulk_convert(body=body)

