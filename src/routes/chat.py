from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from routes.schemes.chat import ChatRequest
from models.ProjectModel import ProjectModel
from controllers import NLPController
from models import ResponseSignal


CHAT_CONTENT_TYPE_ALIASES = {
    "malware_reports": "malware_report",
    "malware report": "malware_report",
    "malware reports": "malware_report",
    "yara rules": "yara_rule",
    "yara_rule": "yara_rule",
    "sigma rules": "sigma_rule",
    "sigma_rule": "sigma_rule",
    "ioc lists": "ioc_list",
    "ioc_list": "ioc_list",
}


def _normalize_chat_content_type(content_type):
    if not isinstance(content_type, str):
        return None
    value = content_type.strip()
    if not value:
        return None
    key = value.lower().replace("-", "_")
    label_key = value.lower().replace("_", " ")
    return CHAT_CONTENT_TYPE_ALIASES.get(label_key, key)


def _chat_metadata_filter(body: ChatRequest):
    metadata_filter = {}
    content_type = _normalize_chat_content_type(body.content_type)
    source_name = (body.source_name or "").strip() if isinstance(body.source_name, str) else ""
    if content_type:
        metadata_filter["content_type"] = content_type
    if source_name:
        metadata_filter["source_name"] = source_name
    return metadata_filter or None


def _relax_auto_chat_filter(body: ChatRequest, metadata_filter: dict):
    if not metadata_filter or not body.auto_content_type:
        return metadata_filter

    relaxed_filter = dict(metadata_filter)
    relaxed_filter.pop("content_type", None)
    return relaxed_filter or None


chat_router = APIRouter(
    prefix="/api/v1/chat",
    tags=["api_v1", "chat"],
)


@chat_router.post("/{project_id}")
async def chat_with_project(request: Request, project_id: int, body: ChatRequest):

    project_model = await ProjectModel.create_instance(
        db_client=request.app.db_client
    )

    project = await project_model.get_project_or_create_one(
        project_id=project_id
    )

    nlp_controller = NLPController(
        vectordb_client=request.app.vectordb_client,
        generation_client=request.app.generation_client,
        embedding_client=request.app.embedding_client,
        template_parser=request.app.template_parser,
    )
    metadata_filter = _chat_metadata_filter(body)
    effective_metadata_filter = metadata_filter

    retrieved_docs = await nlp_controller.retrieve_relevant_context(
        project=project,
        text=body.question,
        limit=body.limit,
        metadata_filter=metadata_filter,
    )

    if not retrieved_docs:
        relaxed_filter = _relax_auto_chat_filter(body, metadata_filter)
        if relaxed_filter != metadata_filter:
            retrieved_docs = await nlp_controller.retrieve_relevant_context(
                project=project,
                text=body.question,
                limit=body.limit,
                metadata_filter=relaxed_filter,
            )
            effective_metadata_filter = relaxed_filter

    if not retrieved_docs:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": ResponseSignal.CHAT_FAILED.value,
                "detail": "No indexed context was found for this project or filter.",
                "filter_relaxed": effective_metadata_filter != metadata_filter,
            }
        )

    answer, full_prompt, chat_history = await nlp_controller.answer_rag_question(
        project=project,
        query=body.question,
        limit=body.limit,
        metadata_filter=effective_metadata_filter,
        retrieved_documents=retrieved_docs,
    )

    if not answer:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "signal": ResponseSignal.CHAT_FAILED.value
            }
        )

    sources_used = len(retrieved_docs) if isinstance(retrieved_docs, list) else 0

    return JSONResponse(
        content={
            "signal": ResponseSignal.CHAT_SUCCESS.value,
            "answer": answer,
            "sources_used": sources_used,
            "filter_relaxed": effective_metadata_filter != metadata_filter,
            "chat_history": chat_history,
        }
    )
