from fastapi import FastAPI
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from routes import base, data, nlp, analysis, investigation, chat, reference, soc_copilot, ioc, admin, sigma, yara_scanner
from helpers.config import get_settings
from stores.llm.LLMProviderFactory import LLMProviderFactory
from stores.vectordb.VectorDBProviderFactory import VectorDBProviderFactory
from stores.llm.templates.template_parser import TemplateParser
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
from pathlib import Path
import logging

# Import metrics setup
from utils.metrics import setup_metrics

app = FastAPI()
logger = logging.getLogger("uvicorn.error")

# Setup Prometheus metrics
setup_metrics(app)


async def startup_span():
    settings = get_settings()
    app.settings = settings

    postgres_conn = f"postgresql+asyncpg://{settings.POSTGRES_USERNAME}:{settings.POSTGRES_PASSWORD}@{settings.POSTGRES_HOST}:{settings.POSTGRES_PORT}/{settings.POSTGRES_MAIN_DATABASE}"

    app.db_engine = create_async_engine(postgres_conn)
    app.db_client = sessionmaker(
        app.db_engine, class_=AsyncSession, expire_on_commit=False
    )

    try:
        async with app.db_engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info(
            "Database connection OK: %s:%s/%s",
            settings.POSTGRES_HOST,
            settings.POSTGRES_PORT,
            settings.POSTGRES_MAIN_DATABASE,
        )
    except Exception as exc:
        logger.error(
            "Database connection unavailable at startup: %s:%s/%s - %s",
            settings.POSTGRES_HOST,
            settings.POSTGRES_PORT,
            settings.POSTGRES_MAIN_DATABASE,
            exc,
        )

    llm_provider_factory = LLMProviderFactory(settings)
    vectordb_provider_factory = VectorDBProviderFactory(config=settings, db_client=app.db_client)

    # generation client
    app.generation_client = llm_provider_factory.create(provider=settings.GENERATION_BACKEND)
    app.generation_client.set_generation_model(model_id=settings.GENERATION_MODEL_ID)

    # embedding client
    app.embedding_client = llm_provider_factory.create(provider=settings.EMBEDDING_BACKEND)
    app.embedding_client.set_embedding_model(model_id=settings.EMBEDDING_MODEL_ID,
                                             embedding_size=settings.EMBEDDING_MODEL_SIZE)

    # vector db client
    app.vectordb_client = vectordb_provider_factory.create(
        provider=settings.VECTOR_DB_BACKEND
    )
    await app.vectordb_client.connect()

    app.template_parser = TemplateParser(
        language=settings.PRIMARY_LANG,
        default_language=settings.DEFAULT_LANG,
    )


async def shutdown_span():
    await app.db_engine.dispose()
    await app.vectordb_client.disconnect()


app.on_event("startup")(startup_span)
app.on_event("shutdown")(shutdown_span)


@app.get("/", include_in_schema=False)
async def root_redirect():
    return RedirectResponse(url="/web/")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon_placeholder():
    return Response(status_code=204)

app.include_router(base.base_router)
app.include_router(data.data_router)
app.include_router(nlp.nlp_router)
app.include_router(analysis.analysis_router)
app.include_router(investigation.investigation_router)
app.include_router(chat.chat_router)
app.include_router(reference.reference_router)
app.include_router(soc_copilot.soc_router)
app.include_router(ioc.ioc_router)
app.include_router(admin.admin_router)
app.include_router(sigma.sigma_router)
app.include_router(sigma.sigma_compat_router)
app.include_router(yara_scanner.yara_scanner_router)

web_dir = Path(__file__).resolve().parent.parent / "web"
if web_dir.exists():
    app.mount("/web", StaticFiles(directory=str(web_dir), html=True), name="web")
