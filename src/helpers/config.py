from pydantic_settings import BaseSettings
from typing import List, Optional


class Settings(BaseSettings):

    APP_NAME: str
    APP_VERSION: str

    FILE_ALLOWED_TYPES: list
    FILE_MAX_SIZE: int
    FILE_DEFAULT_CHUNK_SIZE: int

    POSTGRES_USERNAME: str
    POSTGRES_PASSWORD: str
    POSTGRES_HOST: str
    POSTGRES_PORT: int
    POSTGRES_MAIN_DATABASE: str

    GENERATION_BACKEND: str
    EMBEDDING_BACKEND: str

    OPENAI_API_KEY: Optional[str] = None
    OPENAI_API_URL: Optional[str] = None
    COHERE_API_KEY: Optional[str] = None
    OLLAMA_API_URL: Optional[str] = None

    GENERATION_MODEL_ID_LITERAL: Optional[List[str]] = None
    GENERATION_MODEL_ID: Optional[str] = None
    EMBEDDING_MODEL_ID: Optional[str] = None
    EMBEDDING_MODEL_SIZE: Optional[int] = None
    INPUT_DAFAULT_MAX_CHARACTERS: Optional[int] = None
    GENERATION_DAFAULT_MAX_TOKENS: Optional[int] = None
    GENERATION_DAFAULT_TEMPERATURE: Optional[float] = None

    VECTOR_DB_BACKEND_LITERAL: Optional[List[str]] = None
    VECTOR_DB_BACKEND: str
    VECTOR_DB_PATH: str
    VECTOR_DB_DISTANCE_METHOD: Optional[str] = None
    VECTOR_DB_PGVEC_INDEX_THRESHOLD: Optional[int] = 100

    RAG_TOP_K: int = 5
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None

    PRIMARY_LANG: str = "en"
    DEFAULT_LANG: str = "en"

    class Config:
        env_file = ".env"


def get_settings():
    return Settings()
