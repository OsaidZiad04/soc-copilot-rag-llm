from enum import Enum


class ResponseSignal(Enum):

    FILE_VALIDATED_SUCCESS = "file_validate_successfully"
    FILE_TYPE_NOT_SUPPORTED = "file_type_not_supported"
    FILE_SIZE_EXCEEDED = "file_size_exceeded"
    FILE_UPLOAD_SUCCESS = "file_upload_success"
    FILE_UPLOAD_FAILED = "file_upload_failed"
    PROCESSING_SUCCESS = "processing_success"
    PROCESSING_FAILED = "processing_failed"
    NO_FILES_ERROR = "not_found_files"
    FILE_ID_ERROR = "no_file_found_with_this_id"
    PROJECT_NOT_FOUND_ERROR = "project_not_found"
    INSERT_INTO_VECTORDB_ERROR = "insert_into_vectordb_error"
    INSERT_INTO_VECTORDB_SUCCESS = "insert_into_vectordb_success"
    VECTORDB_COLLECTION_RETRIEVED = "vectordb_collection_retrieved"
    VECTORDB_SEARCH_ERROR = "vectordb_search_error"
    VECTORDB_SEARCH_SUCCESS = "vectordb_search_success"
    RAG_ANSWER_ERROR = "rag_answer_error"
    RAG_ANSWER_SUCCESS = "rag_answer_success"

    ANALYSIS_SUCCESS = "analysis_success"
    ANALYSIS_FAILED = "analysis_failed"
    ANALYSIS_NOT_FOUND = "analysis_not_found"
    ANALYSIS_LIST_SUCCESS = "analysis_list_success"

    INVESTIGATION_SUCCESS = "investigation_success"
    INVESTIGATION_FAILED = "investigation_failed"
    INVESTIGATION_NO_EVENTS = "investigation_no_events"

    CHAT_SUCCESS = "chat_success"
    CHAT_FAILED = "chat_failed"
    REFERENCE_SUCCESS = "reference_success"

    SIGMA_CONVERSION_SUCCESS = "sigma_conversion_success"
    SIGMA_CONVERSION_FAILED = "sigma_conversion_failed"
    SIGMA_VALIDATION_SUCCESS = "sigma_validation_success"
    SIGMA_VALIDATION_FAILED = "sigma_validation_failed"
