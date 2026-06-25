from .BaseController import BaseController
from models.db_schemes import Project, DataChunk
from stores.llm.LLMEnums import DocumentTypeEnum
from typing import List
import json
import re
import logging
import asyncio

class NLPController(BaseController):

    def __init__(self, vectordb_client, generation_client, 
                 embedding_client, template_parser):
        super().__init__()

        self.vectordb_client = vectordb_client
        self.generation_client = generation_client
        self.embedding_client = embedding_client
        self.template_parser = template_parser
        self.logger = logging.getLogger("uvicorn.error")
        self.max_retrieval_query_characters = 1000
        self.embedding_timeout_seconds = 20
        self.generation_timeout_seconds = 60

    async def _run_blocking_client_call(self, label: str, func, *args, timeout: int = 30, **kwargs):
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(func, *args, **kwargs),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            self.logger.error("%s timed out after %s seconds", label, timeout)
        except Exception as exc:
            self.logger.error("%s failed: %s", label, exc)
        return None

    def create_collection_name(self, project_id: str):
        return f"collection_{self.vectordb_client.default_vector_size}_{project_id}".strip()
    
    async def reset_vector_db_collection(self, project: Project):
        collection_name = self.create_collection_name(project_id=project.project_id)
        return await self.vectordb_client.delete_collection(collection_name=collection_name)
    
    async def get_vector_db_collection_info(self, project: Project):
        collection_name = self.create_collection_name(project_id=project.project_id)
        collection_info = await self.vectordb_client.get_collection_info(collection_name=collection_name)

        return json.loads(
            json.dumps(collection_info, default=lambda x: x.__dict__)
        )
    
    async def index_into_vector_db(self, project: Project, chunks: List[DataChunk],
                                   chunks_ids: List[int], 
                                   do_reset: bool = False):
        
        # step1: get collection name
        collection_name = self.create_collection_name(project_id=project.project_id)

        # step2: manage items
        texts = [ c.chunk_text for c in chunks ]
        metadata = [ c.chunk_metadata for c in  chunks]
        vectors = await self._run_blocking_client_call(
            "Document embedding request",
            self.embedding_client.embed_text,
            text=texts,
            document_type=DocumentTypeEnum.DOCUMENT.value,
            timeout=self.embedding_timeout_seconds,
        )

        if not isinstance(vectors, list) or len(vectors) != len(texts):
            self.logger.warning(
                "Batch document embedding failed for %s chunk(s); retrying one by one",
                len(texts),
            )
            vectors = []

            for text in texts:
                item_vectors = await self._run_blocking_client_call(
                    "Document embedding retry",
                    self.embedding_client.embed_text,
                    text=text,
                    document_type=DocumentTypeEnum.DOCUMENT.value,
                    timeout=self.embedding_timeout_seconds,
                )
                if not isinstance(item_vectors, list) or len(item_vectors) == 0:
                    self.logger.error("Failed to embed a chunk during vector indexing retry")
                    return False
                vectors.append(item_vectors[0])

        # step3: create collection if not exists
        _ = await self.vectordb_client.create_collection(
            collection_name=collection_name,
            embedding_size=self.embedding_client.embedding_size,
            do_reset=do_reset,
        )

        # step4: insert into vector db
        _ = await self.vectordb_client.insert_many(
            collection_name=collection_name,
            texts=texts,
            metadata=metadata,
            vectors=vectors,
            record_ids=chunks_ids,
        )

        return True

    def _matches_metadata_filter(self, metadata: dict, metadata_filter: dict = None):
        if not metadata_filter:
            return True
        if not isinstance(metadata, dict):
            metadata = {}

        content_type = (metadata_filter.get("content_type") or "").strip()
        if content_type and metadata.get("content_type") != content_type:
            return False

        source_name = (metadata_filter.get("source_name") or "").strip().lower()
        if source_name:
            candidate = str(metadata.get("source_name") or "").strip().lower()
            if source_name not in candidate:
                return False

        return True

    async def search_vector_db_collection(self, project: Project, text: str, limit: int = 10, metadata_filter: dict = None):

        # step1: get collection name
        query_vector = None
        collection_name = self.create_collection_name(project_id=project.project_id)
        query_text = self._prepare_retrieval_query(text)

        try:
            collection_exists = await self.vectordb_client.is_collection_existed(collection_name=collection_name)
        except Exception as exc:
            self.logger.error("Failed to check vector collection %s: %s", collection_name, exc)
            return False

        if not collection_exists:
            self.logger.error("Can not search for records in a non-existed collection: %s", collection_name)
            return False

        if not query_text:
            return False

        # step2: get text embedding vector
        vectors = await self._run_blocking_client_call(
            "Query embedding request",
            self.embedding_client.embed_text,
            text=query_text,
            document_type=DocumentTypeEnum.QUERY.value,
            timeout=self.embedding_timeout_seconds,
        )

        if not vectors or len(vectors) == 0:
            return False
        
        if isinstance(vectors, list) and len(vectors) > 0:
            query_vector = vectors[0]

        if not query_vector:
            return False    

        # step3: do semantic search
        search_limit = max(limit * 20, 50) if metadata_filter else limit
        results = await self.vectordb_client.search_by_vector(
            collection_name=collection_name,
            vector=query_vector,
            limit=search_limit
        )

        if not results:
            return False

        if metadata_filter:
            results = [
                doc for doc in results
                if self._matches_metadata_filter(getattr(doc, "metadata", None), metadata_filter)
            ][:limit]

            if not results:
                return False

        return results

    def _tokenize(self, text: str):
        if not isinstance(text, str):
            return set()
        return set(re.findall(r"[a-zA-Z0-9_.:-]+", text.lower()))

    def _prepare_retrieval_query(self, text: str):
        text = (text or "").strip()

        if len(text) <= self.max_retrieval_query_characters:
            return text

        self.logger.info(
            "Truncated retrieval query from %s to %s characters",
            len(text),
            self.max_retrieval_query_characters,
        )
        return text[:self.max_retrieval_query_characters].strip()

    """
    [MODIFICATION SUMMARY]
    What: Normalized the 'lexical_overlap' value before calculating the hybrid score.
    Why: Previously, lexical_overlap was an absolute integer (e.g., 5, 10, 20 matching tokens), while rec.score is typically a normalized float (0.0 to 1.0). Adding an unnormalized integer multiplied by 0.15 completely overpowered the semantic vector score, effectively turning the RAG into a simple keyword matcher. Normalizing the overlap guarantees the 85/15 weighting behaves correctly.
    """
    def _rerank_results(self, query: str, results: List, limit: int):
        query_tokens = self._tokenize(query)
        # <-- MODIFIED: Calculate max possible overlap to avoid ZeroDivisionError
        max_possible_overlap = len(query_tokens) if len(query_tokens) > 0 else 1 
        reranked = []

        for rec in results:
            doc_tokens = self._tokenize(rec.text)
            lexical_overlap = len(query_tokens.intersection(doc_tokens))
            
            # <-- MODIFIED: Normalize lexical overlap to be a value between 0.0 and 1.0
            normalized_overlap = lexical_overlap / max_possible_overlap 
            
            # <-- MODIFIED: Apply the weights to normalized values
            hybrid_score = (float(rec.score) * 0.85) + (normalized_overlap * 0.15) 
            reranked.append((hybrid_score, rec))

        reranked.sort(key=lambda x: x[0], reverse=True)
        return [item[1] for item in reranked[:limit]]

    """
    [MODIFICATION SUMMARY]
    What: Added a 'json_mode' parameter to enforce strict JSON fallback structures for SOC Copilot endpoints.
    Why: The project architecture requires the SOC endpoints to return ONLY JSON. If the LLM failed, the previous fallback returned plain text, which would cause parsing crashes on the frontend. This ensures a deterministic, safe JSON structure is returned if json_mode is active.
    """
    # <-- MODIFIED: Added json_mode parameter to support the OutputFormatter schema
    def _build_fallback_answer(self, query: str, retrieved_documents: List, json_mode: bool = False): 
        snippets = [
            doc.text.strip()
            for doc in retrieved_documents
            if getattr(doc, "text", None) and len(doc.text.strip())
        ]

        if len(snippets) == 0:
            # <-- MODIFIED: Return empty JSON structure if in json_mode
            return json.dumps({"summary": "No context found.", "attack_type": "unknown", "risk_level": "info", "ioc": [], "recommendations": [], "confidence": 0.0}) if json_mode else None 

        query_low = (query or "").lower()
        extracted_iocs = []
        
        # <-- MODIFIED: Safely extract potential IoCs for the fallback
        if any(term in query_low for term in ["ioc", "indicator", "ip", "domain", "hash"]):
            extracted_iocs = [snippet[:50] for snippet in snippets[:5]] # Rough extraction for fallback

        if json_mode:
            # <-- MODIFIED: Construct the deterministic JSON fallback defined in the project architecture
            fallback_dict = {
                "summary": "LLM generation failed. Showing raw extracted evidence.",
                "attack_type": "unknown",
                "risk_level": "info",
                "ioc": extracted_iocs,
                "recommendations": ["Review raw logs manually."],
                "confidence": 0.0
            }
            return json.dumps(fallback_dict)

        # Original text fallback logic for non-SOC endpoints
        if extracted_iocs:
            return "Based on retrieved context, relevant indicators and evidence are:\n- " + "\n- ".join(extracted_iocs)

        return "Based on retrieved context:\n" + "\n\n".join(snippets[:3])

    async def retrieve_relevant_context(self, project: Project, text: str, limit: int = 5, metadata_filter: dict = None):
        # RAG sources are context only; retrieval stays isolated from final reasoning output.
        base_results = await self.search_vector_db_collection(
            project=project,
            text=text,
            limit=max(limit * 3, limit),
            metadata_filter=metadata_filter,
        )
        if not isinstance(base_results, list):
            return []
        return self._rerank_results(query=text, results=base_results, limit=limit)
    
    # <-- MODIFIED: Plumbed json_mode through the main answer method
    async def answer_rag_question(self, project: Project, query: str, limit: int = 10,
                                  json_mode: bool = False, metadata_filter: dict = None,
                                  retrieved_documents: list = None):
        
        answer, full_prompt, chat_history = None, None, None

        if retrieved_documents is None:
            retrieved_documents = await self.retrieve_relevant_context(
                project=project,
                text=query,
                limit=limit,
                metadata_filter=metadata_filter,
            )

        if not retrieved_documents or len(retrieved_documents) == 0:
            return answer, full_prompt, chat_history
        
        system_prompt = self.template_parser.get("rag", "system_prompt")

        documents_prompts = "\n".join([
            self.template_parser.get("rag", "document_prompt", {
                    "doc_num": idx + 1,
                    "chunk_text": self.generation_client.process_text(doc.text),
            })
            for idx, doc in enumerate(retrieved_documents)
        ])

        footer_prompt = self.template_parser.get("rag", "footer_prompt", {
            "query": query
        })

        chat_history = [
            self.generation_client.construct_prompt(
                prompt=system_prompt,
                role=self.generation_client.enums.SYSTEM.value,
            )
        ]

        full_prompt = "\n\n".join([ documents_prompts,  footer_prompt])

        answer = await self._run_blocking_client_call(
            "RAG generation request",
            self.generation_client.generate_text,
            prompt=full_prompt,
            chat_history=chat_history,
            timeout=self.generation_timeout_seconds,
        )

        if not answer:
            # <-- MODIFIED: Pass json_mode to the fallback builder
            answer = self._build_fallback_answer(query=query, retrieved_documents=retrieved_documents, json_mode=json_mode) 

        return answer, full_prompt, chat_history
