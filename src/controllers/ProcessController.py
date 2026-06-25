from .BaseController import BaseController
from .ProjectController import ProjectController
import os
from langchain_community.document_loaders import TextLoader
from langchain_community.document_loaders import PyMuPDFLoader
from models import ProcessingEnum
from typing import List
from dataclasses import dataclass
import logging

@dataclass
class Document:
    page_content: str
    metadata: dict

class ProcessController(BaseController):

    def __init__(self, project_id: str):
        super().__init__()

        self.project_id = project_id
        self.project_path = ProjectController().get_project_path(project_id=project_id)
        self.logger = logging.getLogger("uvicorn.error")

    def get_file_extension(self, file_id: str):
        return os.path.splitext(file_id)[-1]

    def get_file_loader(self, file_id: str):

        file_ext = self.get_file_extension(file_id=file_id)
        file_path = os.path.join(
            self.project_path,
            file_id
        )

        if not os.path.exists(file_path):
            return None

        if file_ext in [ProcessingEnum.TXT.value, ProcessingEnum.LOG.value]:
            return TextLoader(file_path, encoding="utf-8")

        if file_ext == ProcessingEnum.PDF.value:
            return PyMuPDFLoader(file_path)
        
        return None

    def get_file_content(self, file_id: str):

        loader = self.get_file_loader(file_id=file_id)
        if loader:
            try:
                return loader.load()
            except Exception as exc:
                self.logger.error(f"Failed to load file content for {file_id}: {exc}")
                return None

        return None

    """
    [MODIFICATION SUMMARY]
    What: Added a dedicated condition to process `.log` files line-by-line, bypassing the character-count chunking.
    Why: In the SOC Copilot context, log files contain time-sensitive security events per line. Chunking them by an arbitrary character count risks splitting IP addresses, timestamps, or actions across different chunks, which causes hallucination in the RAG retrieval. Line-by-line processing preserves the atomic integrity of each security event.
    """
    def process_file_content(self, file_content: list, file_id: str,
                             chunk_size: int=100, overlap_size: int=20):

        # <-- MODIFIED: Check specifically for .log files to apply SOC logic
        if file_id.endswith(ProcessingEnum.LOG.value): 
            self.logger.info(f"Processing LOG file {file_id} line by line to preserve SOC events.")
            chunks = []
            for rec in file_content:
                # <-- MODIFIED: Split by line, not by character count
                lines = [line.strip() for line in rec.page_content.split('\n') if line.strip()] 
                for line in lines:
                    chunks.append(Document(
                        page_content=line,
                        metadata=rec.metadata # <-- MODIFIED: Ensure metadata is preserved for each log line
                    ))
            return chunks

        file_content_texts = [rec.page_content for rec in file_content]
        file_content_metadata = [rec.metadata for rec in file_content]

        chunks = self.process_simpler_splitter(
            texts=file_content_texts,
            metadatas=file_content_metadata, # <-- MODIFIED: Passing metadata down to the splitter function
            chunk_size=chunk_size,
            overlap_size=overlap_size,
        )

        return chunks


    """
    [MODIFICATION SUMMARY]
    What: Restructured the loop to iterate over both texts and their corresponding metadata simultaneously. Also fixed the overlap logic.
    Why: The previous implementation discarded document metadata (setting it to an empty dictionary `{}`), which destroys the system's ability to trace RAG answers back to their source files or pages. This fix ensures accurate metadata is securely attached to every generated chunk.
    """
    def process_simpler_splitter(self, texts: List[str], metadatas: List[dict], chunk_size: int,
                                 overlap_size: int = 20, splitter_tag: str="\n"):
        chunks = []
        
        # <-- MODIFIED: Iterate through texts AND their corresponding metadata simultaneously
        for text, meta in zip(texts, metadatas): 
            lines = [ doc.strip() for doc in text.split(splitter_tag) if len(doc.strip()) > 1 ]
            
            current_chunk = ""
            for line in lines:
                candidate_chunk = current_chunk + line + splitter_tag

                if len(candidate_chunk) > chunk_size and len(current_chunk.strip()) > 0:
                    chunks.append(Document(
                        page_content=current_chunk.strip(),
                        metadata=meta # <-- MODIFIED: Inject the actual metadata instead of an empty {}
                    ))
                    
                    if overlap_size > 0:
                        # <-- MODIFIED: Ensured splitter_tag is appended to the overlap to avoid glued words
                        current_chunk = current_chunk[-overlap_size:] + splitter_tag 
                    else:
                        current_chunk = ""

                current_chunk += line + splitter_tag

            if len(current_chunk.strip()) > 0:
                chunks.append(Document(
                    page_content=current_chunk.strip(),
                    metadata=meta # <-- MODIFIED: Inject the actual metadata for the final chunk as well
                ))

        return chunks


    
