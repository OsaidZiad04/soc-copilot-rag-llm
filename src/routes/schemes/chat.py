from pydantic import BaseModel
from typing import Optional, List


class ChatRequest(BaseModel):
    question: str
    chat_history: Optional[List[dict]] = []
    limit: Optional[int] = 5
    content_type: Optional[str] = None
    source_name: Optional[str] = None
    auto_content_type: Optional[bool] = False
