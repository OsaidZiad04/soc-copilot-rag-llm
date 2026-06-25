from pydantic import BaseModel
from typing import List, Optional


class InvestigationRequest(BaseModel):
    events: List[str]


class InvestigationFileRequest(BaseModel):
    separator: Optional[str] = "---"
