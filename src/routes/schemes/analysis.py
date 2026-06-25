from pydantic import BaseModel
from typing import Optional, List


class AlertAnalysisRequest(BaseModel):
    alert_text: str
    input_type: Optional[str] = "alert"


class InvestigationRequest(BaseModel):
    events: List[str]


class FeedbackRequest(BaseModel):
    feedback: str
    notes: Optional[str] = None


class CVEAnalysisRequest(BaseModel):
    cve_id: str


class StoredFileAnalysisRequest(BaseModel):
    file_id: str
    input_type: Optional[str] = "malware_report"
