from pydantic import BaseModel
from typing import List, Optional


class SigmaConvertRequest(BaseModel):
    sigma_rule: str
    platforms: Optional[List[str]] = None
    filename: Optional[str] = None


class SigmaValidateRequest(BaseModel):
    sigma_rule: str
    filename: Optional[str] = None


class SigmaBulkRule(BaseModel):
    sigma_rule: str
    filename: Optional[str] = None
    platforms: Optional[List[str]] = None


class SigmaBulkConvertRequest(BaseModel):
    rules: List[SigmaBulkRule]
    platforms: Optional[List[str]] = None

