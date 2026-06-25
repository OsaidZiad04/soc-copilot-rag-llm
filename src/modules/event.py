from pydantic import BaseModel, Field
from typing import Optional, Dict, Any


class Event(BaseModel):
    ip: Optional[str] = None
    timestamp: Optional[str] = None
    action: str = Field(default="unknown")
    status: str = Field(default="unknown")
    user: Optional[str] = None
    command: Optional[str] = None
    source: str = Field(default="log")
    raw: str = Field(default="")
    metadata: Dict[str, Any] = Field(default_factory=dict)

