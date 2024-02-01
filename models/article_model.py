from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional

class Description(BaseModel):
    lang: str
    value: str    

class CVE(BaseModel):
    id: str
    sourceIdentifier: str
    published: datetime
    lastModified: datetime
    vulnStatus: str
    descriptions: List[Description]
    metrics: Optional[dict]
    weaknesses: Optional[List]
    configurations: List
    references: List









