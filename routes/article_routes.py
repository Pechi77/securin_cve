from typing import List

from fastapi import APIRouter, HTTPException, status

from securin_cve.models.article_model import CVE
from securin_cve.database.database import get_cve, find_cve_by_id


router = APIRouter()

@router.get("/")
async def root():
    return {"message": "Securin CVE service is running"}

@router.get("/cves", response_description="List all CVEs", response_model=List[CVE])
async def index(page: int = None, score: float = None, last_modified_days: int = None):
    return await get_cve(page, score, last_modified_days)

@router.get("/cves/{id}", response_description="Return a matching CVE", response_model=CVE)
async def get_one_cve(id: str):
    return await find_cve_by_id(id)

