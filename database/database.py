from datetime import datetime, timedelta

import motor.motor_asyncio
import pymongo
from fastapi import HTTPException

client = motor.motor_asyncio.AsyncIOMotorClient("mongodb://localhost:27017")
db = client.securin
collection = "cve"

async def get_cve(page: int, score: float = None, last_modified_days: int = None):
    page = page or 1
    query = {}

    if score is not None:
        query["$or"] = [
            {"metrics.cvssMetricV2.cvssData.baseScore": {"$gte": score}},
            {"metrics.cvssMetricV3.cvssData.baseScore": {"$gte": score}}
        ]

    if last_modified_days is not None:
        last_modified_date = datetime.utcnow() - timedelta(days=last_modified_days)
        query["lastModified"] = {"$gte": last_modified_date.isoformat()}

    cves = await db[collection].find(query).sort('lastModified', pymongo.DESCENDING).skip(10*(page-1)).limit(10).to_list(10)
    
    return cves



async def find_cve_by_id(cve_id: str):
    article = await db[collection].find_one({"id": cve_id.lower()})
    if article:
        return article
    return HTTPException(detail="Not Found", status_code=404)