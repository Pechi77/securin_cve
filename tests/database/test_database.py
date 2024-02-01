import pytest
from unittest.mock import patch, AsyncMock
from fastapi import HTTPException
from securin_cve.database.database import get_cve, find_cve_by_id




async def test_find_cve_by_id_found():
    
    cve = await find_cve_by_id("cve-2000-0495")

    assert cve is not None