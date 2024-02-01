from fastapi.testclient import TestClient
from securin_cve.main import app
from unittest.mock import AsyncMock, patch

client = TestClient(app)

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Securin CVE service is running"}

@patch('securin_cve.routes.article_routes.get_cve')
def test_index(mock_get_cve):
    mock_get_cve.return_value = AsyncMock(return_value=[
        {"a": 1}
    ])

    response = client.get("/cves")
    assert response.status_code == 200
    # Add more assertions to check the content of the response
