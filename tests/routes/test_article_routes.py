from fastapi.testclient import TestClient
from main import app
from unittest.mock import AsyncMock, patch

client = TestClient(app)

def test_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Securin CVE service is running"}

@patch('routes.article_routes.get_cve')
def test_index(mock_get_cve):
    mock_get_cve.return_value = AsyncMock(return_value=[
        {"a": 1}
    ])

    response = client.get("/cves")
    assert response.status_code == 200
    # Add more assertions to check the content of the response

@patch('routes.article_routes.find_cve_by_id')
def test_get_one_cve_found(mock_find_cve_by_id):
    mock_find_cve_by_id.return_value = AsyncMock(return_value=
        {"a": 1}
    )

    response = client.get("/cves/some-cve-id")
    assert response.status_code == 200
    # Add more assertions to check the content of the response

@patch('routes.article_routes.find_cve_by_id')
def test_get_one_cve_not_found(mock_find_cve_by_id):
    mock_find_cve_by_id.return_value = AsyncMock(return_value=None)

    response = client.get("/cves/non-existent-cve-id")
    assert response.status_code == 404
