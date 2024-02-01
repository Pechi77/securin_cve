from fastapi.testclient import TestClient
from securin_cve.main import app

client = TestClient(app)

def test_read_main():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Securin CVE service is running"}

def test_article_router_inclusion():
    response = client.get("/cves")
    
    assert response.status_code == 200
