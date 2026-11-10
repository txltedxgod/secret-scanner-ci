import pytest
from fastapi.testclient import TestClient
from scanner.api import app

client = TestClient(app)


def test_healthz():
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_api_scan_with_secrets():
    token_str = "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
    payload = {
        "content": f"const token = '{token_str}';"
    }
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["has_secrets"] is True
    assert data["total_findings"] >= 1
    assert data["findings"][0]["rule"] == "GitHub Token"


def test_api_scan_without_secrets():
    payload = {
        "content": "const greeting = 'Hello, World!';"
    }
    response = client.post("/api/v1/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["has_secrets"] is False
    assert len(data["findings"]) == 0


def test_api_scan_diff():
    diff = """
diff --git a/app.py b/app.py
--- a/app.py
+++ b/app.py
@@ -1,2 +1,3 @@
+export AWS_SECRET_KEY='AKIAIOSFODNN7EXAMPLE'
"""
    response = client.post("/api/v1/scan/diff", json={"diff": diff})
    assert response.status_code == 200
    data = response.json()
    assert data["has_secrets"] is True
    assert data["findings"][0]["rule"] == "AWS Access Key"


def test_api_rules_catalog():
    response = client.get("/api/v1/rules")
    assert response.status_code == 200
    data = response.json()
    assert data["count"] >= 10
    assert any(r["name"] == "AWS Access Key" for r in data["rules"])
