import json

from app import create_app


def test_health():
    app = create_app()
    client = app.test_client()
    r = client.get("/health")
    assert r.status_code == 200
    data = r.get_json()
    assert data["service"] == "ml-detector"


def test_detect_basic():
    app = create_app()
    client = app.test_client()
    payload = {"packets_per_second": 10, "bytes_per_second": 1000}
    r = client.post("/detect", data=json.dumps(payload), content_type="application/json")
    assert r.status_code == 200
    data = r.get_json()
    assert "threat_detected" in data

