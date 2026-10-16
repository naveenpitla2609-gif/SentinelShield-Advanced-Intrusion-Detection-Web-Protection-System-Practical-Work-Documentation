
from app import app


def test_inspector_detects_sql_injection():
    response = app.test_client().get(
        "/inspect",
        query_string={"search": "' OR '1'='1"},
    )

    data = response.get_json()

    assert response.status_code == 403
    assert data["is_malicious"] is True
    assert len(data["detections"]) > 0


def test_inspector_detects_xss():
    response = app.test_client().get(
        "/inspect",
        query_string={"value": "<script>alert(1)</script>"},
    )

    data = response.get_json()

    assert response.status_code == 403
    assert data["is_malicious"] is True


def test_inspector_allows_normal_request():
    response = app.test_client().get(
        "/inspect",
        query_string={"page": "home"},
    )

    data = response.get_json()

    assert response.status_code == 200
    assert data["is_malicious"] is False
    assert data["detections"] == []

def test_inspector_detects_command_injection():
    response = app.test_client().get(
        "/inspect",
        query_string={"value": "; whoami"},
    )

    data = response.get_json()

    assert response.status_code == 403
    assert data["is_malicious"] is True
    assert any(
        item["category"] == "COMMAND_INJECTION"
        for item in data["detections"]
    )
