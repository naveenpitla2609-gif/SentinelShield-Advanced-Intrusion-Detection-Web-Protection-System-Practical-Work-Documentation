from pathlib import Path

from app import app


def test_health():
    response = app.test_client().get("/health")
    assert response.status_code == 200


def test_normal_request():
    response = app.test_client().get(
        "/inspect?page=home"
    )
    assert response.status_code == 200
    assert response.get_json()["status"] == "allowed"


def test_sql_injection():
    response = app.test_client().get(
        "/inspect",
        query_string={"search": "' OR '1'='1"},
    )
    assert response.status_code == 403


def test_xss():
    response = app.test_client().get(
        "/inspect",
        query_string={"value": "<script>alert(1)</script>"},
    )
    assert response.status_code == 403


def test_path_traversal():
    response = app.test_client().get(
        "/inspect",
        query_string={"file": "../../etc/passwd"},
    )
    assert response.status_code == 403


def test_command_injection():
    response = app.test_client().get(
        "/inspect",
        query_string={"value": "; whoami"},
    )
    assert response.status_code == 403


def test_log_file_exists():
    app.test_client().get("/inspect?page=home")

    log_file = (
        Path(__file__).resolve().parent.parent
        / "Log Analysis"
        / "security_events.jsonl"
    )
    assert log_file.exists()
    assert log_file.stat().st_size > 0
