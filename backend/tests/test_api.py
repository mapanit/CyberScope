import os
import json
import tempfile
import uuid

os.environ.setdefault(
    "SQLALCHEMY_DATABASE_URL",
    f"sqlite:///{tempfile.gettempdir()}/cyberscope-test-{uuid.uuid4().hex}.db",
)
os.environ.setdefault(
    "JWT_SECRET_KEY",
    "test-only-jwt-secret-key-that-is-longer-than-thirty-two-characters",
)

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from fastapi.testclient import TestClient

import server


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "user_reports_dir", lambda username: tmp_path / username)
    monkeypatch.setattr(server.scheduler, "tasks", {})
    monkeypatch.setattr(server.scheduler, "_save_tasks", lambda: None)
    with TestClient(server.app) as test_client:
        yield test_client


def make_headers(username):
    token = server.auth.create_access_token({"sub": username})
    return {"Authorization": f"Bearer {token}"}


def test_register_and_login(client):
    username = f"test-{uuid.uuid4().hex}"
    response = client.post(
        "/auth/register",
        json={"username": username, "password": "strong-test-password"},
    )
    assert response.status_code == 200
    assert response.json()["username"] == username

    response = client.post(
        "/auth/login",
        json={"username": username, "password": "strong-test-password"},
    )
    assert response.status_code == 200
    assert response.json()["token_type"] == "bearer"
    assert response.json()["access_token"]


def test_report_creation_and_crud_are_user_scoped(client, monkeypatch):
    monkeypatch.setattr(
        server,
        "wappalyzer_scan",
        lambda target, reports_dir: {"total": 0, "technologies": []},
    )
    owner_headers = make_headers("report-owner")
    other_headers = make_headers("other-user")
    old_whois_dir = server.user_reports_dir("report-owner") / "whois" / "txt"
    old_whois_dir.mkdir(parents=True)
    (old_whois_dir / "old-whois-error.txt").write_text(
        "Whois command returned no output",
        encoding="utf-8",
    )
    scan_response = client.post(
        "/api/run-selected-tools",
        params={
            "target": "example.org",
            "tools": "wappalyzer",
            "scan_id": str(uuid.uuid4()),
        },
        headers=owner_headers,
    )
    assert scan_response.status_code == 200
    assert "whois" not in scan_response.json()["results"]
    combined_txt = Path(scan_response.json()["combined_reports"]["txt"])
    assert "Whois command returned no output" not in combined_txt.read_text(encoding="utf-8")
    filename = Path(scan_response.json()["combined_reports"]["json"]).name
    assert filename.endswith(".json")
    owner_dir = server.user_reports_dir("report-owner") / "combined" / "json"
    assert (owner_dir / filename).is_file()

    assert client.get("/api/combined-reports").status_code == 401
    assert filename in client.get(
        "/api/combined-reports", headers=owner_headers
    ).json()["json_reports"]
    assert filename not in client.get(
        "/api/combined-reports", headers=other_headers
    ).json()["json_reports"]
    assert client.get(
        "/api/download-combined-report",
        params={"filename": filename, "report_type": "json"},
        headers=owner_headers,
    ).json()["scan_id"] == scan_response.json()["scan_id"]
    assert client.get(
        "/api/get-report-content",
        params={"filename": filename, "report_type": "json"},
        headers=owner_headers,
    ).json()["scan_id"] == scan_response.json()["scan_id"]
    assert client.delete(
        "/api/delete-combined-report",
        params={"filename": filename, "report_type": "json"},
        headers=other_headers,
    ).status_code == 404
    assert (owner_dir / filename).exists()
    assert client.delete(
        "/api/delete-combined-report",
        params={"filename": filename, "report_type": "json"},
        headers=owner_headers,
    ).status_code == 200
    assert not (owner_dir / filename).exists()


def test_task_crud_and_ownership(client):
    owner_headers = make_headers("task-owner")
    other_headers = make_headers("other-task-user")
    task = {
        "query": "example.org",
        "activeTools": ["wappalyzer"],
        "type": "once",
        "time": "23:59",
    }
    create_response = client.post("/api/tasks", json=task, headers=owner_headers)
    assert create_response.status_code == 200
    task_id = create_response.json()["task_id"]

    assert client.get("/api/tasks", headers=owner_headers).json()["count"] == 1
    assert client.get("/api/tasks", headers=other_headers).json()["count"] == 0
    assert client.get(f"/api/tasks/{task_id}", headers=other_headers).status_code == 404
    assert client.get(f"/api/task-results/{task_id}", headers=owner_headers).status_code == 200
    assert client.delete(f"/api/tasks/{task_id}", headers=other_headers).status_code == 404
    assert client.delete(f"/api/tasks/{task_id}", headers=owner_headers).status_code == 200


def test_task_rejects_tools_without_scheduler_callbacks(client):
    response = client.post(
        "/api/tasks",
        json={
            "query": "example.org",
            "activeTools": ["katana"],
            "type": "once",
            "time": "23:59",
        },
        headers=make_headers("task-owner"),
    )
    assert response.status_code == 400
    assert "не поддерживаются планировщиком" in response.json()["detail"]


def test_tool_catalog_has_each_selectable_tool(client):
    response = client.get("/api/tools", headers=make_headers("catalog-owner"))
    assert response.status_code == 200
    tool_ids = {tool["id"] for tool in response.json()["tools"]}
    assert {"scanner", "nuclei", "wappalyzer", "whois", "dns", "nmap"} <= tool_ids


def test_combined_reports_are_listed_newest_first(client, tmp_path):
    headers = make_headers("report-order-owner")
    report_dir = tmp_path / "report-order-owner" / "combined" / "json"
    report_dir.mkdir(parents=True)
    older = report_dir / "combined_report_older.json"
    newer = report_dir / "combined_report_newer.json"
    older.write_text("{}", encoding="utf-8")
    newer.write_text("{}", encoding="utf-8")
    os.utime(older, (100, 100))
    os.utime(newer, (200, 200))

    response = client.get("/api/combined-reports", headers=headers)

    assert response.status_code == 200
    assert response.json()["json_reports"][:2] == [newer.name, older.name]


def test_queued_scan_returns_progress_and_results(client, monkeypatch):
    async def fake_run_selected_tools(**kwargs):
        return {
            "status": "success",
            "scan_id": kwargs["scan_id"],
            "target": kwargs["target"],
            "tools_executed": ["wappalyzer"],
            "tools_count": 1,
            "results": {"wappalyzer": {"status": "success"}},
            "combined_reports": {},
        }

    monkeypatch.setattr(server, "run_selected_tools", fake_run_selected_tools)
    headers = make_headers("queued-owner")
    response = client.post(
        "/api/scans",
        params={
            "target": "example.org",
            "tools": "wappalyzer",
            "scan_id": str(uuid.uuid4()),
        },
        headers=headers,
    )
    assert response.status_code == 202
    scan_id = response.json()["scan_id"]

    status = client.get(
        "/api/scan-status", params={"scan_id": scan_id}, headers=headers
    )
    for _ in range(50):
        if status.json().get("scan_status") not in {"queued", "running"}:
            break
        import time
        time.sleep(0.01)
        status = client.get(
            "/api/scan-status", params={"scan_id": scan_id}, headers=headers
        )
    assert status.json()["scan_status"] == "success"
    result = client.get(
        "/api/scan-results", params={"scan_id": scan_id}, headers=headers
    )
    assert result.status_code == 200
    assert result.json()["results"]["wappalyzer"]["status"] == "success"


def test_queued_scan_reuses_its_session_for_the_scan_handler(client, monkeypatch):
    monkeypatch.setattr(
        server,
        "wappalyzer_scan",
        lambda target, reports_dir: {"total": 1, "technologies": [{"name": "Test"}]},
    )
    headers = make_headers("queued-session-owner")
    response = client.post(
        "/api/scans",
        params={
            "target": "example.org",
            "tools": "wappalyzer",
            "scan_id": str(uuid.uuid4()),
        },
        headers=headers,
    )
    assert response.status_code == 202
    scan_id = response.json()["scan_id"]

    status = client.get(
        "/api/scan-status", params={"scan_id": scan_id}, headers=headers
    )
    for _ in range(500):
        if status.json().get("scan_status") not in {"queued", "running"}:
            break
        import time
        time.sleep(0.01)
        status = client.get(
            "/api/scan-status", params={"scan_id": scan_id}, headers=headers
        )

    assert status.json()["scan_status"] == "success"
    result = client.get(
        "/api/scan-results", params={"scan_id": scan_id}, headers=headers
    )
    assert result.status_code == 200
    assert result.json()["results"]["wappalyzer"]["technologies_found"] == 1
    assert result.json()["combined_reports"]["json"]


def test_queued_scan_failure_returns_error_details_without_results_500(client, monkeypatch):
    async def fail_scan(**kwargs):
        raise server.HTTPException(status_code=500, detail="report generation failed")

    monkeypatch.setattr(server, "run_selected_tools", fail_scan)
    headers = make_headers("queued-error-owner")
    response = client.post(
        "/api/scans",
        params={
            "target": "example.org",
            "tools": "wappalyzer",
            "scan_id": str(uuid.uuid4()),
        },
        headers=headers,
    )
    assert response.status_code == 202
    scan_id = response.json()["scan_id"]

    status = client.get(
        "/api/scan-status", params={"scan_id": scan_id}, headers=headers
    )
    for _ in range(50):
        if status.json().get("scan_status") == "error":
            break
        import time
        time.sleep(0.01)
        status = client.get(
            "/api/scan-status", params={"scan_id": scan_id}, headers=headers
        )
    assert status.json()["error"] == "report generation failed"

    result = client.get(
        "/api/scan-results", params={"scan_id": scan_id}, headers=headers
    )
    assert result.status_code == 200
    assert result.json()["status"] == "error"
    assert result.json()["error"] == "report generation failed"


def test_compare_scans_reports_added_and_removed_findings(client):
    headers = make_headers("compare-owner")
    reports_dir = server.user_reports_dir("compare-owner") / "combined" / "json"
    reports_dir.mkdir(parents=True)
    baseline_id = str(uuid.uuid4())
    current_id = str(uuid.uuid4())
    baseline = {
        "target": "example.org",
        "results": {
            "scanner": {
                "vulnerabilities": [
                    {"name": "Old issue", "severity": "medium", "url": "/old"}
                ]
            }
        },
    }
    current = {
        "target": "example.org",
        "results": {
            "scanner": {
                "vulnerabilities": [
                    {"name": "New issue", "severity": "high", "url": "/new"}
                ]
            }
        },
    }
    (reports_dir / f"combined_report_{baseline_id}.json").write_text(
        json.dumps(baseline), encoding="utf-8"
    )
    (reports_dir / f"combined_report_{current_id}.json").write_text(
        json.dumps(current), encoding="utf-8"
    )

    response = client.get(
        "/api/compare-scans",
        params={
            "baseline_scan_id": baseline_id,
            "current_scan_id": current_id,
        },
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["summary"] == {"added": 1, "removed": 1, "unchanged": 0}
    assert response.json()["added"][0]["title"] == "New issue"
    assert response.json()["removed"][0]["title"] == "Old issue"


def test_scan_reports_no_findings_as_a_successful_scan(client, monkeypatch):
    monkeypatch.setattr(
        server,
        "wappalyzer_scan",
        lambda target, reports_dir: {"total": 0, "technologies": []},
    )
    response = client.post(
        "/api/run-selected-tools",
        params={
            "target": "example.org",
            "tools": "wappalyzer",
            "scan_id": str(uuid.uuid4()),
        },
        headers=make_headers("scan-owner"),
    )
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "success"
    assert result["results"]["wappalyzer"]["status"] == "no_findings"


def test_scan_reports_include_full_tool_results_and_word_report(client, monkeypatch):
    async def fake_run_command(command, scan_id):
        return '{"request":{"endpoint":"https://example.org/page"}}', ""

    monkeypatch.setattr(
        server,
        "wappalyzer_scan",
        lambda target, reports_dir: {
            "total": 1,
            "technologies": [{"name": "Example CMS", "version": "2.4"}],
        },
    )
    monkeypatch.setattr(server, "run_command", fake_run_command)
    response = client.post(
        "/api/run-selected-tools",
        params={
            "target": "example.org",
            "tools": "wappalyzer,katana",
            "scan_id": str(uuid.uuid4()),
        },
        headers=make_headers("scan-owner"),
    )
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "success"
    assert result["results"]["wappalyzer"]["status"] == "success"
    assert result["results"]["katana"]["status"] == "success"
    combined_json = json.loads(
        Path(result["combined_reports"]["json"]).read_text(encoding="utf-8")
    )
    assert combined_json["results"]["wappalyzer"]["data"]["technologies"] == [
        {"name": "Example CMS", "version": "2.4"}
    ]
    assert combined_json["results"]["katana"]["urls_found"][0]["request"]["endpoint"] == (
        "https://example.org/page"
    )
    combined_txt = Path(result["combined_reports"]["txt"]).read_text(encoding="utf-8")
    assert "Example CMS" in combined_txt
    combined_markdown = Path(result["combined_reports"]["md"])
    assert combined_markdown.is_file()
    assert "# CyberScope" in combined_markdown.read_text(encoding="utf-8")
    markdown_response = client.get(
        "/api/download-combined-report",
        params={"filename": combined_markdown.name, "report_type": "md"},
        headers=make_headers("scan-owner"),
    )
    assert markdown_response.status_code == 200
    assert markdown_response.text.startswith("# CyberScope")
    combined_docx = Path(result["combined_reports"]["docx"])
    assert combined_docx.is_file()
    word_report = client.get(
        "/api/download-combined-report",
        params={"filename": combined_docx.name, "report_type": "word"},
        headers=make_headers("scan-owner"),
    )
    assert word_report.status_code == 200
    assert word_report.headers["content-type"] == (
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    )
    from docx import Document

    docx_text = "\n".join(
        paragraph.text for paragraph in Document(combined_docx).paragraphs
    )
    assert "Example CMS" in docx_text
    assert "https://example.org/page" in docx_text


def test_whois_failure_still_saves_tool_and_combined_reports(client, monkeypatch):
    def raise_whois_error(domain):
        raise ValueError("WHOIS response could not be parsed")

    monkeypatch.setattr(server.whois, "whois", raise_whois_error)
    monkeypatch.delattr(server.whois.parser, "PywhoisError", raising=False)
    response = client.post(
        "/api/run-selected-tools",
        params={
            "target": "example.org",
            "tools": "whois",
            "scan_id": str(uuid.uuid4()),
        },
        headers=make_headers("whois-owner"),
    )

    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "error"
    assert result["results"]["whois"]["status"] == "error"
    assert "WHOIS response could not be parsed" in result["results"]["whois"]["error"]
    assert result["results"]["whois"]["reports"]["json"]
    assert result["results"]["whois"]["reports"]["txt"]
    assert result["combined_reports"]["json"]
    assert result["combined_reports"]["txt"]
    assert Path(result["combined_reports"]["json"]).is_file()
    combined_txt = Path(result["combined_reports"]["txt"])
    assert combined_txt.is_file()
    assert "WHOIS response could not be parsed" in combined_txt.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("result", "scan_active", "expected"),
    [
        ({"error": "scanner failed"}, True, "error"),
        ({"error": "request timed out"}, True, "timeout"),
        ({"status": "success"}, False, "cancelled"),
    ],
)
def test_tool_status_normalization(result, scan_active, expected):
    assert server.normalize_tool_status("scanner", result, scan_active)["status"] == expected


def test_scan_cancel_stops_attached_process_and_checks_owner(client):
    import subprocess

    scan_id = str(uuid.uuid4())
    server.create_scan_session(scan_id, "scan-owner")
    process = subprocess.Popen(["sleep", "60"])
    server.set_scan_process(scan_id, process)

    assert client.post(
        "/api/cancel-scan",
        params={"scan_id": scan_id},
        headers=make_headers("other-user"),
    ).status_code == 404
    assert process.poll() is None
    assert client.post(
        "/api/cancel-scan",
        params={"scan_id": scan_id},
        headers=make_headers("scan-owner"),
    ).json()["status"] == "success"
    process.wait(timeout=3)
