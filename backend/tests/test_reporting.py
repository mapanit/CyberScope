import pytest

from core.reporting import normalize_findings, render_markdown_report
from scanner_config import (
    get_amass_profile,
    get_nmap_profile,
    get_retire_profile,
    get_web_scanner_profile,
)


def test_normalize_findings_handles_nuclei_and_retire_and_deduplicates():
    results = {
        "nuclei": {
            "results": [
                {
                    "template_id": "tls-expired",
                    "info": {"name": "Expired certificate", "severity": "high"},
                    "matched_at": "https://example.org",
                }
            ]
        },
        "retire": {
            "vulnerabilities": [
                {
                    "name": "Outdated library",
                    "severity": "moderate",
                    "url": "https://example.org/app.js",
                },
                {
                    "name": "Outdated library",
                    "severity": "medium",
                    "url": "https://example.org/app.js",
                },
            ]
        },
    }

    findings = normalize_findings(results)

    assert len(findings) == 2
    assert {finding["severity"] for finding in findings} == {"high", "medium"}
    assert {finding["tool"] for finding in findings} == {"nuclei", "retire"}


def test_markdown_report_uses_safe_fence_for_embedded_json():
    report = {
        "target": "example.org",
        "scan_id": "scan-1",
        "status": "success",
        "results": {"sample": {"output": "```json\npayload\n```"}},
    }

    markdown = render_markdown_report(report)

    assert "## Подробные результаты" in markdown
    assert "````json" in markdown
    assert "payload" in markdown


def test_scanner_profiles_return_supported_values():
    assert get_amass_profile("quick_passive").timeout == 120
    assert get_web_scanner_profile("medium").get_katana_arguments(
        "https://example.org"
    ) == ["katana", "-u", "https://example.org", "-d", "3", "-c", "50"]
    assert get_retire_profile("all_except_low").include_js
    assert get_nmap_profile("standard").get_full_arguments().startswith("-sV")


def test_scanner_profiles_reject_unknown_names():
    with pytest.raises(ValueError, match="Unknown scanner profile"):
        get_nmap_profile("not-a-profile")
