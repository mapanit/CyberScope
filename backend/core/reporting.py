import hashlib
import json
import re
from typing import Any


def _clean_cell(value: Any) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ").strip()
    return text.replace("|", "\\|")


def _severity(value: Any) -> str:
    severity = str(value or "unknown").lower()
    severity = {"moderate": "medium", "informational": "info"}.get(severity, severity)
    return severity if severity in {"critical", "high", "medium", "low", "info"} else "unknown"


def normalize_findings(tool_results: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract comparable vulnerability findings from heterogeneous tool results."""
    findings: dict[str, dict[str, Any]] = {}
    finding_lists = {"vulnerabilities", "findings", "issues", "alerts", "results"}
    visited: set[int] = set()

    def add_finding(tool: str, item: dict[str, Any]) -> None:
        info = item.get("info")
        info = info if isinstance(info, dict) else {}
        title = (
            item.get("name")
            or item.get("title")
            or item.get("type")
            or item.get("template_id")
            or item.get("cve_id")
            or item.get("id")
            or info.get("name")
            or info.get("title")
            or info.get("severity")
        )
        severity = _severity(item.get("severity") or info.get("severity"))
        target = (
            item.get("matched_at")
            or item.get("url")
            or item.get("endpoint")
            or item.get("host")
            or item.get("affected_url")
            or ""
        )
        description = (
            item.get("description")
            or item.get("recommendation")
            or info.get("description")
            or ""
        )
        if not title or not (severity != "unknown" or "vulnerabilit" in str(item.get("type", "")).lower()
                             or "cve" in str(title).lower() or "template_id" in item):
            return
        identity = "\0".join(
            (tool.lower(), str(title).strip().lower(), str(target).strip().lower(), severity)
        )
        fingerprint = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        findings[fingerprint] = {
            "fingerprint": fingerprint,
            "tool": tool,
            "title": str(title),
            "severity": severity,
            "target": str(target),
            "description": str(description),
        }

    def visit(tool: str, value: Any) -> None:
        if isinstance(value, dict):
            object_id = id(value)
            if object_id in visited:
                return
            visited.add(object_id)
            if isinstance(value.get("info"), dict) or any(
                key in value for key in ("severity", "template_id", "cve_id", "vulnerability")
            ):
                add_finding(tool, value)
            for key, child in value.items():
                if key.lower() in finding_lists and isinstance(child, list):
                    for item in child:
                        if isinstance(item, dict):
                            add_finding(tool, item)
                            visit(tool, item)
                elif key.lower() != "info" and isinstance(child, (dict, list)):
                    visit(tool, child)
        elif isinstance(value, list):
            for item in value:
                visit(tool, item)

    for tool_name, result in tool_results.items():
        visit(tool_name, result)
    return sorted(findings.values(), key=lambda finding: (finding["tool"], finding["title"], finding["target"]))


def _tool_counts(tool_results: dict[str, Any]) -> list[tuple[str, str, int]]:
    rows = []
    for tool, result in tool_results.items():
        result = result if isinstance(result, dict) else {}
        status = str(result.get("status", "unknown"))
        data = result.get("data")
        count = result.get("count")
        if count is None and isinstance(data, dict):
            count = data.get("total", data.get("total_findings", data.get("subdomains_count")))
        if count is None:
            count = len(result.get("vulnerabilities", [])) if isinstance(result.get("vulnerabilities"), list) else 0
        rows.append((tool, status, count if isinstance(count, int) else 0))
    return rows


def render_markdown_report(report: dict[str, Any]) -> str:
    """Render a human-readable Markdown report from the canonical scan result."""
    tool_results = report.get("results", {})
    tool_results = tool_results if isinstance(tool_results, dict) else {}
    findings = normalize_findings(tool_results)
    rows = _tool_counts(tool_results)

    lines = [
        "# CyberScope — отчет о сканировании",
        "",
        f"- **Цель:** {_clean_cell(report.get('target', '-'))}",
        f"- **ID сканирования:** {_clean_cell(report.get('scan_id', '-'))}",
        f"- **Статус:** {_clean_cell(report.get('status', 'unknown'))}",
        f"- **Дата создания:** {_clean_cell(report.get('created_at', '-'))}",
        f"- **Инструменты:** {len(rows)}",
        "",
        "## Сводка инструментов",
        "",
        "| Инструмент | Статус | Результаты |",
        "| --- | --- | ---: |",
    ]
    lines.extend(
        f"| {_clean_cell(tool)} | {_clean_cell(status)} | {count} |"
        for tool, status, count in rows
    )
    lines.extend(["", "## Находки безопасности", ""])
    if findings:
        lines.extend(
            [
                "| Серьезность | Инструмент | Находка | Цель |",
                "| --- | --- | --- | --- |",
            ]
        )
        lines.extend(
            f"| {_clean_cell(item['severity'])} | {_clean_cell(item['tool'])} | "
            f"{_clean_cell(item['title'])} | {_clean_cell(item['target'])} |"
            for item in findings
        )
        for item in findings:
            lines.extend(
                [
                    "",
                    f"### {_clean_cell(item['title'])}",
                    "",
                    f"- **Серьезность:** {_clean_cell(item['severity'])}",
                    f"- **Инструмент:** {_clean_cell(item['tool'])}",
                    f"- **Цель:** {_clean_cell(item['target']) or '-'}",
                    f"- **Описание:** {_clean_cell(item['description']) or 'Нет описания'}",
                ]
            )
    else:
        lines.append("Уязвимости не обнаружены или инструменты не вернули нормализуемые находки.")

    lines.extend(["", "## Подробные результаты", ""])
    for tool, result in tool_results.items():
        json_content = json.dumps(result, ensure_ascii=False, indent=2, default=str)
        longest_backticks = max(
            (len(run) for run in re.findall(r"`+", json_content)),
            default=0,
        )
        fence = "`" * max(3, longest_backticks + 1)
        lines.extend(
            [
                f"### {_clean_cell(tool)}",
                "",
                f"{fence}json",
                json_content,
                fence,
                "",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"
