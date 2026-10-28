import React from "react";

const getFilename = (path) => path.split(/[\\/]/).pop();

const buildTextReport = (results, language) => {
  const heading = language === "ru" ? "ОТЧЕТ О СКАНИРОВАНИИ" : "SCAN REPORT";
  const targetLabel = language === "ru" ? "Цель" : "Target";
  const scanIdLabel = language === "ru" ? "ID сканирования" : "Scan ID";
  const toolsLabel = language === "ru" ? "Результаты инструментов" : "Tool results";
  const detailsLabel = language === "ru" ? "Полные данные" : "Full details";
  const toolResults = Object.entries(results.results || {})
    .map(([tool, result]) => `- ${tool.toUpperCase()}: ${result.status || "unknown"}`)
    .join("\n");

  return [
    heading,
    "=".repeat(40),
    `${targetLabel}: ${results.target || "-"}`,
    `${scanIdLabel}: ${results.scan_id || "-"}`,
    `${toolsLabel}:`,
    toolResults || "-",
    "",
    `${detailsLabel}:`,
    JSON.stringify(results.results || {}, null, 2),
    "",
  ].join("\n");
};

const formatToolCount = (count, language) => {
  if (language !== "ru") return `${count} ${count === 1 ? "tool" : "tools"}`;
  const remainder10 = count % 10;
  const remainder100 = count % 100;
  const noun =
    remainder10 === 1 && remainder100 !== 11
      ? "инструмент"
      : remainder10 >= 2 && remainder10 <= 4 && (remainder100 < 12 || remainder100 > 14)
        ? "инструмента"
        : "инструментов";
  return `${count} ${noun}`;
};

const getScanStatus = (status, language) => {
  const labels = {
    success: language === "ru" ? "Успешно" : "Succeeded",
    error: language === "ru" ? "Завершено с ошибками" : "Completed with errors",
    timeout: language === "ru" ? "Тайм-аут" : "Timed out",
    cancelled: language === "ru" ? "Отменено" : "Cancelled",
  };
  return labels[status] || labels.success;
};

const CompletedScanCard = ({
  results,
  language = "ru",
  onDownloadReport,
  onDownloadContent,
}) => {
  const reportPaths = results.combined_reports || {};
  const scanId = results.scan_id || "scan";
  const tools = results.tools_executed || [];
  const toolsCount = results.tools_count || tools.length;
  const status = results.status || "success";

  const downloadJson = () => {
    if (reportPaths.json) {
      onDownloadReport(getFilename(reportPaths.json), "json");
      return;
    }

    onDownloadContent(
      JSON.stringify(results, null, 2),
      `CyberScope_${scanId}.json`,
      "application/json;charset=utf-8",
    );
  };

  const downloadText = () => {
    if (reportPaths.txt) {
      onDownloadReport(getFilename(reportPaths.txt), "txt");
      return;
    }

    onDownloadContent(
      buildTextReport(results, language),
      `CyberScope_${scanId}.txt`,
      "text/plain;charset=utf-8",
    );
  };

  const downloadWord = () => {
    if (reportPaths.docx) {
      onDownloadReport(getFilename(reportPaths.docx), "word");
    }
  };

  const downloadMarkdown = () => {
    if (reportPaths.md) {
      onDownloadReport(getFilename(reportPaths.md), "md");
    }
  };

  const reportFormatCount = 2 + Number(Boolean(reportPaths.docx)) + Number(Boolean(reportPaths.md));

  return (
    <section className="scan-complete-card" aria-labelledby="scan-complete-title">
      <div className="scan-complete-card__header">
        <span
          className={`scan-complete-card__icon scan-complete-card__icon--${status}`}
          aria-hidden="true"
        >
          <svg viewBox="0 0 24 24" focusable="false">
            {status === "success" ? (
              <path d="m5 12.5 4.5 4.5L19 7" />
            ) : (
              <>
                <path d="M12 7v6" />
                <path d="M12 17h.01" />
              </>
            )}
          </svg>
        </span>
        <div className="scan-complete-card__heading">
          <span className="scan-complete-card__eyebrow">
            {status === "error"
              ? language === "ru" ? "ЗАВЕРШЕНО С ОШИБКАМИ" : "COMPLETED WITH ERRORS"
              : language === "ru" ? "АНАЛИЗ ЗАВЕРШЕН" : "ANALYSIS COMPLETE"}
          </span>
          <h3 id="scan-complete-title">
            {language === "ru" ? "Результаты доступны" : "Your results are ready"}
          </h3>
        </div>
        <span className={`scan-complete-card__status scan-complete-card__status--${status}`}>
          {getScanStatus(status, language)}
        </span>
      </div>

      <div className="scan-complete-card__details">
        <div className="scan-complete-card__detail">
          <span>{language === "ru" ? "ЦЕЛЬ" : "TARGET"}</span>
          <strong title={results.target}>{results.target || "-"}</strong>
        </div>
        <div className="scan-complete-card__detail">
          <span>{language === "ru" ? "ИНСТРУМЕНТЫ" : "TOOLS"}</span>
          <strong>{formatToolCount(toolsCount, language)}</strong>
        </div>
        <div className="scan-complete-card__detail scan-complete-card__detail--id">
          <span>{language === "ru" ? "ID СКАНИРОВАНИЯ" : "SCAN ID"}</span>
          <strong title={scanId}>{scanId}</strong>
        </div>
      </div>

      <div className="scan-complete-card__downloads">
        <div className="scan-complete-card__downloads-heading">
          <div>
            <h4>{language === "ru" ? "Скачать отчет" : "Download report"}</h4>
            <p>
              {language === "ru"
                ? "Выберите удобный формат файла"
                : "Choose the format that works for you"}
            </p>
          </div>
          <span>{reportFormatCount} {language === "ru" ? "формата" : "formats"}</span>
        </div>
        <div className="scan-complete-card__format-list">
          {reportPaths.docx && (
            <button
              className="scan-complete-card__format scan-complete-card__format--word"
              type="button"
              onClick={downloadWord}
            >
              <span className="scan-complete-card__format-icon" aria-hidden="true">
                DOCX
              </span>
              <span className="scan-complete-card__format-copy">
                <strong>Word</strong>
                <small>
                  {language === "ru" ? "Готовый отчет для чтения и печати" : "Ready to read and print"}
                </small>
              </span>
              <span className="scan-complete-card__download-icon" aria-hidden="true">
                ↓
              </span>
            </button>
          )}
          {reportPaths.md && (
            <button
              className="scan-complete-card__format scan-complete-card__format--markdown"
              type="button"
              onClick={downloadMarkdown}
            >
              <span className="scan-complete-card__format-icon" aria-hidden="true">
                .MD
              </span>
              <span className="scan-complete-card__format-copy">
                <strong>Markdown</strong>
                <small>
                  {language === "ru" ? "Для удобного чтения и публикации" : "For easy reading and publishing"}
                </small>
              </span>
              <span className="scan-complete-card__download-icon" aria-hidden="true">
                ↓
              </span>
            </button>
          )}
          <button
            className="scan-complete-card__format scan-complete-card__format--json"
            type="button"
            onClick={downloadJson}
          >
            <span className="scan-complete-card__format-icon" aria-hidden="true">
              {"{ }"}
            </span>
            <span className="scan-complete-card__format-copy">
              <strong>JSON</strong>
              <small>
                {language === "ru" ? "Для анализа и интеграций" : "For analysis and integrations"}
              </small>
            </span>
            <span className="scan-complete-card__download-icon" aria-hidden="true">
              ↓
            </span>
          </button>
          <button
            className="scan-complete-card__format scan-complete-card__format--txt"
            type="button"
            onClick={downloadText}
          >
            <span className="scan-complete-card__format-icon" aria-hidden="true">
              TXT
            </span>
            <span className="scan-complete-card__format-copy">
              <strong>TXT</strong>
              <small>
                {language === "ru" ? "Для чтения и обмена" : "For reading and sharing"}
              </small>
            </span>
            <span className="scan-complete-card__download-icon" aria-hidden="true">
              ↓
            </span>
          </button>
        </div>
      </div>
    </section>
  );
};

export default CompletedScanCard;
