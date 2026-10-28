import React, { useEffect, useState } from "react";
import "./Home.scss";
import Tools from "./Tools/Tools";
import SearchForm from "./components/SearchForm";
import ReportsPanel from "./components/ReportsPanel";
import ResultsSection from "./components/ResultsSection";
import CompletedScanCard from "./components/CompletedScanCard";
import ScanningInfo from "./components/ScanningInfo";
import ReportViewer from "./components/ReportViewer/ReportViewer";
import AIAnalysis from "./components/AIAnalysis/AIAnalysis";
import ScheduleScanner from "./ScheduleScanner/ScheduleScanner";
import Image from "../../../Img/clock.png";
import { useScanState } from "./hooks/useScanState";
import { useReports } from "./hooks/useReports";
import { scanService } from "./services/scanService";
import { reportService } from "./services/reportService";

const loadSavedScanReport = async (filename, reportLists) => {
  const content = await reportService.getReportContent(filename, "json");
  const report = JSON.parse(content);
  const scanId = filename.match(/^combined_report_(.+)\.json$/)?.[1];
  if (!scanId || !report || typeof report !== "object") {
    throw new Error("Некорректный формат отчета сканирования");
  }
  const findRelatedReport = (reports) =>
    reports.find((reportName) => reportName.includes(scanId));
  const combinedReports = {
    json: filename,
    txt: findRelatedReport(reportLists.txt),
    docx: findRelatedReport(reportLists.word),
    md: findRelatedReport(reportLists.md),
  };

  return { ...report, combined_reports: combinedReports };
};

const Search = ({ language = "ru" }) => {
  const [activeMenu, setActiveMenu] = useState(false);
  const [activeScheduleScanner, setActiveScheduleScanner] = useState(false);
  const [btn, setBtn] = useState(false);
  const [viewerOpen, setViewerOpen] = useState(false);
  const [aiAnalysisOpen, setAIAnalysisOpen] = useState(false);
  const [aiAnalysisData, setAIAnalysisData] = useState({
    reportData: null,
    reportFilePath: null,
  });
  const [viewerData, setViewerData] = useState({
    filename: "",
    reportType: "",
  });
  const [reportLoadError, setReportLoadError] = useState("");

  // кастомные хуки для управления состоянием
  const {
    activeTools,
    setActiveTools,
    query,
    setQuery,
    loading,
    setLoading,
    scanProgress,
    setScanProgress,
    results,
    setResults,
    scanAborted,
    setScanAborted,
    allowInternal,
    setAllowInternal,
    expandedJsonTools,
    setExpandedJsonTools,
    abortControllerRef,
    scanIdRef,
    cancelScan,
  } = useScanState();

  const {
    wordReports,
    loadingReports,
    txtReports,
    loadingTxtReports,
    combinedReports,
    loadingCombined,
    combinedReportFilter,
    setCombinedReportFilter,
    fetchWordReports,
    fetchCombinedReports,
    fetchTxtReports,
  } = useReports();

  useEffect(() => {
    if (loading || loadingCombined || results || !combinedReports.json.length) {
      return undefined;
    }

    let active = true;
    const latestReport = combinedReports.json[0];
    loadSavedScanReport(latestReport, combinedReports)
      .then((report) => {
        if (active) setResults(report);
      })
      .catch((error) => {
        if (active) {
          setReportLoadError(error.message);
          console.error("Не удалось загрузить последний отчет сканирования:", error);
        }
      });

    return () => {
      active = false;
    };
  }, [combinedReports, loading, loadingCombined, results, setResults]);

  const selectCombinedReport = async (filename) => {
    try {
      setReportLoadError("");
      setResults(await loadSavedScanReport(filename, combinedReports));
    } catch (error) {
      setReportLoadError(error.message);
      console.error("Не удалось загрузить отчет сканирования:", error);
    }
  };

  // Основной обработчик отправки формы

  const handleSubmit = async (e, urlsList = null, targetType = "url") => {
    e.preventDefault();

    // Не отправлять запрос, если нет выбранных инструментов
    if (activeTools.length === 0) {
      alert("Выберите хотя бы один инструмент");
      return;
    }

    // Убедиться что urls это всегда массив, а не строка
    let urls;
    if (Array.isArray(urlsList)) {
      urls = urlsList;
    } else if (typeof urlsList === 'string' && urlsList.trim()) {
      urls = [urlsList];  // ✅ Обёрнуть строку в массив
    } else {
      urls = Array.isArray(query) ? query : [query];
    }

    if (!urls || urls.length === 0) {
      alert(
        language === "ru" ? "Пожалуйста, введите URL" : "Please enter a URL",
      );
      return;
    }

    try {
      const allResults = [];
      setLoading(true);
      setScanProgress(null);
      setResults(null);
      setReportLoadError("");
      setScanAborted(false);
      abortControllerRef.current = new AbortController();

      for (const url of urls) {
        if (!url || !url.trim()) continue;  // ✅ Добавил проверку на null/undefined

        try {
          const scanId = crypto.randomUUID();
          scanIdRef.current = scanId;
          const data = await scanService.runScan(
            url,
            activeTools,
            allowInternal,
            abortControllerRef.current.signal,
            scanId,
            setScanProgress,
          );

          if (!scanAborted) {
            allResults.push({ url, data, timestamp: new Date().toISOString() });
            setResults(allResults[0]?.data || null);
            await fetchWordReports();
            await fetchCombinedReports();
          }
        } catch (error) {
          if (error.name !== "AbortError") {
            allResults.push({
              url,
              error: error.message,
              timestamp: new Date().toISOString(),
            });
          }
        } finally {
          scanIdRef.current = null;
        }
      }

      if (allResults.length > 1 && !scanAborted) {
        alert(`Отсканировано ${allResults.length} сайтов`);
      }
    } catch (error) {
      if (error.name === "AbortError") {
        console.log("Сканирование отменено");
        return;
      }
      alert(`Ошибка: ${error.message}`);
      setResults(null);
    } finally {
      setLoading(false);
      abortControllerRef.current = null;
    }
  };

  // Вспомогательные функции для работы с отчетами
  const openReportViewer = (filename, reportType) => {
    setViewerData({ filename, reportType });
    setViewerOpen(true);
  };

  const closeReportViewer = () => {
    setViewerOpen(false);
    setViewerData({ filename: "", reportType: "" });
  };

  const openAIAnalysis = (reportData, reportFilePath = null) => {
    setAIAnalysisData({
      reportData,
      reportFilePath,
    });
    setAIAnalysisOpen(true);
  };

  const closeAIAnalysis = () => {
    setAIAnalysisOpen(false);
    setAIAnalysisData({ reportData: null, reportFilePath: null });
  };

  const downloadWordReport = async (filename) => {
    try {
      await reportService.downloadWordReport(filename);
    } catch (error) {
      console.error(
        language === "ru"
          ? "Ошибка при скачивании отчета:"
          : "Error downloading report:",
        error,
      );
      alert(
        language === "ru"
          ? "Ошибка при скачивании файла"
          : "Error downloading file",
      );
    }
  };

  const downloadCombinedReport = async (filename, reportType = "json") => {
    try {
      await reportService.downloadCombinedReport(filename, reportType);
    } catch (error) {
      console.error(
        language === "ru"
          ? "Ошибка при скачивании отчета:"
          : "Error downloading report:",
        error,
      );
      alert(
        language === "ru"
          ? "Ошибка при скачивании файла"
          : "Error downloading file",
      );
    }
  };

  const downloadContent = (content, filename, contentType) => {
    reportService.downloadContent(content, filename, contentType);
  };

  const downloadTxtReport = async (tool, filename) => {
    try {
      await reportService.downloadTxtReport(tool, filename);
    } catch (error) {
      console.error(
        language === "ru"
          ? "Ошибка при скачивании отчета:"
          : "Error downloading report:",
        error,
      );
      alert(
        language === "ru"
          ? "Ошибка при скачивании файла"
          : "Error downloading file",
      );
    }
  };

  const deleteWordReport = async (filename) => {
    if (
      !window.confirm(
        language === "ru"
          ? `Вы уверены, что хотите удалить ${filename}?`
          : `Are you sure you want to delete ${filename}?`,
      )
    ) {
      return;
    }

    try {
      await reportService.deleteWordReport(filename);
      await fetchWordReports();

      alert(
        language === "ru"
          ? "Отчет успешно удален"
          : "Report successfully deleted",
      );
    } catch (error) {
      console.error(
        language === "ru"
          ? "Ошибка при удалении отчета:"
          : "Error deleting report:",
        error,
      );
      alert(
        language === "ru" ? "Ошибка при удалении файла" : "Error deleting file",
      );
    }
  };

  const deleteCombinedReport = async (filename, reportType = "json") => {
    if (
      !window.confirm(
        language === "ru"
          ? `Вы уверены, что хотите удалить ${filename}?`
          : `Are you sure you want to delete ${filename}?`,
      )
    ) {
      return;
    }

    try {
      await reportService.deleteCombinedReport(filename, reportType);
      await fetchCombinedReports();

      alert(
        language === "ru"
          ? "Отчет успешно удален"
          : "Report successfully deleted",
      );
    } catch (error) {
      console.error(
        language === "ru"
          ? "Ошибка при удалении отчета:"
          : "Error deleting report:",
        error,
      );
      alert(
        language === "ru" ? "Ошибка при удалении файла" : "Error deleting file",
      );
    }
  };

  const deleteTxtReport = async (tool, filename) => {
    if (
      !window.confirm(
        language === "ru"
          ? `Вы уверены, что хотите удалить ${filename}?`
          : `Are you sure you want to delete ${filename}?`,
      )
    ) {
      return;
    }

    try {
      await reportService.deleteTxtReport(tool, filename);
      await fetchTxtReports();

      alert(
        language === "ru"
          ? "Отчет успешно удален"
          : "Report successfully deleted",
      );
    } catch (error) {
      console.error(
        language === "ru"
          ? "Ошибка при удалении отчета:"
          : "Error deleting report:",
        error,
      );
      alert(
        language === "ru" ? "Ошибка при удалении файла" : "Error deleting file",
      );
    }
  };

  const deleteAllWordReports = async () => {
    if (
      !window.confirm(
        language === "ru"
          ? "Вы уверены, что хотите удалить ВСЕ отчеты? Это действие необратимо!"
          : "Are you sure you want to delete ALL reports? This action is irreversible!",
      )
    ) {
      return;
    }

    try {
      await reportService.deleteAllWordReports();
      await fetchWordReports();

      alert(
        language === "ru"
          ? "Все отчеты успешно удалены"
          : "All reports successfully deleted",
      );
    } catch (error) {
      console.error(
        language === "ru"
          ? "Ошибка при удалении отчетов:"
          : "Error deleting reports:",
        error,
      );
      alert(
        language === "ru"
          ? "Ошибка при удалении файлов"
          : "Error deleting files",
      );
    }
  };

  const clearAllReports = async () => {
    if (
      !window.confirm(
        language === "ru"
          ? "Вы уверены? Это удалит ВСЕ отчеты (word, json, combined) навсегда!"
          : "Are you sure? This will delete ALL reports (word, json, combined) permanently!",
      )
    ) {
      return;
    }

    try {
      const data = await reportService.clearAllReports();
      await fetchWordReports();
      await fetchCombinedReports();
      await fetchTxtReports();

      alert(
        language === "ru"
          ? `Успешно удалено файлов: ${data.deleted}`
          : `Successfully deleted files: ${data.deleted}`,
      );
    } catch (error) {
      console.error(
        language === "ru"
          ? "Ошибка при очистке отчетов:"
          : "Error clearing reports:",
        error,
      );
      alert(
        language === "ru"
          ? "Ошибка при очистке отчетов"
          : "Error clearing reports",
      );
    }
  };

  // Функция рендеринга результатов сканера
  const renderScannerResults = (result) => {
    if (result.error) {
      return (
        <div className="error-message">
          {result.cancelled
            ? language === "ru"
              ? "⚠️ Сканирование отменено"
              : "⚠️ Scan cancelled"
            : `${language === "ru" ? "Ошибка" : "Error"}: ${result.error}`}
        </div>
      );
    }

    const report = result.report || {};
    const summary = result.summary || report.summary || {};
    const vulnerabilities = report.vulnerabilities || [];

    return (
      <div className="scanner-results">
        <div className="scanner-summary">
          <h5>
            {language === "ru" ? "Сводка сканирования:" : "Scan Summary:"}
          </h5>
          <p>
            <strong>{language === "ru" ? "Цель:" : "Target:"}</strong>{" "}
            {report.scan_info?.target ||
              (language === "ru" ? "Не указано" : "Not specified")}
          </p>
          <p>
            <strong>
              {language === "ru" ? "Дата сканирования:" : "Scan Date:"}
            </strong>{" "}
            {report.scan_info?.scan_date ||
              (language === "ru" ? "Не указано" : "Not specified")}
          </p>
          <p>
            <strong>
              {language === "ru"
                ? "Всего уязвимостей:"
                : "Total Vulnerabilities:"}
            </strong>{" "}
            {summary.total_vulnerabilities || 0}
          </p>
          <p>
            <strong style={{ color: "#ff4444" }}>
              {language === "ru" ? "Высокий риск:" : "High Risk:"}
            </strong>{" "}
            {summary.high || 0}
          </p>
          <p>
            <strong style={{ color: "#ffaa00" }}>
              {language === "ru" ? "Средний риск:" : "Medium Risk:"}
            </strong>{" "}
            {summary.medium || 0}
          </p>
          <p>
            <strong style={{ color: "#0099cc" }}>
              {language === "ru" ? "Низкий риск:" : "Low Risk:"}
            </strong>{" "}
            {summary.low || 0}
          </p>
        </div>

        {vulnerabilities.length > 0 ? (
          <div className="vulnerabilities-list">
            <h5>
              {language === "ru"
                ? "Найденные уязвимости:"
                : "Found Vulnerabilities:"}
            </h5>
            {vulnerabilities.map((vuln, index) => (
              <div
                key={index}
                className={`vulnerability-item severity-${vuln.severity?.toLowerCase()}`}
              >
                <div className="vulnerability-header">
                  <span className="vulnerability-type">{vuln.type}</span>
                  <span
                    className={`severity-badge severity-${vuln.severity?.toLowerCase()}`}
                  >
                    {vuln.severity}
                  </span>
                </div>
                <div className="vulnerability-details">
                  <p>
                    <strong>
                      {language === "ru" ? "Описание:" : "Description:"}
                    </strong>{" "}
                    {vuln.details}
                  </p>
                  <p>
                    <strong>
                      {language === "ru" ? "Рекомендации:" : "Recommendations:"}
                    </strong>{" "}
                    {vuln.recommendation}
                  </p>
                  {vuln.affected_url && (
                    <p>
                      <strong>
                        {language === "ru"
                          ? "Затронутый URL:"
                          : "Affected URL:"}
                      </strong>{" "}
                      {vuln.affected_url}
                    </p>
                  )}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="no-vulnerabilities">
            <p>
              {language === "ru"
                ? "✅ Уязвимостей не найдено!"
                : "✅ No vulnerabilities found!"}
            </p>
          </div>
        )}
      </div>
    );
  };

  // Функция рендеринга объединенных результатов
  const renderCombinedResults = (results) => {
    if (results.combined_reports && results.status !== "cancelled") {
      const toolsCount =
        results.tools_count || results.tools_executed?.length || 0;
      const scanId = results.scan_id || "unknown";

      return (
        <div className="combined-results">
          <CompletedScanCard
            results={{ ...results, tools_count: toolsCount, scan_id: scanId }}
            language={language}
            onDownloadReport={downloadCombinedReport}
            onDownloadContent={downloadContent}
          />

          {results.results &&
            Object.entries(results.results).map(([toolName, toolResult]) => {
              const isExpanded = expandedJsonTools[toolName] || false;

              return (
                <div
                  key={toolName}
                  className={`tool-result ${toolResult.status === "error" ? "error" : ""}`}
                >
                  <div className="tool-result-header">
                    <div className="tool-result-content">
                      <h5>
                        {toolName.toUpperCase()}
                        <span
                          className={`status-badge ${toolResult.status === "error" ? "error" : "success"}`}
                        >
                          {toolResult.status?.toUpperCase()}
                        </span>
                      </h5>

                      {toolResult.error ? (
                        <p className="error-message">❌ {toolResult.error}</p>
                      ) : (
                        <div>
                          {toolResult.technologies_found !== undefined && (
                            <p>
                              <strong>
                                {language === "ru"
                                  ? "🔍 Технологий обнаружено:"
                                  : "🔍 Technologies Found:"}
                              </strong>{" "}
                              {toolResult.technologies_found}
                            </p>
                          )}
                          {toolResult.count !== undefined && (
                            <p>
                              <strong>
                                {language === "ru"
                                  ? "📊 Находок:"
                                  : "📊 Findings:"}
                              </strong>{" "}
                              {toolResult.count}
                            </p>
                          )}
                          {toolResult.vulnerabilities?.length > 0 && (
                            <div style={{ marginTop: "8px" }}>
                              <p>
                                <strong>
                                  {language === "ru"
                                    ? "⚠️ Уязвимости:"
                                    : "⚠️ Vulnerabilities:"}
                                </strong>{" "}
                                {toolResult.vulnerabilities.length}
                              </p>
                              <div className="vulnerabilities-list">
                                {toolResult.vulnerabilities
                                  .slice(0, 3)
                                  .map((vuln, idx) => (
                                    <div key={idx}>
                                      • {vuln.type || "Unknown"}:{" "}
                                      {vuln.details?.substring(0, 50) || "N/A"}
                                      ...
                                    </div>
                                  ))}
                              </div>
                            </div>
                          )}
                        </div>
                      )}
                    </div>

                    <button
                      type="button"
                      onClick={() =>
                        setExpandedJsonTools((prev) => ({
                          ...prev,
                          [toolName]: !isExpanded,
                        }))
                      }
                      className={`json-button ${isExpanded ? "expanded" : ""}`}
                      title={
                        language === "ru"
                          ? "Показать/скрыть JSON"
                          : "Show/Hide JSON"
                      }
                    >
                      {isExpanded ? "▼ JSON" : "▶ JSON"}
                    </button>
                  </div>

                  {isExpanded && (
                    <div className="json-container">
                      <pre className="json-pre">
                        {JSON.stringify(toolResult, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              );
            })}
        </div>
      );
    }

    return null;
  };

  return (
    <section className="container__cyber">
      <div className={activeMenu ? "section__cyber active" : "section__cyber"}>
        <div className="menu__container">
          <div className={btn ? "menu__home active" : "menu__home"}>
            <button
              onClick={() => setBtn(!btn)}
              className={btn ? "menu__btn active" : "menu__btn"}
            >
              {btn
                ? language === "ru"
                  ? "закрыть"
                  : "close"
                : language === "ru"
                  ? "открыть"
                  : "open"}
            </button>
            <Tools activeTools={activeTools} setActiveTools={setActiveTools} />
          </div>
          <div className="btn__container">
            <div
              className={
                activeScheduleScanner
                  ? "schedule__scanner-btn active"
                  : "schedule__scanner-btn"
              }
              onClick={() => setActiveScheduleScanner(!activeScheduleScanner)}
            >
              <img className="btn__clock" src={Image} alt="" />
            </div>
            <ScheduleScanner
              activeScheduleScanner={activeScheduleScanner}
              setActiveScheduleScanner={setActiveScheduleScanner}
              activeTools={activeTools}
              setActiveTools={setActiveTools}
              query={query}
              setQuery={setQuery}
              allowInternal={allowInternal}
              setAllowInternal={setAllowInternal}
              language={language}
              onSchedule={(task) => {
                console.log(
                  language === "ru"
                    ? "Запланировано сканирование:"
                    : "Scan scheduled:",
                  task,
                );
                // Здесь можно добавить интеграцию с бэкендом
              }}
            />
            <button
              className={
                activeMenu ? "btn__menu-active active" : "btn__menu-active"
              }
              onClick={() => setActiveMenu(!activeMenu)}
            >
              <div className="line"></div>
              <div className="line"></div>
            </button>
          </div>
        </div>

        <div className="search__container">
          <div className="container__reports">
            <SearchForm
              query={query}
              setQuery={setQuery}
              loading={loading}
              handleSubmit={handleSubmit}
              cancelScan={cancelScan}
              activeTools={activeTools}
              allowInternal={allowInternal}
              setAllowInternal={setAllowInternal}
              language={language}
            />

            <ReportsPanel
              wordReports={wordReports}
              loadingReports={loadingReports}
              txtReports={txtReports}
              loadingTxtReports={loadingTxtReports}
              combinedReports={combinedReports}
              loadingCombined={loadingCombined}
              combinedReportFilter={combinedReportFilter}
              setCombinedReportFilter={setCombinedReportFilter}
              fetchWordReports={fetchWordReports}
              fetchCombinedReports={fetchCombinedReports}
              fetchTxtReports={fetchTxtReports}
              downloadWordReport={downloadWordReport}
              downloadCombinedReport={downloadCombinedReport}
              downloadTxtReport={downloadTxtReport}
              deleteWordReport={deleteWordReport}
              deleteCombinedReport={deleteCombinedReport}
              deleteTxtReport={deleteTxtReport}
              deleteAllWordReports={deleteAllWordReports}
              clearAllReports={clearAllReports}
              openReportViewer={openReportViewer}
              onSelectCombinedReport={selectCombinedReport}
              openAIAnalysis={openAIAnalysis}
              language={language}
            />
          </div>

          {loading ? (
            <ScanningInfo
              activeTools={activeTools}
              query={query}
              cancelScan={cancelScan}
              scanProgress={scanProgress}
              language={language}
            />
          ) : (
            <>
              {reportLoadError && (
                <p role="alert" className="error-message">{reportLoadError}</p>
              )}
              <ResultsSection
                results={results}
                scanAborted={scanAborted}
                expandedJsonTools={expandedJsonTools}
                setExpandedJsonTools={setExpandedJsonTools}
                renderScannerResults={renderScannerResults}
                renderCombinedResults={renderCombinedResults}
                language={language}
              />
            </>
          )}
        </div>
      </div>

      {viewerOpen && (
        <ReportViewer
          filename={viewerData.filename}
          reportType={viewerData.reportType}
          onClose={closeReportViewer}
          language={language}
        />
      )}

      {aiAnalysisOpen && (
        <AIAnalysis
          reportData={aiAnalysisData.reportData}
          reportFilePath={aiAnalysisData.reportFilePath}
          onClose={closeAIAnalysis}
          language={language}
        />
      )}
    </section>
  );
};

export default Search;