import React, { useState, useEffect } from "react";
import "./AIAnalysis.scss";
import aiAnalysisService from "../../services/aiAnalysisService";

const AIAnalysis = ({ reportData, reportFilePath, onClose, language = "ru" }) => {
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [lmStudioStatus, setLmStudioStatus] = useState(null);
  const [expandedSections, setExpandedSections] = useState({
    analysis: true,
    problems: false,
    recommendations: false,
    steps: false,
    verification: false,
    priority: false,
  });

  useEffect(() => {
    // Проверяем статус LM Studio при открытии компонента
    checkLMStudioStatus();
  }, []);

  const checkLMStudioStatus = async () => {
    try {
      const status = await aiAnalysisService.checkLMStudioStatus();
      setLmStudioStatus(status);
      if (status.status !== "online") {
        setError(
          language === "ru"
            ? "⚠️ LM Studio не подключен. Убедитесь что LM Studio запущен на http://127.0.0.1:1234"
            : "⚠️ LM Studio is not connected. Make sure it's running on http://127.0.0.1:1234"
        );
      }
    } catch (err) {
      console.error("Error checking LM Studio status:", err);
    }
  };

  const performAnalysis = async () => {
    setLoading(true);
    setError(null);
    try {
      let result;
      
      if (reportFilePath) {
        // Анализируем по пути к файлу
        result = await aiAnalysisService.analyzeReport(reportFilePath);
      } else if (reportData) {
        // Анализируем по данным отчета
        result = await aiAnalysisService.analyzeReportData(reportData);
      } else {
        throw new Error(
          language === "ru"
            ? "Нет данных отчета для анализа"
            : "No report data to analyze"
        );
      }

      setAnalysis(result);
      setExpandedSections((prev) => ({
        ...prev,
        analysis: true,
      }));
    } catch (err) {
      console.error("Error during analysis:", err);
      setError(
        err.response?.data?.detail ||
          err.message ||
          (language === "ru"
            ? "Ошибка при анализе отчета"
            : "Error analyzing report")
      );
    } finally {
      setLoading(false);
    }
  };

  const toggleSection = (section) => {
    setExpandedSections((prev) => ({
      ...prev,
      [section]: !prev[section],
    }));
  };

  const parseAnalysisText = (text) => {
    // Разбиваем текст по секциям
    const sections = {
      analysis: "",
      problems: "",
      recommendations: "",
      steps: "",
      verification: "",
      priority: "",
    };

    const lines = text.split("\n");
    let currentSection = null;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (line.includes("АНАЛИЗ") || line.includes("ANALYSIS")) {
        currentSection = "analysis";
      } else if (
        line.includes("КРИТИЧНЫЕ ПРОБЛЕМЫ") ||
        line.includes("CRITICAL ISSUES")
      ) {
        currentSection = "problems";
      } else if (
        line.includes("РЕКОМЕНДАЦИИ") ||
        line.includes("RECOMMENDATIONS")
      ) {
        currentSection = "recommendations";
      } else if (
        line.includes("ШАГИ") ||
        line.includes("STEPS") ||
        line.includes("ДЕЙСТВИЯ")
      ) {
        currentSection = "steps";
      } else if (
        line.includes("ПРОВЕРКА") ||
        line.includes("VERIFICATION")
      ) {
        currentSection = "verification";
      } else if (line.includes("ПРИОРИТЕТ") || line.includes("PRIORITY")) {
        currentSection = "priority";
      } else if (currentSection && line.trim()) {
        sections[currentSection] += line + "\n";
      }
    }

    return sections;
  };

  const renderSection = (title, content, sectionKey) => {
    if (!content || !content.trim()) return null;

    const isExpanded = expandedSections[sectionKey];

    return (
      <div key={sectionKey} className="analysis-section">
        <div
          className="section-header"
          onClick={() => toggleSection(sectionKey)}
        >
          <span className="section-title">{title}</span>
          <span className={`toggle-icon ${isExpanded ? "expanded" : ""}`}>
            ▼
          </span>
        </div>
        {isExpanded && (
          <div className="section-content">
            <div className="content-text">
              {content.split("\n").map((line, idx) => {
                if (!line.trim()) return null;
                // Выделяем нумерованные пункты
                if (/^\d+\./.test(line.trim())) {
                  return (
                    <div key={idx} className="numbered-item">
                      {line}
                    </div>
                  );
                }
                // Выделяем маркированные пункты
                if (line.trim().startsWith("•") || line.trim().startsWith("-")) {
                  return (
                    <div key={idx} className="bullet-item">
                      {line}
                    </div>
                  );
                }
                return (
                  <p key={idx} className="content-paragraph">
                    {line}
                  </p>
                );
              })}
            </div>
          </div>
        )}
      </div>
    );
  };

  const sections = analysis
    ? parseAnalysisText(analysis.analysis?.analysis || "")
    : {};

  return (
    <div className="ai-analysis-container">
      <div className="ai-analysis-modal">
        <div className="modal-header">
          <h2>
            {language === "ru"
              ? "🤖 Анализ отчета с AI"
              : "🤖 AI Report Analysis"}
          </h2>
          <button className="close-btn" onClick={onClose}>
            ✕
          </button>
        </div>

        <div className="modal-body">
          {/* Статус LM Studio */}
          <div className={`lm-studio-status ${lmStudioStatus?.status}`}>
            <span className="status-dot"></span>
            <span className="status-text">
              {lmStudioStatus?.message ||
                (language === "ru"
                  ? "Проверка статуса LM Studio..."
                  : "Checking LM Studio status...")}
            </span>
          </div>

          {/* Кнопка анализа */}
          {!analysis && (
            <div className="analysis-prompt">
              <p>
                {language === "ru"
                  ? "Нажмите кнопку ниже, чтобы получить детальный анализ отчета с рекомендациями и шагами по исправлению найденных проблем."
                  : "Click the button below to get detailed analysis of the report with recommendations and remediation steps."}
              </p>
              <button
                className="analyze-btn"
                onClick={performAnalysis}
                disabled={loading || lmStudioStatus?.status !== "online"}
              >
                {loading ? (
                  <>
                    <span className="spinner"></span>
                    {language === "ru"
                      ? "Анализирую отчет..."
                      : "Analyzing report..."}
                  </>
                ) : (
                  <>
                    {language === "ru"
                      ? "🚀 Запустить анализ AI"
                      : "🚀 Start AI Analysis"}
                  </>
                )}
              </button>
            </div>
          )}

          {/* Ошибки */}
          {error && (
            <div className="error-message">
              <span className="error-icon">⚠️</span>
              <div className="error-content">
                <p>{error}</p>
                <button
                  className="retry-btn"
                  onClick={checkLMStudioStatus}
                >
                  {language === "ru"
                    ? "Повторить проверку"
                    : "Retry Check"}
                </button>
              </div>
            </div>
          )}

          {/* Результаты анализа */}
          {analysis && (
            <div className="analysis-results">
              {renderSection(
                language === "ru" ? "📋 Анализ" : "📋 Analysis",
                sections.analysis,
                "analysis"
              )}
              {renderSection(
                language === "ru" ? "⚠️ Критичные проблемы" : "⚠️ Critical Issues",
                sections.problems,
                "problems"
              )}
              {renderSection(
                language === "ru" ? "📋 Рекомендации" : "📋 Recommendations",
                sections.recommendations,
                "recommendations"
              )}
              {renderSection(
                language === "ru" ? "🔧 Шаги для исправления" : "🔧 Remediation Steps",
                sections.steps,
                "steps"
              )}
              {renderSection(
                language === "ru" ? "✅ Проверка" : "✅ Verification",
                sections.verification,
                "verification"
              )}
              {renderSection(
                language === "ru" ? "📊 Приоритет" : "📊 Priority",
                sections.priority,
                "priority"
              )}

              <div className="analysis-meta">
                <p className="meta-info">
                  {language === "ru" ? "Модель: " : "Model: "}
                  <span>{analysis.analysis?.model || "LM Studio Local AI"}</span>
                </p>
                <p className="meta-info">
                  {language === "ru" ? "Время анализа: " : "Analysis Time: "}
                  <span>
                    {new Date(analysis.analysis?.timestamp).toLocaleString()}
                  </span>
                </p>
              </div>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button className="close-modal-btn" onClick={onClose}>
            {language === "ru" ? "Закрыть" : "Close"}
          </button>
          {analysis && (
            <button className="new-analysis-btn" onClick={performAnalysis}>
              {language === "ru"
                ? "🔄 Новый анализ"
                : "🔄 New Analysis"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default AIAnalysis;
