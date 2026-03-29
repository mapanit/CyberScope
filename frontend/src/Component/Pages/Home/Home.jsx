import React, { useState } from 'react';
import './Home.scss';
import Tools from './Tools/Tools';
import SearchForm from './components/SearchForm';
import ReportsPanel from './components/ReportsPanel';
import ResultsSection from './components/ResultsSection';
import ScheduleScanner from './ScheduleScanner/ScheduleScanner';
import Image from "../../../Img/clock.png";
import { useScanState } from './hooks/useScanState';
import { useReports } from './hooks/useReports';
import { scanService } from './services/scanService';
import { reportService } from './services/reportService';

const Search = () => {
    const [activeMenu, setActiveMenu] = useState(false);
    const [activeScheduleScanner, setActiveScheduleScanner] = useState(false);
    const [btn, setBtn] = useState(false);

    // кастомные хуки для управления состоянием
    const {
        activeTools, setActiveTools,
        query, setQuery,
        loading, setLoading,
        results, setResults,
        scanAborted, setScanAborted,
        allowInternal, setAllowInternal,
        expandedJsonTools, setExpandedJsonTools,
        abortControllerRef,
        cancelScan
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
        fetchTxtReports
    } = useReports();

    // Основной обработчик отправки формы
    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            scanService.validateInput(query, activeTools);

            setLoading(true);
            setResults(null);
            setScanAborted(false);
            abortControllerRef.current = new AbortController();

            const data = await scanService.runScan(
                query,
                activeTools,
                allowInternal,
                abortControllerRef.current.signal
            );

            if (!scanAborted) {
                setResults(data);
                await fetchWordReports();
                await fetchCombinedReports();
                console.log('Сканирование завершено:', data);
            }

        } catch (error) {
            if (error.name === 'AbortError') {
                console.log('Сканирование отменено');
                return;
            }
            console.error('Ошибка при сканировании:', error);
            alert(`Ошибка: ${error.message}`);
            setResults(null);
        } finally {
            setLoading(false);
            abortControllerRef.current = null;
        }
    };

    // Вспомогательные функции для работы с отчетами
    const downloadWordReport = async (filename) => {
        try {
            await reportService.downloadWordReport(filename);
        } catch (error) {
            console.error('Ошибка при скачивании отчета:', error);
            alert('Ошибка при скачивании файла');
        }
    };

    const downloadCombinedReport = async (filename, reportType = 'json') => {
        try {
            await reportService.downloadCombinedReport(filename, reportType);
        } catch (error) {
            console.error('Ошибка при скачивании отчета:', error);
            alert('Ошибка при скачивании файла');
        }
    };

    const downloadTxtReport = async (tool, filename) => {
        try {
            await reportService.downloadTxtReport(tool, filename);
        } catch (error) {
            console.error('Ошибка при скачивании отчета:', error);
            alert('Ошибка при скачивании файла');
        }
    };

    const deleteWordReport = async (filename) => {
        if (!window.confirm(`Вы уверены, что хотите удалить ${filename}?`)) {
            return;
        }

        try {
            await reportService.deleteWordReport(filename);
            await fetchWordReports();
            alert('Отчет успешно удален');
        } catch (error) {
            console.error('Ошибка при удалении отчета:', error);
            alert('Ошибка при удалении файла');
        }
    };

    const deleteCombinedReport = async (filename, reportType = 'json') => {
        if (!window.confirm(`Вы уверены, что хотите удалить ${filename}?`)) {
            return;
        }

        try {
            await reportService.deleteCombinedReport(filename, reportType);
            await fetchCombinedReports();
            alert('Отчет успешно удален');
        } catch (error) {
            console.error('Ошибка при удалении отчета:', error);
            alert('Ошибка при удалении файла');
        }
    };

    const deleteTxtReport = async (tool, filename) => {
        if (!window.confirm(`Вы уверены, что хотите удалить ${filename}?`)) {
            return;
        }

        try {
            await reportService.deleteTxtReport(tool, filename);
            await fetchTxtReports();
            alert('Отчет успешно удален');
        } catch (error) {
            console.error('Ошибка при удалении отчета:', error);
            alert('Ошибка при удалении файла');
        }
    };

    const deleteAllWordReports = async () => {
        if (!window.confirm('Вы уверены, что хотите удалить ВСЕ отчеты? Это действие необратимо!')) {
            return;
        }

        try {
            await reportService.deleteAllWordReports();
            await fetchWordReports();
            alert('Все отчеты успешно удалены');
        } catch (error) {
            console.error('Ошибка при удалении отчетов:', error);
            alert('Ошибка при удалении файлов');
        }
    };

    const clearAllReports = async () => {
        if (!window.confirm('Вы уверены? Это удалит ВСЕ отчеты (word, json, combined) навсегда!')) {
            return;
        }

        try {
            const data = await reportService.clearAllReports();
            await fetchWordReports();
            await fetchCombinedReports();
            await fetchTxtReports();
            alert(`Успешно удалено файлов: ${data.deleted}`);
        } catch (error) {
            console.error('Ошибка при очистке отчетов:', error);
            alert('Ошибка при очистке отчетов');
        }
    };

    // Функция рендеринга результатов сканера
    const renderScannerResults = (result) => {
        if (result.error) {
            return (
                <div className="error-message">
                    {result.cancelled ? '⚠️ Сканирование отменено' : `Ошибка: ${result.error}`}
                </div>
            );
        }

        const report = result.report || {};
        const summary = result.summary || report.summary || {};
        const vulnerabilities = report.vulnerabilities || [];

        return (
            <div className="scanner-results">
                <div className="scanner-summary">
                    <h5>Сводка сканирования:</h5>
                    <p><strong>Цель:</strong> {report.scan_info?.target || 'Не указано'}</p>
                    <p><strong>Дата сканирования:</strong> {report.scan_info?.scan_date || 'Не указано'}</p>
                    <p><strong>Всего уязвимостей:</strong> {summary.total_vulnerabilities || 0}</p>
                    <p><strong style={{ color: '#ff4444' }}>Высокий риск:</strong> {summary.high || 0}</p>
                    <p><strong style={{ color: '#ffaa00' }}>Средний риск:</strong> {summary.medium || 0}</p>
                    <p><strong style={{ color: '#0099cc' }}>Низкий риск:</strong> {summary.low || 0}</p>
                </div>

                {vulnerabilities.length > 0 ? (
                    <div className="vulnerabilities-list">
                        <h5>Найденные уязвимости:</h5>
                        {vulnerabilities.map((vuln, index) => (
                            <div key={index} className={`vulnerability-item severity-${vuln.severity?.toLowerCase()}`}>
                                <div className="vulnerability-header">
                                    <span className="vulnerability-type">{vuln.type}</span>
                                    <span className={`severity-badge severity-${vuln.severity?.toLowerCase()}`}>
                                        {vuln.severity}
                                    </span>
                                </div>
                                <div className="vulnerability-details">
                                    <p><strong>Описание:</strong> {vuln.details}</p>
                                    <p><strong>Рекомендации:</strong> {vuln.recommendation}</p>
                                    {vuln.affected_url && <p><strong>Затронутый URL:</strong> {vuln.affected_url}</p>}
                                </div>
                            </div>
                        ))}
                    </div>
                ) : (
                    <div className="no-vulnerabilities">
                        <p>✅ Уязвимостей не найдено!</p>
                    </div>
                )}
            </div>
        );
    };

    // Функция рендеринга объединенных результатов
    const renderCombinedResults = (results) => {
        if (results.status === 'success' && results.combined_reports) {
            const toolsCount = results.tools_count || results.tools_executed?.length || 0;
            const scanId = results.scan_id || 'unknown';

            return (
                <div className="combined-results">
                    <div className="combined-summary">
                        <h3>📊 Объединенный отчет сканирования</h3>
                        <div className="summary-info">
                            <p><strong>ID сканирования:</strong> {scanId}</p>
                            <p><strong>Целевой адрес:</strong> {results.target}</p>
                            <p><strong>Используемых инструментов:</strong> {toolsCount}</p>
                            <p><strong>Инструменты:</strong> {results.tools_executed?.join(', ') || 'N/A'}</p>
                        </div>

                        {results.combined_reports && (
                            <div className="combined-reports-links" style={{ marginTop: '12px', paddingTop: '12px', borderTop: '1px solid #e0e0e0' }}>
                                <h5>Скачать отчеты:</h5>
                                {results.combined_reports.json && (
                                    <button
                                        type="button"
                                        onClick={() => downloadCombinedReport(
                                            results.combined_reports.json.split('/').pop(),
                                            'json'
                                        )}
                                        style={{
                                            padding: '6px 12px',
                                            backgroundColor: '#0066cc',
                                            color: 'white',
                                            border: 'none',
                                            borderRadius: '3px',
                                            cursor: 'pointer',
                                            fontSize: '12px',
                                            marginRight: '8px',
                                            marginBottom: '8px'
                                        }}
                                        onMouseOver={(e) => e.target.style.backgroundColor = '#0052a3'}
                                        onMouseOut={(e) => e.target.style.backgroundColor = '#0066cc'}
                                    >
                                        📄 Скачать JSON отчет
                                    </button>
                                )}
                                {results.combined_reports.docx && (
                                    <button
                                        type="button"
                                        onClick={() => downloadCombinedReport(
                                            results.combined_reports.docx.split('/').pop(),
                                            'word'
                                        )}
                                        style={{
                                            padding: '6px 12px',
                                            backgroundColor: '#28a745',
                                            color: 'white',
                                            border: 'none',
                                            borderRadius: '3px',
                                            cursor: 'pointer',
                                            fontSize: '12px',
                                            marginBottom: '8px'
                                        }}
                                        onMouseOver={(e) => e.target.style.backgroundColor = '#218838'}
                                        onMouseOut={(e) => e.target.style.backgroundColor = '#28a745'}
                                    >
                                        📘 Скачать Word отчет
                                    </button>
                                )}
                                {results.combined_reports.txt && (
                                    <button
                                        type="button"
                                        onClick={() => downloadCombinedReport(
                                            results.combined_reports.txt.split('/').pop(),
                                            'txt'
                                        )}
                                        style={{
                                            padding: '6px 12px',
                                            backgroundColor: '#ea9330',
                                            color: 'white',
                                            border: 'none',
                                            borderRadius: '3px',
                                            cursor: 'pointer',
                                            fontSize: '12px',
                                            marginBottom: '8px'
                                        }}
                                        onMouseOver={(e) => e.target.style.backgroundColor = '#ea9330'}
                                        onMouseOut={(e) => e.target.style.backgroundColor = '#ea9330'}
                                    >
                                        📘 Скачать TXT отчет
                                    </button>
                                )}
                            </div>
                        )}
                    </div>

                    {results.results && Object.entries(results.results).map(([toolName, toolResult]) => {
                        const isExpanded = expandedJsonTools[toolName] || false;

                        return (
                            <div key={toolName} className={`tool-result ${toolResult.status === 'error' ? 'error' : ''}`}>
                                <div className="tool-result-header">
                                    <div className="tool-result-content">
                                        <h5>
                                            {toolName.toUpperCase()}
                                            <span className={`status-badge ${toolResult.status === 'error' ? 'error' : 'success'}`}>
                                                {toolResult.status?.toUpperCase()}
                                            </span>
                                        </h5>

                                        {toolResult.error ? (
                                            <p className="error-message">❌ {toolResult.error}</p>
                                        ) : (
                                            <div>
                                                {toolResult.technologies_found !== undefined && (
                                                    <p><strong>🔍 Технологий обнаружено:</strong> {toolResult.technologies_found}</p>
                                                )}
                                                {toolResult.count !== undefined && (
                                                    <p><strong>📊 Находок:</strong> {toolResult.count}</p>
                                                )}
                                                {toolResult.vulnerabilities?.length > 0 && (
                                                    <div style={{ marginTop: '8px' }}>
                                                        <p><strong>⚠️ Уязвимости:</strong> {toolResult.vulnerabilities.length}</p>
                                                        <div className="vulnerabilities-list">
                                                            {toolResult.vulnerabilities.slice(0, 3).map((vuln, idx) => (
                                                                <div key={idx}>
                                                                    • {vuln.type || 'Unknown'}: {vuln.details?.substring(0, 50) || 'N/A'}...
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
                                        onClick={() => setExpandedJsonTools(prev => ({
                                            ...prev,
                                            [toolName]: !isExpanded
                                        }))}
                                        className={`json-button ${isExpanded ? 'expanded' : ''}`}
                                        title="Показать/скрыть JSON"
                                    >
                                        {isExpanded ? '▼ JSON' : '▶ JSON'}
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
        <main className={activeMenu ? "main__cyber active" : "main__cyber"}>
            <div className="container">
                <div className="menu__container">
                    <div className={btn ? "menu__home active" : "menu__home"}>
                        <button
                            onClick={() => setBtn(!btn)}
                            className={btn ? "menu__btn active" : "menu__btn"}
                        >
                            {btn ? 'закрыть' : 'открыть'}
                        </button>
                        <Tools activeTools={activeTools} setActiveTools={setActiveTools} />
                    </div>
                    <div className="btn__container">
                        <div
                            className={activeScheduleScanner ? "schedule__scanner-btn active" : "schedule__scanner-btn"}
                            onClick={() => setActiveScheduleScanner(!activeScheduleScanner)}
                        >
                            <img className='btn__clock' src={Image} alt="" />
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
                            onSchedule={(task) => {
                                console.log('Запланировано сканирование:', task);
                                // Здесь можно добавить интеграцию с бэкендом
                            }}
                        />
                        <button
                            className={activeMenu ? "btn__menu-active active" : "btn__menu-active"}
                            onClick={() => setActiveMenu(!activeMenu)}>
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
                        />
                    </div>

                    <ResultsSection
                        results={results}
                        scanAborted={scanAborted}
                        expandedJsonTools={expandedJsonTools}
                        setExpandedJsonTools={setExpandedJsonTools}
                        renderScannerResults={renderScannerResults}
                        renderCombinedResults={renderCombinedResults}
                    />
                </div>
            </div>
        </main>
    );
};

export default Search;
