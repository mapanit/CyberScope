import React, { useState } from 'react';
import './Home.scss';
import Tools from './Tools/Tools';
import SearchForm from './components/SearchForm';
import ReportsPanel from './components/ReportsPanel';
import ResultsSection from './components/ResultsSection';
import ReportViewer from './components/ReportViewer/ReportViewer';
import ScheduleScanner from './ScheduleScanner/ScheduleScanner';
import Image from "../../../Img/clock.png";
import { useScanState } from './hooks/useScanState';
import { useReports } from './hooks/useReports';
import { scanService } from './services/scanService';
import { reportService } from './services/reportService';


const Search = ({ language = "ru" }) => {
    const [activeMenu, setActiveMenu] = useState(false);
    const [activeScheduleScanner, setActiveScheduleScanner] = useState(false);
    const [btn, setBtn] = useState(false);
    const [viewerOpen, setViewerOpen] = useState(false);
    const [viewerData, setViewerData] = useState({ filename: '', reportType: '' });

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
    const handleSubmit = async (e, urlsList = null) => {
        e.preventDefault();
        
        // Используем переданный список URL'ов или query
        const urls = urlsList || (Array.isArray(query) ? query : [query]);
        
        if (!urls || urls.length === 0) {
            alert(language === "ru" ? 'Пожалуйста, введите URL' : 'Please enter a URL');
            return;
        }

        try {
            // Сканируем все URL'ы
            const allResults = [];
            
            for (const url of urls) {
                if (!url.trim()) continue;
                
                scanService.validateInput(url, activeTools);
                setLoading(true);
                setResults(null);
                setScanAborted(false);
                abortControllerRef.current = new AbortController();

                try {
                    const data = await scanService.runScan(
                        url,
                        activeTools,
                        allowInternal,
                        abortControllerRef.current.signal
                    );

                    if (!scanAborted) {
                        allResults.push({
                            url,
                            data,
                            timestamp: new Date().toISOString()
                        });
                    }
                } catch (error) {
                    if (error.name !== 'AbortError') {
                        allResults.push({
                            url,
                            error: error.message,
                            timestamp: new Date().toISOString()
                        });
                    }
                }
            }

            if (allResults.length > 0 && !scanAborted) {
                // Показываем результаты первого сканирования
                setResults(allResults[0].data || null);
                await fetchWordReports();
                await fetchCombinedReports();

                console.log(language === "ru" ? 'Сканирование завершено:' : 'Scan completed:', allResults);
                
                // Если было несколько URL'ов, показываем уведомление
                if (allResults.length > 1) {
                    alert(language === "ru" 
                        ? `Отсканировано ${allResults.length} сайтов` 
                        : `Scanned ${allResults.length} websites`
                    );
                }
            }

        } catch (error) {
            if (error.name === 'AbortError') {
                console.log(language === "ru" ? 'Сканирование отменено' : 'Scan cancelled');
                return;
            }
            console.error(language === "ru" ? 'Ошибка при сканировании:' : 'Scan error:', error);
            alert(`${language === "ru" ? 'Ошибка' : 'Error'}: ${error.message}`);

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
        setViewerData({ filename: '', reportType: '' });
    };

    const downloadWordReport = async (filename) => {
        try {
            await reportService.downloadWordReport(filename);
        } catch (error) {

            console.error(language === "ru" ? 'Ошибка при скачивании отчета:' : 'Error downloading report:', error);
            alert(language === "ru" ? 'Ошибка при скачивании файла' : 'Error downloading file');
        }
    };

    const downloadCombinedReport = async (filename, reportType = 'json') => {
        try {
            await reportService.downloadCombinedReport(filename, reportType);
        } catch (error) {

            console.error(language === "ru" ? 'Ошибка при скачивании отчета:' : 'Error downloading report:', error);
            alert(language === "ru" ? 'Ошибка при скачивании файла' : 'Error downloading file');
        }
    };

    const downloadTxtReport = async (tool, filename) => {
        try {
            await reportService.downloadTxtReport(tool, filename);
        } catch (error) {

            console.error(language === "ru" ? 'Ошибка при скачивании отчета:' : 'Error downloading report:', error);
            alert(language === "ru" ? 'Ошибка при скачивании файла' : 'Error downloading file');
        }
    };

    const deleteWordReport = async (filename) => {

        if (!window.confirm(language === "ru" ? `Вы уверены, что хотите удалить ${filename}?` : `Are you sure you want to delete ${filename}?`)) {
            return;
        }

        try {
            await reportService.deleteWordReport(filename);
            await fetchWordReports();

            alert(language === "ru" ? 'Отчет успешно удален' : 'Report successfully deleted');
        } catch (error) {
            console.error(language === "ru" ? 'Ошибка при удалении отчета:' : 'Error deleting report:', error);
            alert(language === "ru" ? 'Ошибка при удалении файла' : 'Error deleting file');
        }
    };

    const deleteCombinedReport = async (filename, reportType = 'json') => {

        if (!window.confirm(language === "ru" ? `Вы уверены, что хотите удалить ${filename}?` : `Are you sure you want to delete ${filename}?`)) {
            return;
        }

        try {
            await reportService.deleteCombinedReport(filename, reportType);
            await fetchCombinedReports();

            alert(language === "ru" ? 'Отчет успешно удален' : 'Report successfully deleted');
        } catch (error) {
            console.error(language === "ru" ? 'Ошибка при удалении отчета:' : 'Error deleting report:', error);
            alert(language === "ru" ? 'Ошибка при удалении файла' : 'Error deleting file');
        }
    };

    const deleteTxtReport = async (tool, filename) => {

        if (!window.confirm(language === "ru" ? `Вы уверены, что хотите удалить ${filename}?` : `Are you sure you want to delete ${filename}?`)) {
            return;
        }

        try {
            await reportService.deleteTxtReport(tool, filename);
            await fetchTxtReports();

            alert(language === "ru" ? 'Отчет успешно удален' : 'Report successfully deleted');
        } catch (error) {
            console.error(language === "ru" ? 'Ошибка при удалении отчета:' : 'Error deleting report:', error);
            alert(language === "ru" ? 'Ошибка при удалении файла' : 'Error deleting file');
        }
    };

    const deleteAllWordReports = async () => {

        if (!window.confirm(language === "ru" ? 'Вы уверены, что хотите удалить ВСЕ отчеты? Это действие необратимо!' : 'Are you sure you want to delete ALL reports? This action is irreversible!')) {
            return;
        }

        try {
            await reportService.deleteAllWordReports();
            await fetchWordReports();

            alert(language === "ru" ? 'Все отчеты успешно удалены' : 'All reports successfully deleted');
        } catch (error) {
            console.error(language === "ru" ? 'Ошибка при удалении отчетов:' : 'Error deleting reports:', error);
            alert(language === "ru" ? 'Ошибка при удалении файлов' : 'Error deleting files');
        }
    };

    const clearAllReports = async () => {

        if (!window.confirm(language === "ru" ? 'Вы уверены? Это удалит ВСЕ отчеты (word, json, combined) навсегда!' : 'Are you sure? This will delete ALL reports (word, json, combined) permanently!')) {
            return;
        }

        try {
            const data = await reportService.clearAllReports();
            await fetchWordReports();
            await fetchCombinedReports();
            await fetchTxtReports();

            alert(language === "ru" ? `Успешно удалено файлов: ${data.deleted}` : `Successfully deleted files: ${data.deleted}`);
        } catch (error) {
            console.error(language === "ru" ? 'Ошибка при очистке отчетов:' : 'Error clearing reports:', error);
            alert(language === "ru" ? 'Ошибка при очистке отчетов' : 'Error clearing reports');
        }
    };

    // Функция рендеринга результатов сканера
    const renderScannerResults = (result) => {
        if (result.error) {
            return (
                <div className="error-message">
                    {result.cancelled 
                        ? (language === "ru" ? '⚠️ Сканирование отменено' : '⚠️ Scan cancelled') 
                        : `${language === "ru" ? 'Ошибка' : 'Error'}: ${result.error}`}
                </div>
            );
        }

        const report = result.report || {};
        const summary = result.summary || report.summary || {};
        const vulnerabilities = report.vulnerabilities || [];

        return (
            <div className="scanner-results">
                <div className="scanner-summary">

                    <h5>{language === "ru" ? 'Сводка сканирования:' : 'Scan Summary:'}</h5>
                    <p><strong>{language === "ru" ? 'Цель:' : 'Target:'}</strong> {report.scan_info?.target || (language === "ru" ? 'Не указано' : 'Not specified')}</p>
                    <p><strong>{language === "ru" ? 'Дата сканирования:' : 'Scan Date:'}</strong> {report.scan_info?.scan_date || (language === "ru" ? 'Не указано' : 'Not specified')}</p>
                    <p><strong>{language === "ru" ? 'Всего уязвимостей:' : 'Total Vulnerabilities:'}</strong> {summary.total_vulnerabilities || 0}</p>
                    <p><strong style={{ color: '#ff4444' }}>{language === "ru" ? 'Высокий риск:' : 'High Risk:'}</strong> {summary.high || 0}</p>
                    <p><strong style={{ color: '#ffaa00' }}>{language === "ru" ? 'Средний риск:' : 'Medium Risk:'}</strong> {summary.medium || 0}</p>
                    <p><strong style={{ color: '#0099cc' }}>{language === "ru" ? 'Низкий риск:' : 'Low Risk:'}</strong> {summary.low || 0}</p>
                </div>

                {vulnerabilities.length > 0 ? (
                    <div className="vulnerabilities-list">

                        <h5>{language === "ru" ? 'Найденные уязвимости:' : 'Found Vulnerabilities:'}</h5>
                        {vulnerabilities.map((vuln, index) => (
                            <div key={index} className={`vulnerability-item severity-${vuln.severity?.toLowerCase()}`}>
                                <div className="vulnerability-header">
                                    <span className="vulnerability-type">{vuln.type}</span>
                                    <span className={`severity-badge severity-${vuln.severity?.toLowerCase()}`}>
                                        {vuln.severity}
                                    </span>
                                </div>
                                <div className="vulnerability-details">

                                    <p><strong>{language === "ru" ? 'Описание:' : 'Description:'}</strong> {vuln.details}</p>
                                    <p><strong>{language === "ru" ? 'Рекомендации:' : 'Recommendations:'}</strong> {vuln.recommendation}</p>
                                    {vuln.affected_url && <p><strong>{language === "ru" ? 'Затронутый URL:' : 'Affected URL:'}</strong> {vuln.affected_url}</p>}
                                </div>
                            </div>
                        ))}
                    </div>
                ) : (
                    <div className="no-vulnerabilities">

                        <p>{language === "ru" ? '✅ Уязвимостей не найдено!' : '✅ No vulnerabilities found!'}</p>
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
                        <h3>{language === "ru" ? '📊 Объединенный отчет сканирования' : '📊 Combined Scan Report'}</h3>
                        <div className="summary-info">
                            <p><strong>{language === "ru" ? 'ID сканирования:' : 'Scan ID:'}</strong> {scanId}</p>
                            <p><strong>{language === "ru" ? 'Целевой адрес:' : 'Target Address:'}</strong> {results.target}</p>
                            <p><strong>{language === "ru" ? 'Используемых инструментов:' : 'Tools Used:'}</strong> {toolsCount}</p>
                            <p><strong>{language === "ru" ? 'Инструменты:' : 'Tools:'}</strong> {results.tools_executed?.join(', ') || 'N/A'}</p>
                        </div>
                        {results.combined_reports && (
                            <div className="combined-reports-links" style={{ marginTop: '12px', paddingTop: '12px', borderTop: '1px solid #e0e0e0' }}>
                                <h5>{language === "ru" ? 'Скачать отчеты:' : 'Download Reports:'}</h5>
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

                                        {language === "ru" ? '📄 Скачать JSON отчет' : '📄 Download JSON Report'}
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

                                        {language === "ru" ? '📘 Скачать Word отчет' : '📘 Download Word Report'}
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

                                        {language === "ru" ? '📘 Скачать TXT отчет' : '📘 Download TXT Report'}
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

                                                    <p><strong>{language === "ru" ? '🔍 Технологий обнаружено:' : '🔍 Technologies Found:'}</strong> {toolResult.technologies_found}</p>
                                                )}
                                                {toolResult.count !== undefined && (
                                                    <p><strong>{language === "ru" ? '📊 Находок:' : '📊 Findings:'}</strong> {toolResult.count}</p>
                                                )}
                                                {toolResult.vulnerabilities?.length > 0 && (
                                                    <div style={{ marginTop: '8px' }}>
                                                        <p><strong>{language === "ru" ? '⚠️ Уязвимости:' : '⚠️ Vulnerabilities:'}</strong> {toolResult.vulnerabilities.length}</p>
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
                                        title={language === "ru" ? 'Показать/скрыть JSON' : 'Show/Hide JSON'}
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
        <section className='container__cyber'>
            <div className={activeMenu ? "section__cyber active" : "section__cyber"}>
                <div className="menu__container">
                    <div className={btn ? "menu__home active" : "menu__home"}>
                        <button
                            onClick={() => setBtn(!btn)}
                            className={btn ? "menu__btn active" : "menu__btn"}
                        >

                            {btn ? (language === "ru" ? 'закрыть' : 'close') : (language === "ru" ? 'открыть' : 'open')}
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

                            language={language}
                            onSchedule={(task) => {
                                console.log(language === "ru" ? 'Запланировано сканирование:' : 'Scan scheduled:', task);
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

                            language={language}
                        />
                    </div>

                    <ResultsSection
                        results={results}
                        scanAborted={scanAborted}
                        expandedJsonTools={expandedJsonTools}
                        setExpandedJsonTools={setExpandedJsonTools}
                        renderScannerResults={renderScannerResults}
                        renderCombinedResults={renderCombinedResults}

                        language={language}
                    />
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
        </section>
    );
};

export default Search;