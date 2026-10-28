import React from 'react';

const getStatusLabel = (status, language) => {
    const labels = {
        success: language === "ru" ? "Успешно" : "Succeeded",
        no_findings: language === "ru" ? "Находок нет" : "No findings",
        error: language === "ru" ? "Ошибка" : "Error",
        timeout: language === "ru" ? "Тайм-аут" : "Timed out",
        cancelled: language === "ru" ? "Отменено" : "Cancelled",
    };
    return labels[status] || (language === "ru" ? "Неизвестный статус" : "Unknown status");
};

const ResultsSection = ({ 
    results, 
    scanAborted, 
    expandedJsonTools,
    setExpandedJsonTools,
    renderScannerResults,

    renderCombinedResults,
    language = "ru"
}) => {
    if (!results) return null;

    return (
        <div className="results">
            <div className="results-header">

                <h3>{language === "ru" ? 'Результаты сканирования:' : 'Scan Results:'}</h3>
            </div>
            
            {scanAborted && (
                <div className="scan-aborted-message">

                    {language === "ru" ? '⚠️ Сканирование было отменено' : '⚠️ Scan was cancelled'}
                </div>
            )}
            
            {results.combined_reports &&
            Object.keys(results.combined_reports).length > 0 &&
            results.status !== 'cancelled' ? (
                renderCombinedResults(results, expandedJsonTools, setExpandedJsonTools)
            ) : results.results ? (
                <>
                    <p className={`scan-status scan-status--${results.status}`}>
                        {language === "ru" ? "Общий статус: " : "Overall status: "}
                        {getStatusLabel(results.status, language)}
                    </p>
                    {results.error && (
                        <div className="error-message" role="alert">
                            {language === "ru" ? "Ошибка сканирования: " : "Scan error: "}
                            {results.error}
                        </div>
                    )}
                    {Object.entries(results.results).map(([toolName, toolResult]) => (
                        <div key={toolName} className="result-section">
                            <div className="result-header">
                                <h4>{toolName.toUpperCase()}</h4>
                                <span className={`scan-status scan-status--${toolResult.status}`}>
                                    {getStatusLabel(toolResult.status, language)}
                                </span>
                            </div>
                            {toolResult.error && (
                                <div className={toolResult.status === "error" || toolResult.status === "timeout" ? "error-message" : ""}>
                                    {toolResult.error}
                                </div>
                            )}
                            <pre className="results__pre">
                                {JSON.stringify(toolResult, null, 2)}
                            </pre>
                        </div>
                    ))}
                </>
            ) : (
                Object.entries(results).map(([toolName, toolResult]) => (
                    <div key={toolName} className="result-section">
                        <div className="result-header">
                            <h4>{toolName.toUpperCase()}</h4>
                            {toolResult.cancelled && (

                                <span className="cancelled-badge">{language === "ru" ? 'Отменено' : 'Cancelled'}</span>
                            )}
                        </div>
                        
                        {toolName === 'scanner' ? (
                            renderScannerResults(toolResult)
                        ) : toolResult.error ? (
                            <div className="error-message">

                                {toolResult.cancelled 
                                    ? (language === "ru" ? '⚠️ Сканирование отменено' : '⚠️ Scan cancelled') 
                                    : `${language === "ru" ? 'Ошибка' : 'Error'}: ${toolResult.error}`}
                            </div>
                        ) : toolResult.output ? (
                            <pre className="results__pre">
                                {toolResult.output}
                            </pre>
                        ) : (
                            <pre className="results__pre">
                                {JSON.stringify(toolResult, null, 2)}
                            </pre>
                        )}
                    </div>
                ))
            )}
        </div>
    );
};

export default ResultsSection;
