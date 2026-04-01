import React from 'react';

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
            
            {results.status === 'success' && results.combined_reports ? (
                renderCombinedResults(results, expandedJsonTools, setExpandedJsonTools)
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
