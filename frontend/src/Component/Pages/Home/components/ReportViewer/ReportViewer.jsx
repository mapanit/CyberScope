import React, { useState, useEffect } from 'react';
import './ReportViewer.scss';
import { reportService } from '../../services/reportService';

const ReportViewer = ({ filename, reportType, onClose, language = 'ru' }) => {
    const [content, setContent] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [parsedData, setParsedData] = useState(null);

    useEffect(() => {
        loadReportContent();
    }, [filename, reportType]);

    const loadReportContent = async () => {
        try {
            setLoading(true);
            setError(null);
            const data = await reportService.getReportContent(filename, reportType);
            setContent(data);

            // Если JSON, попытаемся распарсить для красивого отображения
            if (reportType === 'json') {
                try {
                    const parsed = JSON.parse(data);
                    setParsedData(parsed);
                } catch (e) {
                    // Если не парсится, оставляем как текст
                    setParsedData(null);
                }
            }
        } catch (err) {
            setError(err.message);
            console.error('Ошибка при загрузке отчета:', err);
        } finally {
            setLoading(false);
        }
    };

    const renderJsonContent = (data, depth = 0) => {
        if (data === null || data === undefined) return <span className="json-null">null</span>;

        if (typeof data === 'string') {
            return <span className="json-string">"{data}"</span>;
        }

        if (typeof data === 'number') {
            return <span className="json-number">{data}</span>;
        }

        if (typeof data === 'boolean') {
            return <span className="json-boolean">{String(data)}</span>;
        }

        if (Array.isArray(data)) {
            return (
                <div className="json-array">
                    <span className="json-bracket">[</span>
                    <div className="json-content" style={{ marginLeft: '20px' }}>
                        {data.map((item, idx) => (
                            <div key={idx} className="json-item">
                                <span className="json-index">{idx}:</span>
                                {renderJsonContent(item, depth + 1)}
                                {idx < data.length - 1 && <span className="json-comma">,</span>}
                            </div>
                        ))}
                    </div>
                    <span className="json-bracket">]</span>
                </div>
            );
        }

        if (typeof data === 'object') {
            const keys = Object.keys(data);
            return (
                <div className="json-object">
                    <span className="json-bracket">{'{'}</span>
                    <div className="json-content" style={{ marginLeft: '20px' }}>
                        {keys.map((key, idx) => (
                            <div key={idx} className="json-item">
                                <span className="json-key">"{key}"</span>
                                <span className="json-colon">:</span>
                                {renderJsonContent(data[key], depth + 1)}
                                {idx < keys.length - 1 && <span className="json-comma">,</span>}
                            </div>
                        ))}
                    </div>
                    <span className="json-bracket">{'}'}</span>
                </div>
            );
        }

        return <span>{String(data)}</span>;
    };

    return (
        <div className="report-viewer-overlay" onClick={onClose}>
            <div className="report-viewer-modal" onClick={(e) => e.stopPropagation()}>
                <div className="report-viewer-header">
                    <h3>
                        {language === 'ru' ? '📄 Просмотр отчета' : '📄 View Report'}
                        {' '}
                        <span className="filename">{filename}</span>
                    </h3>
                    <button className="close-btn" onClick={onClose}>✕</button>
                </div>

                <div className="report-viewer-content">
                    {loading ? (
                        <div className="loading">
                            <p>{language === 'ru' ? '⏳ Загрузка...' : '⏳ Loading...'}</p>
                        </div>
                    ) : error ? (
                        <div className="error">
                            <p>{language === 'ru' ? '❌ Ошибка при загрузке:' : '❌ Error loading:'} {error}</p>
                        </div>
                    ) : (
                        <div className="content-wrapper">
                            {reportType === 'json' && parsedData ? (
                                <div className="json-viewer">
                                    {renderJsonContent(parsedData)}
                                </div>
                            ) : (
                                <pre className="text-viewer">{content}</pre>
                            )}
                        </div>
                    )}
                </div>

                <div className="report-viewer-footer">
                    <button 
                        className="btn-copy"
                        onClick={() => {
                            navigator.clipboard.writeText(content);
                            alert(language === 'ru' ? '✅ Скопировано в буфер обмена' : '✅ Copied to clipboard');
                        }}
                    >
                        {language === 'ru' ? '📋 Копировать' : '📋 Copy'}
                    </button>
                    <button className="btn-close" onClick={onClose}>
                        {language === 'ru' ? 'Закрыть' : 'Close'}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default ReportViewer;
