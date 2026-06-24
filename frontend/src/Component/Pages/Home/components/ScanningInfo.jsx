import React, { useState, useEffect } from 'react';
import './ScanningInfo.scss';

const ScanningInfo = ({ 
    activeTools, 
    query, 
    cancelScan, 
    language = "ru" 
}) => {
    const [elapsedTime, setElapsedTime] = useState(0);

    useEffect(() => {
        const interval = setInterval(() => {
            setElapsedTime(prev => prev + 1);
        }, 1000);

        return () => clearInterval(interval);
    }, []);

    const formatTime = (seconds) => {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        const secs = seconds % 60;

        if (hours > 0) {
            return `${hours}ч ${minutes}м ${secs}с`;
        } else if (minutes > 0) {
            return `${minutes}м ${secs}с`;
        } else {
            return `${secs}с`;
        }
    };

    const toolsList = Array.isArray(activeTools) 
        ? activeTools 
        : (typeof activeTools === 'string' ? activeTools.split(',').map(t => t.trim()) : []);

    return (
        <div className="scanning-info">
            <div className="scanning-info__container">
                {/* Заголовок */}
                <div className="scanning-info__header">
                    <div className="scanning-status">
                        <span className="pulse-dot"></span>
                        <h3>
                            {language === "ru" 
                                ? "🔍 Сканирование в процессе" 
                                : "🔍 Scanning in progress"}
                        </h3>
                    </div>
                </div>

                {/* Информация о сканировании */}
                <div className="scanning-info__content">
                    {/* Целевой URL */}
                    <div className="info-block">
                        <label>{language === "ru" ? "📍 Целевой адрес:" : "📍 Target:"}</label>
                        <div className="info-value target-url">
                            <span title={query}>{query}</span>
                        </div>
                    </div>

                    {/* Время сканирования */}
                    <div className="info-block">
                        <label>{language === "ru" ? "⏱️ Время сканирования:" : "⏱️ Elapsed Time:"}</label>
                        <div className="info-value timer">
                            {formatTime(elapsedTime)}
                        </div>
                    </div>

                    {/* Выбранные инструменты */}
                    <div className="info-block">
                        <label>
                            {language === "ru" 
                                ? `🛠️ Активные инструменты (${toolsList.length}):` 
                                : `🛠️ Active Tools (${toolsList.length}):`}
                        </label>
                        <div className="tools-list">
                            {toolsList.map((tool, index) => (
                                <div key={index} className="tool-item">
                                    <span className="tool-name">{tool}</span>
                                    <span className="tool-status">
                                        <span className="spinner"></span>
                                        {language === "ru" ? "в процессе" : "processing"}
                                    </span>
                                </div>
                            ))}
                        </div>
                    </div>

                    {/* Прогресс бар */}
                    <div className="info-block">
                        <label>{language === "ru" ? "📊 Прогресс:" : "📊 Progress:"}</label>
                        <div className="progress-bar">
                            <div className="progress-fill"></div>
                        </div>
                    </div>

                    {/* Советы */}
                    <div className="scanning-tips">
                        <p>
                            {language === "ru" 
                                ? "💡 Пожалуйста, не закрывайте страницу во время сканирования"
                                : "💡 Please don't close this page during scanning"}
                        </p>
                    </div>
                </div>

                {/* Кнопка отмены */}
                <div className="scanning-info__footer">
                    <button 
                        className="cancel-scan-btn"
                        onClick={cancelScan}
                    >
                        {language === "ru" ? "⛔ Отменить сканирование" : "⛔ Cancel Scan"}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default ScanningInfo;
