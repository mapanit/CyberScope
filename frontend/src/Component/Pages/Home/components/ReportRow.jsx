import React from 'react';

const ReportRow = ({ report, icon = '', bgColor, btnColor = '#0066cc', onDownload, onDelete, onView, onAnalyzeAI, reportType = 'json' }) => {
    const hoverColor = btnColor === '#0066cc' ? '#0052a3' : (btnColor === '#00cc00' ? '#009900' : '#0052a3');
    
    // Обработка как объекта {filename, size, created} так и строки
    const filename = typeof report === 'string' ? report : report?.filename || report;
    const size = typeof report === 'object' && report?.size ? (report.size / 1024).toFixed(2) + ' KB' : '';
    const created = typeof report === 'object' && report?.created ? new Date(report.created * 1000).toLocaleDateString() : '';
    
    return (
        <div 
            style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '8px',
                backgroundColor: bgColor,
                borderRadius: '4px',
                fontSize: '12px',
                overflow: 'hidden',
                color: 'black'
            }}
        >
            <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={filename}>
                    {icon} {filename}
                </span>
                {size && (
                    <span style={{ fontSize: '10px', color: '#666', marginTop: '2px' }}>
                        {size} {created && `• ${created}`}
                    </span>
                )}
            </div>
            <div style={{ display: 'flex', gap: '4px', marginLeft: '8px' }}>
                {onView && (reportType === 'json' || reportType === 'txt_report') && (
                    <button
                        type="button"
                        onClick={() => onView(filename, reportType)}
                        style={{
                            padding: '4px 8px',
                            backgroundColor: '#9966ff',
                            color: 'white',
                            border: 'none',
                            borderRadius: '3px',
                            cursor: 'pointer',
                            fontSize: '11px',
                            whiteSpace: 'nowrap',
                            flexShrink: 0
                        }}
                        onMouseOver={(e) => e.target.style.backgroundColor = '#7744cc'}
                        onMouseOut={(e) => e.target.style.backgroundColor = '#9966ff'}
                        title="Просмотреть отчет"
                    >
                        👁️
                    </button>
                )}
                {onAnalyzeAI && reportType === 'json' && (
                    <button
                        type="button"
                        onClick={() => onAnalyzeAI(filename)}
                        style={{
                            padding: '4px 8px',
                            backgroundColor: '#667eea',
                            color: 'white',
                            border: 'none',
                            borderRadius: '3px',
                            cursor: 'pointer',
                            fontSize: '11px',
                            whiteSpace: 'nowrap',
                            flexShrink: 0
                        }}
                        onMouseOver={(e) => e.target.style.backgroundColor = '#764ba2'}
                        onMouseOut={(e) => e.target.style.backgroundColor = '#667eea'}
                        title="Анализировать с AI"
                    >
                        🤖
                    </button>
                )}
                <button
                    type="button"
                    onClick={onDownload}
                    style={{
                        padding: '4px 8px',
                        backgroundColor: btnColor,
                        color: 'white',
                        border: 'none',
                        borderRadius: '3px',
                        cursor: 'pointer',
                        fontSize: '11px',
                        whiteSpace: 'nowrap',
                        flexShrink: 0
                    }}
                    onMouseOver={(e) => e.target.style.backgroundColor = hoverColor}
                    onMouseOut={(e) => e.target.style.backgroundColor = btnColor}
                    title="Скачать отчет"
                >
                    ↓
                </button>
                <button
                    type="button"
                    onClick={onDelete}
                    style={{
                        padding: '4px 8px',
                        backgroundColor: '#cc3333',
                        color: 'white',
                        border: 'none',
                        borderRadius: '3px',
                        cursor: 'pointer',
                        fontSize: '11px',
                        whiteSpace: 'nowrap',
                        flexShrink: 0
                    }}
                    onMouseOver={(e) => e.target.style.backgroundColor = '#990000'}
                    onMouseOut={(e) => e.target.style.backgroundColor = '#cc3333'}
                    title="Удалить отчет"
                >
                    🗑️
                </button>
            </div>
        </div>
    );
};

export default ReportRow;