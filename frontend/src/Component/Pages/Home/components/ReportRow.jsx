import React from 'react';

const ReportRow = ({ report, icon = '', bgColor, btnColor = '#0066cc', onDownload, onDelete }) => {
    const hoverColor = btnColor === '#0066cc' ? '#0052a3' : (btnColor === '#00cc00' ? '#009900' : '#0052a3');
    
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
            <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={report}>
                {icon} {report}
            </span>
            <div style={{ display: 'flex', gap: '4px', marginLeft: '8px' }}>
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
