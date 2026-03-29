import React from 'react';
import { NavLink } from 'react-router-dom';
import ReportRow from './ReportRow';

const ReportsPanel = ({
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
    downloadWordReport,
    downloadCombinedReport,
    downloadTxtReport,
    deleteWordReport,
    deleteCombinedReport,
    deleteTxtReport,
    deleteAllWordReports,
    clearAllReports
}) => {
    return (
        <div className="install__info">
            <NavLink to="/help" className="help__link" activeClassName="help__link">Помощник</NavLink>
            
            <div style={{ marginTop: '16px', paddingTop: '16px', borderTop: '1px solid #e0e0e0' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                    <h6 className='h6'>🛠️ Управление отчетами</h6>
                    <button
                        type="button"
                        onClick={clearAllReports}
                        style={{
                            padding: '6px 12px',
                            backgroundColor: '#ff6b6b',
                            color: 'white',
                            border: 'none',
                            borderRadius: '3px',
                            cursor: 'pointer',
                            fontSize: '12px',
                            fontWeight: 'bold'
                        }}
                        onMouseOver={(e) => e.target.style.backgroundColor = '#ee5a5a'}
                        onMouseOut={(e) => e.target.style.backgroundColor = '#ff6b6b'}
                        title="Очистить ВСЕ отчеты (word, json, combined)"
                    >
                        🗑️ Очистить ВСЕ отчеты
                    </button>
                </div>
                <p style={{ fontSize: '11px', color: '#98a2b3', margin: '0' }}>
                    Удалит все сохраненные отчеты (JSON, Word и объединённые)
                </p>
            </div>
            
            {wordReports.length > 0 && (
                <div className="word-reports-list" style={{ marginTop: '16px', paddingTop: '16px', borderTop: '1px solid #e0e0e0', overflowY: 'overlay'}}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                        <h6 className='h6'>Сохраненные отчеты</h6>
                        <div style={{ display: 'flex', gap: '8px' }}>
                            <button
                                type="button"
                                onClick={fetchWordReports}
                                disabled={loadingReports}
                                style={{
                                    padding: '4px 8px',
                                    backgroundColor: '#0066cc',
                                    color: 'white',
                                    border: 'none',
                                    borderRadius: '3px',
                                    cursor: loadingReports ? 'not-allowed' : 'pointer',
                                    fontSize: '11px',
                                    opacity: loadingReports ? 0.6 : 1
                                }}
                                onMouseOver={(e) => !loadingReports && (e.target.style.backgroundColor = '#0052a3')}
                                onMouseOut={(e) => !loadingReports && (e.target.style.backgroundColor = '#0066cc')}
                                title="Обновить список отчетов"
                            >
                                ⟳
                            </button>
                            <button
                                type="button"
                                onClick={deleteAllWordReports}
                                style={{
                                    padding: '4px 8px',
                                    backgroundColor: '#cc3333',
                                    color: 'white',
                                    border: 'none',
                                    borderRadius: '3px',
                                    cursor: 'pointer',
                                    fontSize: '11px'
                                }}
                                onMouseOver={(e) => e.target.style.backgroundColor = '#990000'}
                                onMouseOut={(e) => e.target.style.backgroundColor = '#cc3333'}
                                title="Удалить все отчеты"
                            >
                                🗑️ Удалить всё
                            </button>
                        </div>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                        {wordReports.map((report, index) => (
                            <ReportRow 
                                key={index}
                                report={report}
                                bgColor="#f5f5f5"
                                onDownload={() => downloadWordReport(report)}
                                onDelete={() => deleteWordReport(report)}
                            />
                        ))}
                    </div>
                </div>
            )}
            
            {Object.keys(txtReports).length > 0 && (
                <div className="txt-reports-list" style={{ marginTop: '16px', paddingTop: '16px', borderTop: '1px solid #e0e0e0', overflowY: 'overlay'}}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                        <h6 className='h6'>📝 TXT Отчеты инструментов</h6>
                        <button
                            type="button"
                            onClick={fetchTxtReports}
                            disabled={loadingTxtReports}
                            style={{
                                padding: '4px 8px',
                                backgroundColor: '#0066cc',
                                color: 'white',
                                border: 'none',
                                borderRadius: '3px',
                                cursor: loadingTxtReports ? 'not-allowed' : 'pointer',
                                fontSize: '11px',
                                opacity: loadingTxtReports ? 0.6 : 1
                            }}
                            onMouseOver={(e) => !loadingTxtReports && (e.target.style.backgroundColor = '#0052a3')}
                            onMouseOut={(e) => !loadingTxtReports && (e.target.style.backgroundColor = '#0066cc')}
                            title="Обновить список отчетов"
                        >
                            ⟳
                        </button>
                    </div>
                    {Object.entries(txtReports).map(([tool, files]) => (
                        files.length > 0 && (
                            <div key={tool} style={{ marginBottom: '12px' }}>
                                <h6 style={{ fontSize: '12px', color: '#666', marginBottom: '8px', textTransform: 'uppercase' }}>{tool}:</h6>
                                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                                    {files.map((filename, index) => (
                                        <div
                                            key={`${tool}-${index}`}
                                            style={{
                                                display: 'flex',
                                                justifyContent: 'space-between',
                                                alignItems: 'center',
                                                padding: '8px 12px',
                                                backgroundColor: '#f0f0f0',
                                                borderRadius: '3px',
                                                fontSize: '12px',
                                                border: '1px solid #ddd'
                                            }}
                                        >
                                            <span title={filename} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                                                {filename}
                                            </span>
                                            <div style={{ display: 'flex', gap: '6px', marginLeft: '8px' }}>
                                                <button
                                                    type="button"
                                                    onClick={() => downloadTxtReport(tool, filename)}
                                                    style={{
                                                        padding: '4px 8px',
                                                        backgroundColor: '#0066cc',
                                                        color: 'white',
                                                        border: 'none',
                                                        borderRadius: '3px',
                                                        cursor: 'pointer',
                                                        fontSize: '11px',
                                                        whiteSpace: 'nowrap'
                                                    }}
                                                    onMouseOver={(e) => e.target.style.backgroundColor = '#0052a3'}
                                                    onMouseOut={(e) => e.target.style.backgroundColor = '#0066cc'}
                                                    title="Скачать"
                                                >
                                                    ⬇️
                                                </button>
                                                <button
                                                    type="button"
                                                    onClick={() => deleteTxtReport(tool, filename)}
                                                    style={{
                                                        padding: '4px 8px',
                                                        backgroundColor: '#cc3333',
                                                        color: 'white',
                                                        border: 'none',
                                                        borderRadius: '3px',
                                                        cursor: 'pointer',
                                                        fontSize: '11px',
                                                        whiteSpace: 'nowrap'
                                                    }}
                                                    onMouseOver={(e) => e.target.style.backgroundColor = '#990000'}
                                                    onMouseOut={(e) => e.target.style.backgroundColor = '#cc3333'}
                                                    title="Удалить"
                                                >
                                                    🗑️
                                                </button>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>
                        )
                    ))}
                </div>
            )}
            
            {(combinedReports.json.length > 0 || combinedReports.txt.length > 0 || combinedReports.word.length > 0) && (
                <div className="word-reports-list" style={{ marginTop: '16px', paddingTop: '16px', borderTop: '1px solid #e0e0e0' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                        <h6 className='h6'>📊 Скомпилированные отчеты</h6>
                        <button
                            type="button"
                            onClick={fetchCombinedReports}
                            disabled={loadingCombined}
                            style={{
                                padding: '4px 8px',
                                backgroundColor: '#0066cc',
                                color: 'white',
                                border: 'none',
                                borderRadius: '3px',
                                cursor: loadingCombined ? 'not-allowed' : 'pointer',
                                fontSize: '11px',
                                opacity: loadingCombined ? 0.6 : 1
                            }}
                            onMouseOver={(e) => !loadingCombined && (e.target.style.backgroundColor = '#0052a3')}
                            onMouseOut={(e) => !loadingCombined && (e.target.style.backgroundColor = '#0066cc')}
                            title="Обновить список отчетов"
                        >
                            ⟳
                        </button>
                    </div>
                    
                    <div style={{ display: 'flex', gap: '8px', marginBottom: '12px', flexWrap: 'wrap' }}>
                        <button
                            type="button"
                            onClick={() => setCombinedReportFilter('all')}
                            style={{
                                padding: '6px 12px',
                                backgroundColor: combinedReportFilter === 'all' ? '#0066cc' : '#e0e0e0',
                                color: combinedReportFilter === 'all' ? 'white' : '#333',
                                border: 'none',
                                borderRadius: '3px',
                                cursor: 'pointer',
                                fontSize: '11px',
                                fontWeight: combinedReportFilter === 'all' ? 'bold' : 'normal',
                            }}
                            onMouseOver={(e) => combinedReportFilter !== 'all' && (e.target.style.backgroundColor = '#d0d0d0')}
                            onMouseOut={(e) => combinedReportFilter !== 'all' && (e.target.style.backgroundColor = '#e0e0e0')}
                            title="Показать все отчеты"
                        >
                            Все ({combinedReports.json.length + combinedReports.txt.length + combinedReports.word.length})
                        </button>
                        <button
                            type="button"
                            onClick={() => setCombinedReportFilter('json')}
                            style={{
                                padding: '6px 12px',
                                backgroundColor: combinedReportFilter === 'json' ? '#0066cc' : '#e8f4fd',
                                color: combinedReportFilter === 'json' ? 'white' : '#0066cc',
                                border: '1px solid #0066cc',
                                borderRadius: '3px',
                                cursor: 'pointer',
                                fontSize: '11px',
                            }}
                            onMouseOver={(e) => combinedReportFilter !== 'json' && (e.target.style.backgroundColor = '#d0e6f7')}
                            onMouseOut={(e) => combinedReportFilter !== 'json' && (e.target.style.backgroundColor = '#e8f4fd')}
                            title="Показать только JSON отчеты"
                        >
                            📄 JSON ({combinedReports.json.length})
                        </button>
                        <button
                            type="button"
                            onClick={() => setCombinedReportFilter('txt')}
                            style={{
                                padding: '6px 12px',
                                backgroundColor: combinedReportFilter === 'txt' ? '#ff9900' : '#fff4e6',
                                color: combinedReportFilter === 'txt' ? 'white' : '#ff9900',
                                border: '1px solid #ff9900',
                                borderRadius: '3px',
                                cursor: 'pointer',
                                fontSize: '11px',
                            }}
                            onMouseOver={(e) => combinedReportFilter !== 'txt' && (e.target.style.backgroundColor = '#ffe6cc')}
                            onMouseOut={(e) => combinedReportFilter !== 'txt' && (e.target.style.backgroundColor = '#fff4e6')}
                            title="Показать только TXT отчеты"
                        >
                            📝 TXT ({combinedReports.txt.length})
                        </button>
                        <button
                            type="button"
                            onClick={() => setCombinedReportFilter('word')}
                            style={{
                                padding: '6px 12px',
                                backgroundColor: combinedReportFilter === 'word' ? '#00cc00' : '#e8f8e8',
                                color: combinedReportFilter === 'word' ? 'white' : '#00cc00',
                                border: '1px solid #00cc00',
                                borderRadius: '3px',
                                cursor: 'pointer',
                                fontSize: '11px',
                            }}
                            onMouseOver={(e) => combinedReportFilter !== 'word' && (e.target.style.backgroundColor = '#d0f5d0')}
                            onMouseOut={(e) => combinedReportFilter !== 'word' && (e.target.style.backgroundColor = '#e8f8e8')}
                            title="Показать только WORD отчеты"
                        >
                            📝 WORD ({combinedReports.word.length})
                        </button>
                    </div>
                    
                    {(combinedReportFilter === 'all' || combinedReportFilter === 'json') && combinedReports.json.length > 0 && (
                        <div style={{ marginBottom: '12px' }}>
                            <h6 style={{ fontSize: '12px', color: '#666', marginBottom: '8px' }}>JSON отчеты:</h6>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                {combinedReports.json.map((report, index) => (
                                    <ReportRow 
                                        key={`json-${index}`} 
                                        report={report} 
                                        icon="📄"
                                        bgColor="#e8f4fd"
                                        btnColor="#0066cc"
                                        onDownload={() => downloadCombinedReport(report, 'json')}
                                        onDelete={() => deleteCombinedReport(report, 'json')}
                                    />
                                ))}
                            </div>
                        </div>
                    )}
                    
                    {(combinedReportFilter === 'all' || combinedReportFilter === 'txt') && combinedReports.txt.length > 0 && (
                        <div style={{ marginBottom: '12px' }}>
                            <h6 style={{ fontSize: '12px', color: '#666', marginBottom: '8px' }}>TXT отчеты:</h6>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                {combinedReports.txt.map((report, index) => (
                                    <ReportRow 
                                        key={`txt-${index}`} 
                                        report={report} 
                                        icon="📝"
                                        bgColor="#fff4e6"
                                        btnColor="#ff9900"
                                        onDownload={() => downloadCombinedReport(report, 'txt')}
                                        onDelete={() => deleteCombinedReport(report, 'txt')}
                                    />
                                ))}
                            </div>
                        </div>
                    )}
                    
                    {(combinedReportFilter === 'all' || combinedReportFilter === 'word') && combinedReports.word.length > 0 && (
                        <div>
                            <h6 style={{ fontSize: '12px', color: '#666', marginBottom: '8px' }}>WORD отчеты:</h6>
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                {combinedReports.word.map((report, index) => (
                                    <ReportRow 
                                        key={`word-${index}`} 
                                        report={report} 
                                        icon="📝"
                                        bgColor="#e8f8e8"
                                        btnColor="#00cc00"
                                        onDownload={() => downloadCombinedReport(report, 'word')}
                                        onDelete={() => deleteCombinedReport(report, 'word')}
                                    />
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

export default ReportsPanel;
