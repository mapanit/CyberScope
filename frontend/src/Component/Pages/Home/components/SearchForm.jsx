import React from 'react';

const SearchForm = ({ 
    query, 
    setQuery, 
    loading, 
    handleSubmit, 
    cancelScan, 
    activeTools,
    allowInternal,

    setAllowInternal,
    language = "ru"
}) => {
    return (
        <form className="form__search" onSubmit={handleSubmit}>
            <label htmlFor="search-input">{language === "ru" ? 'Поиск' : 'Search'}</label>
            <div className="form__row">
                <input
                    id="search-input"
                    type="text"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}

                    placeholder={language === "ru" ? "Адрес сайта (пример: https://example.com)" : "Website URL (example: https://example.com)"}
                    aria-label={language === "ru" ? "Поисковый запрос" : "Search query"}
                    disabled={loading}
                />
                <div className="form-buttons">
                    <button 
                        className='form__btn' 
                        type="submit" 

                        aria-label={language === "ru" ? "Найти" : "Start"} 
                        disabled={loading}
                    >
                        {loading ? (language === "ru" ? 'Сканирование...' : 'Scanning...') : (language === "ru" ? 'начать' : 'Start')}
                    </button>
                    {loading && (
                        <button 
                            type="button"
                            className='cancel-btn'
                            onClick={() => {
                                // Вызываем отмену и подавляем любые unhandled rejections
                                const result = cancelScan();
                                if (result && typeof result.catch === 'function') {
                                    result.catch(err => {
                                        console.warn('Предупреждение при отмене:', err);
                                    });
                                }
                            }}

                            aria-label={language === "ru" ? "Отменить сканирование" : "Cancel scan"}
                        >
                            {language === "ru" ? 'Отменить' : 'Cancel'}
                        </button>
                    )}
                </div>
            </div>
            {activeTools.length > 0 && (
                <p style={{ marginTop: '8px', color: '#98a2b3', fontSize: '12px' }}>

                    {language === "ru" ? 'Выбранные инструменты:' : 'Selected tools:'} <strong>{activeTools.join(', ')}</strong>
                </p>
            )}
            <div style={{ marginTop: '12px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <input
                    type="checkbox"
                    id="allow-internal"
                    checked={allowInternal}
                    onChange={(e) => setAllowInternal(e.target.checked)}
                    style={{ cursor: 'pointer' }}
                />
                <label htmlFor="allow-internal" style={{ fontSize: '12px', color: '#98a2b3', cursor: 'pointer' }}>

                    {language === "ru" 
                        ? 'Разрешить сканирование внутренних адресов (localhost, 127.0.0.1, private IP)' 
                        : 'Allow scanning internal addresses (localhost, 127.0.0.1, private IP)'}
                </label>
            </div>
        </form>
    );
};

export default SearchForm;
