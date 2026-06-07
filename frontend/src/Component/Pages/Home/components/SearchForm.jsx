import React, { useState } from "react";
import { NavLink } from "react-router-dom";

const SearchForm = ({
  query,
  setQuery,
  loading,
  handleSubmit,
  cancelScan,
  activeTools,
  allowInternal,
  setAllowInternal,
  language = "ru",
}) => {
  const [urls, setUrls] = useState(query ? [query] : [""]);

  const handleAddUrl = () => {
    setUrls([...urls, ""]);
  };

  const handleRemoveUrl = (index) => {
    const newUrls = urls.filter((_, i) => i !== index);
    setUrls(newUrls.length === 0 ? [""] : newUrls);
  };

  const handleUrlChange = (index, value) => {
    const newUrls = [...urls];
    newUrls[index] = value;
    setUrls(newUrls);
    // Обновляем основной query (для совместимости)
    setQuery(newUrls[0]);
  };

  const handleFormSubmit = (e) => {
    e.preventDefault();
    // Фильтруем пустые URL'ы
    const validUrls = urls.filter((url) => url.trim());
    if (validUrls.length === 0) {
      alert(
        language === "ru"
          ? "Пожалуйста, введите хотя бы один URL"
          : "Please enter at least one URL",
      );
      return;
    }
    // Передаём все URL'ы
    setQuery(validUrls);
    handleSubmit(e, validUrls);
  };

  return (
    <form className="form__search" onSubmit={handleFormSubmit}>
      <label htmlFor="search-input">
        {language === "ru" ? "Поиск" : "Search"}
      </label>

      <div className="urls-container" style={{ marginBottom: "12px" }}>
        {urls.map((url, index) => (
          <div
            key={index}
            className="form__row"
            style={{
              marginBottom: "8px",
              display: "flex",
              gap: "8px",
              alignItems: "center",
            }}
          >
            <input
              type="text"
              value={url}
              onChange={(e) => handleUrlChange(index, e.target.value)}
              placeholder={
                language === "ru"
                  ? "Адрес сайта (пример: https://example.com)"
                  : "Website URL (example: https://example.com)"
              }
              aria-label={
                language === "ru" ? `URL ${index + 1}` : `URL ${index + 1}`
              }
              disabled={loading}
              style={{ flex: 1 }}
            />
            {urls.length > 1 && (
              <button
                type="button"
                onClick={() => handleRemoveUrl(index)}
                disabled={loading}
                style={{
                  padding: "6px 12px",
                  backgroundColor: "#dc3545",
                  color: "white",
                  border: "none",
                  borderRadius: "4px",
                  cursor: loading ? "not-allowed" : "pointer",
                  fontSize: "12px",
                }}
                title={language === "ru" ? "Удалить" : "Remove"}
              >
                ✕
              </button>
            )}
          </div>
        ))}
      </div>

      <div style={{ marginBottom: "12px" }}>
        <button
          type="button"
          onClick={handleAddUrl}
          disabled={loading}
          style={{
            padding: "6px 12px",
            backgroundColor: "#6c757d",
            color: "white",
            border: "none",
            borderRadius: "4px",
            cursor: loading ? "not-allowed" : "pointer",
            fontSize: "12px",
            marginBottom: "8px",
          }}
        >
          + {language === "ru" ? "Добавить URL" : "Add URL"}
        </button>
      </div>

      <NavLink to="/help" className="help__link" activeClassName="active">
        {language === "ru" ? "Помощник" : "Help"}
      </NavLink>

      <div className="form__row">
        <div className="form-buttons">
          <button
            className="form__btn"
            type="submit"
            aria-label={language === "ru" ? "Найти" : "Start"}
            disabled={loading}
          >
            {loading
              ? language === "ru"
                ? "Сканирование..."
                : "Scanning..."
              : language === "ru"
                ? "начать"
                : "Start"}
          </button>
          {loading && (
            <button
              type="button"
              className="cancel-btn"
              onClick={() => {
                const result = cancelScan();
                if (result && typeof result.catch === "function") {
                  result.catch((err) => {
                    console.warn("Предупреждение при отмене:", err);
                  });
                }
              }}
              aria-label={
                language === "ru" ? "Отменить сканирование" : "Cancel scan"
              }
            >
              {language === "ru" ? "Отменить" : "Cancel"}
            </button>
          )}
        </div>
      </div>

      {activeTools.length > 0 && (
        <p style={{ marginTop: "8px", color: "#98a2b3", fontSize: "12px" }}>
          {language === "ru" ? "Выбранные инструменты:" : "Selected tools:"}{" "}
          <strong>{activeTools.join(", ")}</strong>
        </p>
      )}

      <div
        style={{
          marginTop: "12px",
          display: "flex",
          alignItems: "center",
          gap: "8px",
        }}
      >
        <input
          type="checkbox"
          id="allow-internal"
          checked={allowInternal}
          onChange={(e) => setAllowInternal(e.target.checked)}
          style={{ cursor: "pointer" }}
        />
        <label
          htmlFor="allow-internal"
          style={{ fontSize: "12px", color: "#98a2b3", cursor: "pointer" }}
        >
          {language === "ru"
            ? "Разрешить сканирование внутренних адресов (localhost, 127.0.0.1, private IP)"
            : "Allow scanning internal addresses (localhost, 127.0.0.1, private IP)"}
        </label>
      </div>
    </form>
  );
};

export default SearchForm;