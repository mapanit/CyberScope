import React, { useState } from "react";

const Tools = ({ setActiveTools, activeTools }) => {
  const [tooltipOpen, setTooltipOpen] = useState(null);

  const tools = [
    { id: "scanner", label: "Scanner", info: "Проверяет SQL инъекции, XSS, security headers, чувствительные файлы и другие уязвимости"},
    { id: "osint", label: "OSINT", info: "Сбор информации о домене, IP и других объектах через открытые источники" },
    { id: "wappalyzer", label: "Wappalyzer", info: "Определение технологий, фреймворков и CMS на сайте" },
    { id: "nuclei", label: "Nuclei", info: "Быстрое сканирование на основе YAML шаблонов для выявления CVE" },
    { id: "whois", label: "WhoIS", info: "Получение информации о регистрации и владельце домена" },
    { id: "web", label: "Web", info: "Сканирование инструментов для веб-разведки" },
    { id: "retire", label: "Retire", info: "Сканирование JavaScript библиотек на наличие уязвимостей" },
    { id: "cors", label: "CORS", info: "Проверка конфигурации CORS на наличие уязвимостей" },
    { id: "ssl-tls", label: "SSL/TLS", info: "Детальный анализ конфигурации SSL/TLS" },
  ];

  const handleToolClick = (toolId) => {
    if (activeTools.includes(toolId)) {
      setActiveTools(activeTools.filter(tool => tool !== toolId));
    } else {
      setActiveTools([...activeTools, toolId]);
    }
  };

  return (
    <div className="menu__active">
      {tools.map((tool) => (
        <button
          key={tool.id}
          type="button"
          className={`menu__active-btn ${activeTools.includes(tool.id) ? "active" : ""}`}
          onClick={() => handleToolClick(tool.id)}
          title={`Выбрать инструмент ${tool.label}`}
        >
          {tool.label}
          <div
            className="tagging"
            onMouseEnter={() => setTooltipOpen(tool.id)}
            onMouseLeave={() => setTooltipOpen(null)}
          >
            {tooltipOpen === tool.id && (
              <div className="tooltip">
                <p>{tool.info}</p>
              </div>
            )}
          </div>
        </button>
      ))}
    </div>
  );
};

export default Tools;