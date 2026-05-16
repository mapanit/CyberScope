import React, { useState } from "react";

const Tools = ({ setActiveTools, activeTools }) => {
  const [tooltipOpen, setTooltipOpen] = useState(null);

  const tools = [
    { id: "osint", label: "OSINT", info: "Сбор информации о домене, IP и других объектах через открытые источники" },
    { id: "whois", label: "WhoIS", info: "Получение информации о регистрации и владельце домена" },
    { id: "dns", label: "DNS", info: "Сканирование DNS записей" },
    
    { id: "nmap", label: "Nmap", info: "Сканирование портов и сервисов на целевом хосте" },
    
    { id: "wappalyzer", label: "Wappalyzer", info: "Определение технологий, фреймворков и CMS на сайте" },
    { id: "ssl-tls", label: "ssl-tls", info: "Проверка конфигурации SSL/TLS на наличие уязвимостей" },
    
    { id: "scanner", label: "Scanner", info: "Проверяет SQL инъекции, XSS, security headers, чувствительные файлы и другие уязвимости"},
    { id: "retire", label: "Retire", info: "Сканирование JavaScript библиотек на наличие уязвимостей" },
    { id: "cors", label: "CORS", info: "Проверка конфигурации CORS на наличие уязвимостей" },
    { id: "web", label: "Web", info: "Сканирование инструментов для веб-разведки" },
    
    { id: "nuclei", label: "Nuclei", info: "Быстрое сканирование на основе YAML шаблонов для выявления CVE" },
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