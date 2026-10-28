import React, { useEffect, useState } from "react";
import { apiFetch } from "../../../../api";


const Tools = ({ setActiveTools, activeTools }) => {
  const [tooltipOpen, setTooltipOpen] = useState(null);
  const [tools, setTools] = useState([]);
  const [catalogError, setCatalogError] = useState("");

  useEffect(() => {
    let active = true;
    apiFetch("/api/tools")
      .then(async (response) => {
        if (!response.ok) {
          throw new Error(`Не удалось загрузить список инструментов (${response.status})`);
        }
        const data = await response.json();
        if (active) {
          const selectableTools = (data.tools || []).filter((tool) => tool.selectable !== false);
          setTools(selectableTools);
          const selectableIds = new Set(selectableTools.map((tool) => tool.id));
          setActiveTools((currentTools) =>
            currentTools.filter((toolId) => selectableIds.has(toolId)),
          );
        }
      })
      .catch((error) => {
        if (active) setCatalogError(error.message);
      });
    return () => {
      active = false;
    };
  }, [setActiveTools]);

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
          title={tool.available
            ? `Выбрать инструмент ${tool.label}`
            : `${tool.label}: отсутствуют зависимости — ${(tool.missing_dependencies || []).join(", ")}`}
        >
          {tool.label}
          <div
            className="tagging"
            onMouseEnter={() => setTooltipOpen(tool.id)}
            onMouseLeave={() => setTooltipOpen(null)}
          >
            {tooltipOpen === tool.id && (
              <div className="tooltip">
                <p>{tool.description}</p>
                {!tool.available && (
                  <p>Не установлено: {(tool.missing_dependencies || []).join(", ")}</p>
                )}
              </div>
            )}
          </div>
        </button>
      ))}
      {catalogError && (
        <p role="alert" className="tool-catalog-error">
          Не удалось проверить доступность инструментов: {catalogError}
        </p>
      )}
    </div>
  );
};

export default Tools;