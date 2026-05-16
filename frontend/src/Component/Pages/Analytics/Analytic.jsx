import React, { useState, useEffect } from "react";
import {
  PieChart,
  Pie,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  Cell,
  ResponsiveContainer
} from "recharts";
import "./Analytic.scss";

const Analytic = ({ language }) => {
  const [scanData, setScanData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [availableReports, setAvailableReports] = useState({
    scanner: [],
    nuclei: [],
    nmap: [],
    web: [],
    cors: [],
    osint: [],
    combined: []
  });
  const [selectedTool, setSelectedTool] = useState("scanner");
  const [selectedReport, setSelectedReport] = useState("");
  const [reportsLoading, setReportsLoading] = useState(false);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  // Цвета для графиков
  const COLORS = {
    critical: "#ff0000",
    high: "#ff4d4f",
    medium: "#faad14",
    low: "#52c41a",
    info: "#1890ff"
  };

  // Получение токена из localStorage
  const getToken = () => {
    const tokenKeys = ['access_token', 'token', 'jwt', 'auth_token'];
    
    for (const key of tokenKeys) {
      const token = localStorage.getItem(key);
      if (token) {
        console.log(`[DEBUG] Token found with key: ${key}`);
        return token;
      }
    }
    
    for (const key of tokenKeys) {
      const token = sessionStorage.getItem(key);
      if (token) {
        console.log(`[DEBUG] Token found in sessionStorage with key: ${key}`);
        return token;
      }
    }
    
    console.log('[DEBUG] No token found in storage');
    return null;
  };

  const token = getToken();

  // Проверка авторизации
  useEffect(() => {
    if (token) {
      setIsAuthenticated(true);
      console.log('[DEBUG] User is authenticated');
    } else {
      setIsAuthenticated(false);
      setError('Не авторизован. Пожалуйста, войдите в систему.');
      setLoading(false);
    }
  }, [token]);

  // Загрузка списка доступных отчетов
  useEffect(() => {
    if (!token || !isAuthenticated) return;

    const loadAvailableReports = async () => {
      setReportsLoading(true);
      setError(null);
      
      try {
        console.log('[DEBUG] Loading available reports...');
        
        const response = await fetch("http://localhost:8000/api/available-reports", {
          headers: {
            "Authorization": `Bearer ${token}`,
            "Content-Type": "application/json"
          }
        });
        
        if (!response.ok) {
          if (response.status === 401) {
            throw new Error("Сессия истекла. Пожалуйста, войдите снова.");
          }
          throw new Error(`Ошибка ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        console.log('[DEBUG] Available reports:', data);
        
        if (data.status === 'success' && data.reports) {
          setAvailableReports(data.reports);
          
          const firstTool = Object.keys(data.reports).find(tool => data.reports[tool] && data.reports[tool].length > 0);
          if (firstTool && data.reports[firstTool].length > 0) {
            setSelectedTool(firstTool);
            setSelectedReport(data.reports[firstTool][0].filename);
            loadReportContent(firstTool, data.reports[firstTool][0].path);
          } else {
            setError("Нет доступных отчетов. Запустите сканирование для создания отчетов.");
            setLoading(false);
          }
        } else {
          setError("Не удалось загрузить список отчетов");
          setLoading(false);
        }
      } catch (err) {
        console.error('[DEBUG] Error loading reports:', err);
        setError(err.message || "Ошибка загрузки списка отчетов");
        setLoading(false);
      } finally {
        setReportsLoading(false);
      }
    };

    loadAvailableReports();
  }, [token, isAuthenticated]);

  // Загрузка содержимого выбранного отчета
  const loadReportContent = async (tool, path) => {
    if (!token) return;
    
    setLoading(true);
    console.log(`[DEBUG] Loading report: ${tool} - ${path}`);
    
    try {
      const response = await fetch(`http://localhost:8000/api/report-content?report_path=${encodeURIComponent(path)}`, {
        headers: {
          "Authorization": `Bearer ${token}`,
          "Content-Type": "application/json"
        }
      });
      
      if (!response.ok) {
        if (response.status === 401) {
          throw new Error("Сессия истекла. Пожалуйста, войдите снова.");
        }
        throw new Error(`Ошибка ${response.status}: ${response.statusText}`);
      }
      
      const result = await response.json();
      console.log('[DEBUG] Report content loaded:', result.tool);
      setScanData(result.data);
      setError(null);
    } catch (err) {
      console.error('[DEBUG] Error loading report:', err);
      setError(err.message);
      setScanData(null);
    } finally {
      setLoading(false);
    }
  };

  const handleToolChange = (tool) => {
    setSelectedTool(tool);
    if (availableReports[tool] && availableReports[tool].length > 0) {
      const firstReport = availableReports[tool][0];
      setSelectedReport(firstReport.filename);
      loadReportContent(tool, firstReport.path);
    } else {
      setScanData(null);
      setSelectedReport("");
      setError(`Нет отчетов для инструмента ${tool.toUpperCase()}`);
    }
  };

  const handleReportChange = (e) => {
    const filename = e.target.value;
    setSelectedReport(filename);
    const report = availableReports[selectedTool]?.find(r => r.filename === filename);
    if (report) {
      loadReportContent(selectedTool, report.path);
    }
  };

  // ==================== ПАРСЕРЫ ДЛЯ РАЗНЫХ ИНСТРУМЕНТОВ ====================

  // Получение severity данных в зависимости от инструмента
  const getSeverityData = () => {
    if (!scanData) return [];
    
    let severityMap = {};
    
    // Для Web сканера - нет severity, показываем количество URL/эндпоинтов
    if (selectedTool === 'web') {
      const totalResults = getWebTotalResults();
      if (totalResults > 0) {
        return [{ name: "Найдено результатов", value: totalResults, color: "#1890ff" }];
      }
      return [];
    }
    
    // Для Nuclei - проверяем структуру
    if (selectedTool === 'nuclei') {
      if (scanData.total_findings === 0 || !scanData.results || scanData.results.length === 0) {
        return [];
      }
      
      if (scanData.by_severity) {
        severityMap = scanData.by_severity;
      } else if (scanData.results && Array.isArray(scanData.results)) {
        scanData.results.forEach(result => {
          const severity = (result.info?.severity || result.severity || 'info').toLowerCase();
          severityMap[severity] = (severityMap[severity] || 0) + 1;
        });
      }
    }
    
    // Для CORS - используем summary
    if (selectedTool === 'cors' && scanData.summary) {
      severityMap = {
        critical: scanData.summary.critical || 0,
        high: scanData.summary.high || 0,
        medium: scanData.summary.medium || 0,
        low: scanData.summary.low || 0
      };
    }
    
    // Для Scanner
    if (selectedTool === 'scanner' && scanData.summary) {
      severityMap = {
        critical: scanData.summary.critical || 0,
        high: scanData.summary.high || 0,
        medium: scanData.summary.medium || 0,
        low: scanData.summary.low || 0
      };
    }
    
    // Для Nmap
    if (selectedTool === 'nmap' && scanData.vulnerabilities) {
      if (Array.isArray(scanData.vulnerabilities)) {
        scanData.vulnerabilities.forEach(vuln => {
          const severity = (vuln.severity || 'low').toLowerCase();
          severityMap[severity] = (severityMap[severity] || 0) + 1;
        });
      }
      if (scanData.vulnerabilities_by_severity) {
        severityMap = scanData.vulnerabilities_by_severity;
      }
    }
    
    // Для CORS - используем summary если есть
    if (selectedTool === 'cors' && scanData.summary) {
      severityMap = {
        critical: scanData.summary.critical || 0,
        high: scanData.summary.high || 0,
        medium: scanData.summary.medium || 0,
        low: scanData.summary.low || 0
      };
    }
    
    // Для OSINT - обычно нет severity, но можем показать статистику по источникам
    if (selectedTool === 'osint') {
      if (scanData.summary?.by_severity) {
        severityMap = scanData.summary.by_severity;
      } else if (scanData.results && Array.isArray(scanData.results)) {
        scanData.results.forEach(result => {
          const severity = (result.severity || 'info').toLowerCase();
          severityMap[severity] = (severityMap[severity] || 0) + 1;
        });
      }
    }
    
    return Object.entries(severityMap)
      .filter(([_, value]) => value > 0)
      .map(([name, value]) => ({ 
        name: name.charAt(0).toUpperCase() + name.slice(1), 
        value,
        color: COLORS[name.toLowerCase()] || "#8884d8"
      }));
  };

  // Получение топ типов для Web сканера (инструменты)
  const getWebToolData = () => {
    if (!scanData || selectedTool !== 'web') return [];
    
    const toolStats = [];
    
    if (scanData.summary?.by_tool) {
      Object.entries(scanData.summary.by_tool).forEach(([tool, count]) => {
        toolStats.push({ name: tool, count });
      });
    } else if (scanData.tools) {
      Object.entries(scanData.tools).forEach(([tool, data]) => {
        if (data.count !== undefined) {
          toolStats.push({ name: tool, count: data.count });
        }
      });
    }
    
    return toolStats.sort((a, b) => b.count - a.count).slice(0, 8);
  };

  // Получение топ типов уязвимостей
  const getTopVulnerabilityTypes = () => {
    if (!scanData) return [];
    
    const typeCount = {};
    
    // Для Web - показываем найденные URL/эндпоинты
    if (selectedTool === 'web') {
      const urls = getAllWebUrls();
      urls.forEach(url => {
        const hostname = extractHostname(url);
        typeCount[hostname] = (typeCount[hostname] || 0) + 1;
      });
      return Object.entries(typeCount)
        .map(([name, count]) => ({ name: name.length > 30 ? name.substring(0, 30) + "..." : name, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 8);
    }
    
    // Для Scanner
    if (selectedTool === 'scanner' && scanData.vulnerabilities && Array.isArray(scanData.vulnerabilities)) {
      scanData.vulnerabilities.forEach(vuln => {
        const type = vuln.type || vuln.name || "Unknown";
        typeCount[type] = (typeCount[type] || 0) + 1;
      });
    }
    
    // Для Nuclei
    if (selectedTool === 'nuclei' && scanData.results && Array.isArray(scanData.results)) {
      scanData.results.forEach(result => {
        const type = result.template_id || result.name || "Unknown";
        typeCount[type] = (typeCount[type] || 0) + 1;
      });
    }
    
    // Для Nmap
    if (selectedTool === 'nmap' && scanData.vulnerabilities && Array.isArray(scanData.vulnerabilities)) {
      scanData.vulnerabilities.forEach(vuln => {
        const type = vuln.cve_id || vuln.service || "Unknown";
        typeCount[type] = (typeCount[type] || 0) + 1;
      });
    }
    
    // Для CORS
    if (selectedTool === 'cors' && scanData.vulnerabilities && Array.isArray(scanData.vulnerabilities)) {
      scanData.vulnerabilities.forEach(vuln => {
        const type = vuln.type || "Unknown";
        typeCount[type] = (typeCount[type] || 0) + 1;
      });
    }
    
    // Для OSINT
    if (selectedTool === 'osint' && scanData.results && Array.isArray(scanData.results)) {
      scanData.results.forEach(result => {
        const type = result.source || result.type || "Unknown";
        typeCount[type] = (typeCount[type] || 0) + 1;
      });
    }
    
    return Object.entries(typeCount)
      .map(([name, count]) => ({ name: name.length > 30 ? name.substring(0, 30) + "..." : name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  };

  // Получение всех URL из Web отчета
  const getAllWebUrls = () => {
    if (!scanData || selectedTool !== 'web') return [];
    
    const urls = [];
    
    // Из Katana
    if (scanData.results?.katana && Array.isArray(scanData.results.katana)) {
      urls.push(...scanData.results.katana);
    }
    
    // Из JSFinder
    if (scanData.results?.jsfinder_urls && Array.isArray(scanData.results.jsfinder_urls)) {
      urls.push(...scanData.results.jsfinder_urls);
    }
    
    // Из Gobuster (парсим статусы)
    if (scanData.results?.gobuster && Array.isArray(scanData.results.gobuster)) {
      scanData.results.gobuster.forEach(item => {
        const match = item.match(/^(\S+)/);
        if (match) {
          urls.push(match[1]);
        }
      });
    }
    
    // Альтернативная структура
    if (scanData.results && typeof scanData.results === 'object') {
      Object.values(scanData.results).forEach(value => {
        if (Array.isArray(value)) {
          value.forEach(item => {
            if (typeof item === 'string' && (item.startsWith('http') || item.includes('/'))) {
              urls.push(item);
            }
          });
        }
      });
    }
    
    return [...new Set(urls)]; // Удаляем дубликаты
  };

  // Извлечение hostname из URL
  const extractHostname = (url) => {
    try {
      const urlObj = new URL(url);
      return urlObj.hostname;
    } catch {
      return url.split('/')[0] || url;
    }
  };

  // Получение данных по эндпоинтам для Web
  const getWebEndpointData = () => {
    if (!scanData || selectedTool !== 'web') return [];
    
    const endpointCount = {};
    const urls = getAllWebUrls();
    
    urls.forEach(url => {
      let path = '/';
      try {
        const urlObj = new URL(url);
        path = urlObj.pathname || '/';
        if (path === '' || path === '/') path = '/';
      } catch {
        path = url;
      }
      endpointCount[path] = (endpointCount[path] || 0) + 1;
    });
    
    return Object.entries(endpointCount)
      .map(([path, count]) => ({ url: path.length > 40 ? path.substring(0, 40) + "..." : path, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
  };

  // Получение данных по эндпоинтам для других инструментов
  const getEndpointData = () => {
    if (!scanData) return [];
    
    // Для Web используем специальный метод
    if (selectedTool === 'web') {
      return getWebEndpointData();
    }
    
    const endpointCount = {};
    
    if (selectedTool === 'scanner' && scanData.vulnerabilities && Array.isArray(scanData.vulnerabilities)) {
      scanData.vulnerabilities.forEach(vuln => {
        const url = vuln.url || vuln.affected_url || "Unknown";
        let shortName = url.length > 40 ? url.substring(0, 40) + "..." : url;
        endpointCount[shortName] = (endpointCount[shortName] || 0) + 1;
      });
    }
    
    if (selectedTool === 'nuclei' && scanData.results && Array.isArray(scanData.results)) {
      scanData.results.forEach(result => {
        const url = result.matched_at || result.host || "Unknown";
        let shortName = url.length > 40 ? url.substring(0, 40) + "..." : url;
        endpointCount[shortName] = (endpointCount[shortName] || 0) + 1;
      });
    }
    
    if (selectedTool === 'nmap' && scanData.hosts && Array.isArray(scanData.hosts)) {
      scanData.hosts.forEach(host => {
        const hostname = typeof host === 'string' ? host : host.host || host.ip || "Unknown";
        endpointCount[hostname] = (endpointCount[hostname] || 0) + 1;
      });
    }
    
    if (selectedTool === 'cors' && scanData.vulnerabilities && Array.isArray(scanData.vulnerabilities)) {
      scanData.vulnerabilities.forEach(vuln => {
        const url = vuln.affected_url || scanData.scan_info?.target_url || "Unknown";
        let shortName = url.length > 40 ? url.substring(0, 40) + "..." : url;
        endpointCount[shortName] = (endpointCount[shortName] || 0) + 1;
      });
    }
    
    if (selectedTool === 'osint' && scanData.results && Array.isArray(scanData.results)) {
      scanData.results.forEach(result => {
        const url = result.url || result.subdomain || result.value || "Unknown";
        let shortName = url.length > 40 ? url.substring(0, 40) + "..." : url;
        endpointCount[shortName] = (endpointCount[shortName] || 0) + 1;
      });
    }
    
    return Object.entries(endpointCount)
      .map(([url, count]) => ({ url, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  };

  // Общая статистика
  const getTotalStats = () => {
    if (!scanData) return { total: 0 };
    
    // Для Web показываем общее количество найденных URL
    if (selectedTool === 'web') {
      const total = getWebTotalResults();
      return { total };
    }
    
    // Для Nuclei без результатов
    if (selectedTool === 'nuclei' && scanData.total_findings === 0) {
      return { total: 0 };
    }
    
    const severityData = getSeverityData();
    const total = severityData.reduce((sum, item) => sum + item.value, 0);
    const stats = { total };
    
    severityData.forEach(item => {
      stats[item.name.toLowerCase()] = item.value;
    });
    
    return stats;
  };

  // Общее количество результатов для Web
  const getWebTotalResults = () => {
    if (!scanData || selectedTool !== 'web') return 0;
    return getAllWebUrls().length;
  };

  // Получение информации о цели
  const getTargetInfo = () => {
    if (!scanData) return null;
    
    if (selectedTool === 'web' && scanData.scan_info?.target_url) {
      return scanData.scan_info.target_url;
    }
    
    if (scanData.target) return scanData.target;
    if (scanData.scan_info?.target_url) return scanData.scan_info.target_url;
    if (scanData.scan_info?.target) return scanData.scan_info.target;
    
    return null;
  };

  // Получение времени сканирования
  const getScanTime = () => {
    if (!scanData) return null;
    
    if (scanData.scan_datetime) return scanData.scan_datetime;
    if (scanData.metadata?.generated_at) return scanData.metadata.generated_at;
    if (scanData.scan_info?.scan_start_time) return scanData.scan_info.scan_start_time;
    
    return null;
  };

  const stats = getTotalStats();
  const severityData = getSeverityData();
  const topVulnTypes = getTopVulnerabilityTypes();
  const endpointData = getEndpointData();
  const webToolData = getWebToolData();
  const totalWebResults = getWebTotalResults();
  const targetInfo = getTargetInfo();
  const scanTime = getScanTime();

  // Проверка авторизации
  if (!isAuthenticated) {
    return (
      <main className="main__analytic">
        <div className="container">
          <div className="error">
            🔒 {language === "ru" 
              ? "Требуется авторизация. Пожалуйста, войдите в систему." 
              : "Authentication required. Please log in."}
            <button 
              onClick={() => window.location.href = '/login'}
              className="login-btn"
            >
              {language === "ru" ? "Войти" : "Login"}
            </button>
          </div>
        </div>
      </main>
    );
  }

  if (reportsLoading && !scanData) {
    return (
      <main className="main__analytic">
        <div className="container">
          <div className="loading">
            ⏳ {language === "ru" ? "Загрузка списка отчетов..." : "Loading reports list..."}
          </div>
        </div>
      </main>
    );
  }

  if (error && !scanData) {
    return (
      <main className="main__analytic">
        <div className="container">
          <div className="error">
            ❌ {error}
          </div>
        </div>
      </main>
    );
  }

  return (
    <main className="main__analytic">
      <div className="container">
        {/* Селектор отчетов */}
        <div className="report-selector">
          <div className="selector-group">
            <label>{language === "ru" ? "Инструмент:" : "Tool:"}</label>
            <select 
              value={selectedTool} 
              onChange={(e) => handleToolChange(e.target.value)}
              disabled={reportsLoading}
            >
              {Object.entries(availableReports).map(([tool, reports]) => 
                reports && reports.length > 0 ? (
                  <option key={tool} value={tool}>
                    🔧 {tool.toUpperCase()} ({reports.length})
                  </option>
                ) : null
              )}
              {Object.values(availableReports).every(arr => !arr || arr.length === 0) && (
                <option disabled>Нет доступных отчетов</option>
              )}
            </select>
          </div>
          
          <div className="selector-group">
            <label>{language === "ru" ? "Отчет:" : "Report:"}</label>
            <select 
              value={selectedReport} 
              onChange={handleReportChange}
              disabled={reportsLoading || !availableReports[selectedTool]?.length}
            >
              {availableReports[selectedTool]?.map((report) => (
                <option key={report.filename} value={report.filename}>
                  📄 {new Date(report.scan_datetime).toLocaleString()} - {report.total_vulnerabilities || 0} уязв.
                </option>
              ))}
            </select>
          </div>
          
          {reportsLoading && <div className="selector-loading">🔄 Загрузка...</div>}
        </div>

        {/* Заголовок */}
        {scanData && (
          <div className="header">
            <h2 className="h2">
              {selectedTool.toUpperCase()} {language === "ru" ? "сканер - результаты" : "Scanner - Results"}
            </h2>
            <span className="span">
              {language === "ru"
                ? `🔍 Найдено ${selectedTool === 'web' ? 'URL/эндпоинтов' : 'уязвимостей'}: ${stats.total}`
                : `🔍 Found ${selectedTool === 'web' ? 'URLs/endpoints' : 'vulnerabilities'}: ${stats.total}`}
            </span>
            {scanTime && (
              <span className="date">
                📅 {new Date(scanTime).toLocaleString()}
              </span>
            )}
            {targetInfo && (
              <span className="target">
                🎯 {language === "ru" ? "Цель:" : "Target:"} {targetInfo}
              </span>
            )}
          </div>
        )}

        {/* Графики */}
        {scanData && stats.total > 0 && (
          <>
            {/* Статистическая панель */}
            <div className="stats-panel">
              {selectedTool !== 'web' && Object.entries(stats).map(([key, value]) => 
                key !== 'total' && value > 0 && (
                  <div key={key} className={`stat-card stat-${key}`}>
                    <div className="stat-value">{value}</div>
                    <div className="stat-label">{key.toUpperCase()}</div>
                  </div>
                )
              )}
              <div className="stat-card stat-total">
                <div className="stat-value">{stats.total}</div>
                <div className="stat-label">
                  {selectedTool === 'web' ? 'URLs/ENDPOINTS' : 'TOTAL'}
                </div>
              </div>
            </div>

            <div className="charts-grid">
              {/* Круговая диаграмма - для Web показываем распределение по инструментам */}
              {severityData.length > 0 && selectedTool !== 'web' && (
                <div className="chart-card">
                  <h3 className="chart-title">
                    {language === "ru" ? "Распределение по критичности" : "Severity Distribution"}
                  </h3>
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie
                        data={severityData}
                        cx="50%"
                        cy="50%"
                        labelLine={false}
                        label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                        outerRadius={80}
                        fill="#8884d8"
                        dataKey="value"
                      >
                        {severityData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              )}

              {/* Для Web - показываем распределение по инструментам */}
              {selectedTool === 'web' && webToolData.length > 0 && (
                <div className="chart-card">
                  <h3 className="chart-title">
                    {language === "ru" ? "Распределение по инструментам" : "Results by Tool"}
                  </h3>
                  <ResponsiveContainer width="100%" height={300}>
                    <PieChart>
                      <Pie
                        data={webToolData}
                        cx="50%"
                        cy="50%"
                        labelLine={false}
                        label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                        outerRadius={80}
                        fill="#8884d8"
                        dataKey="count"
                      >
                        {webToolData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={Object.values(COLORS)[index % Object.values(COLORS).length]} />
                        ))}
                      </Pie>
                      <Tooltip />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                </div>
              )}

              {/* Bar chart - топ типов */}
              {topVulnTypes.length > 0 && (
                <div className="chart-card">
                  <h3 className="chart-title">
                    {language === "ru" 
                      ? (selectedTool === 'web' ? "Топ хостов по количеству URL" : "Топ уязвимостей по типу")
                      : (selectedTool === 'web' ? "Top Hosts by URL Count" : "Top Vulnerability Types")}
                  </h3>
                  <ResponsiveContainer width="100%" height={300}>
                    <BarChart data={topVulnTypes} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis type="number" />
                      <YAxis 
                        dataKey="name" 
                        type="category" 
                        width={130}
                        tick={{ fontSize: 11 }}
                      />
                      <Tooltip />
                      <Legend />
                      <Bar dataKey="count" fill="#8884d8" name={selectedTool === 'web' ? "URL count" : "Количество"} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}

              {/* Bar chart - по эндпоинтам/хостам */}
              {endpointData.length > 0 && (
                <div className="chart-card full-width">
                  <h3 className="chart-title">
                    {language === "ru" 
                      ? (selectedTool === 'web' ? "Найденные пути/эндпоинты" : "Уязвимости по эндпоинтам")
                      : (selectedTool === 'web' ? "Discovered Paths/Endpoints" : "Vulnerabilities by Endpoint")}
                  </h3>
                  <ResponsiveContainer width="100%" height={350}>
                    <BarChart data={endpointData}>
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="url" angle={-35} textAnchor="end" height={80} tick={{ fontSize: 10 }} />
                      <YAxis />
                      <Tooltip />
                      <Legend />
                      <Bar dataKey="count" fill="#82ca9d" name={selectedTool === 'web' ? "URL count" : "Количество"} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </div>
          </>
        )}

        {/* Сообщение когда нет результатов */}
        {scanData && stats.total === 0 && (
          <div className="no-vulnerabilities">
            <div className="success-icon">✅</div>
            <h3>
              {selectedTool === 'web' 
                ? (language === "ru" ? "URL/эндпоинты не найдены" : "No URLs/endpoints found")
                : (language === "ru" ? "Уязвимости не найдены" : "No vulnerabilities found")}
            </h3>
            <p>
              {selectedTool === 'web'
                ? (language === "ru" 
                    ? "Сканирование не выявило URL или эндпоинтов. Проверьте доступность цели."
                    : "The scan did not reveal any URLs or endpoints. Check target availability.")
                : (language === "ru" 
                    ? "Сканирование не выявило известных уязвимостей."
                    : "The scan did not reveal any known vulnerabilities.")}
            </p>
          </div>
        )}

        {/* Дополнительная информация для Web сканера */}
        {selectedTool === 'web' && scanData && totalWebResults > 0 && (
          <div className="additional-info">
            <h3>📊 Детальная статистика Web сканирования</h3>
            <div className="web-stats">
              <div className="stat-item">
                <span className="stat-icon">🌐</span>
                <span className="stat-label">Katana (crawler):</span>
                <span className="stat-value">{scanData.results?.katana?.length || 0} URL</span>
              </div>
              <div className="stat-item">
                <span className="stat-icon">🔍</span>
                <span className="stat-label">JSFinder:</span>
                <span className="stat-value">{scanData.results?.jsfinder_urls?.length || 0} URL</span>
              </div>
              <div className="stat-item">
                <span className="stat-icon">💣</span>
                <span className="stat-label">Gobuster:</span>
                <span className="stat-value">{scanData.results?.gobuster?.length || 0} директорий</span>
              </div>
            </div>
            {scanData.scan_info?.total_duration_seconds && (
              <div className="scan-duration">
                ⏱️ {language === "ru" ? "Время сканирования:" : "Scan duration:"} {scanData.scan_info.total_duration_seconds.toFixed(2)} сек.
              </div>
            )}
          </div>
        )}
      </div>
    </main>
  );
};

export default Analytic;