import React, { useState, useEffect } from 'react';
import './ScheduleScanner.scss';

const ScheduleScanner = ({ activeScheduleScanner, setActiveScheduleScanner, activeTools, setActiveTools, query, setQuery, allowInternal, setAllowInternal, onSchedule, language = "ru" }) => {
  const [scheduleType, setScheduleType] = useState('once');
  const [scheduleTime, setScheduleTime] = useState('');
  const [scheduleDate, setScheduleDate] = useState('');
  const [scheduleDays, setScheduleDays] = useState([]);
  const [scheduleMonthDay, setScheduleMonthDay] = useState(1);
  const [scheduledTasks, setScheduledTasks] = useState([]);
  const [viewMode, setViewMode] = useState('create'); // 'create' or 'list'
  
  const weekDays = language === "ru" ? [
    { id: '0', name: 'Вс' },
    { id: '1', name: 'Пн' },
    { id: '2', name: 'Вт' },
    { id: '3', name: 'Ср' },
    { id: '4', name: 'Чт' },
    { id: '5', name: 'Пт' },
    { id: '6', name: 'Сб' }
  ] : [
    { id: '0', name: 'Sun' },
    { id: '1', name: 'Mon' },
    { id: '2', name: 'Tue' },
    { id: '3', name: 'Wed' },
    { id: '4', name: 'Thu' },
    { id: '5', name: 'Fri' },
    { id: '6', name: 'Sat' }
  ];

  const toolsList = [
    { id: "scanner", label: "Scanner", icon: "🔍" },
    { id: "osint", label: "OSINT", icon: "🌐" },
    { id: "wappalyzer", label: "Wappalyzer", icon: "⚙️" },
    { id: "nuclei", label: "Nuclei", icon: "🎯" },
    { id: "whois", label: "WhoIS", icon: "📝" },
    { id: "web", label: "Web", icon: "🌍" },
    { id: "retire", label: "Retire", icon: "🌍" },
    { id: "cors", label: "CORS", icon: "🌍" },
    { id: "ssl-tls", label: "SSL/TLS", icon: "🌍" }
    
  ];

  // Загрузка сохраненных задач
  useEffect(() => {
    fetchTasks();
  }, []);

  // Загрузить задачи с backend
  const fetchTasks = async () => {
    try {
      const response = await fetch('http://localhost:8000/api/tasks');
      const data = await response.json();
      if (data.status === 'success') {
        setScheduledTasks(data.tasks);
      }
    } catch (error) {
      console.error('Ошибка при загрузке задач:', error);
      // Fallback на localStorage
      const saved = localStorage.getItem('scheduledScans');
      if (saved) {
        setScheduledTasks(JSON.parse(saved));
      }
    }
  };

  // Сохранение задач (локально для UI, отправка на backend при создании)
  const saveTasks = (tasks) => {
    localStorage.setItem('scheduledScans', JSON.stringify(tasks));
    setScheduledTasks(tasks);
  };

  // Расчет следующего запуска
  const calculateNextRun = () => {
    const now = new Date();
    const [hours, minutes] = scheduleTime.split(':');
    
    if (!hours || !minutes) return null;
    
    let nextRun = new Date();

    switch (scheduleType) {
      case 'once':
        if (!scheduleDate) return null;
        nextRun = new Date(scheduleDate);
        nextRun.setHours(parseInt(hours), parseInt(minutes), 0, 0);
        break;
      
      case 'daily':
        nextRun.setHours(parseInt(hours), parseInt(minutes), 0, 0);
        if (nextRun <= now) {
          nextRun.setDate(nextRun.getDate() + 1);
        }
        break;
      
      case 'weekly':
        nextRun.setHours(parseInt(hours), parseInt(minutes), 0, 0);
        const today = now.getDay();
        const nextDay = scheduleDays
          .map(d => parseInt(d))
          .sort((a, b) => a - b)
          .find(day => day > today);
        
        if (nextDay !== undefined) {
          const daysToAdd = nextDay - today;
          nextRun.setDate(nextRun.getDate() + daysToAdd);
        } else if (scheduleDays.length > 0) {
          const firstDay = parseInt(scheduleDays[0]);
          const daysToAdd = (7 - today) + firstDay;
          nextRun.setDate(nextRun.getDate() + daysToAdd);
        } else {
          return null;
        }
        
        if (nextRun <= now) {
          nextRun.setDate(nextRun.getDate() + 7);
        }
        break;
      
      case 'monthly':
        nextRun.setDate(scheduleMonthDay);
        nextRun.setHours(parseInt(hours), parseInt(minutes), 0, 0);
        if (nextRun <= now) {
          nextRun.setMonth(nextRun.getMonth() + 1);
        }
        break;
      
      default:
        return null;
    }

    return nextRun;
  };

  // Добавление задачи
  const addSchedule = async () => {
    // Получаем список URL'ов (если query - массив, иначе преобразуем в массив)
    const urlList = Array.isArray(query) ? query : (query ? [query] : []);
    const validUrls = urlList.filter(url => url.trim());

    if (validUrls.length === 0) {
      alert(language === "ru" ? 'Пожалуйста, введите цель сканирования' : 'Please enter the scan target');
      return;
    }

    if (!scheduleTime) {
      alert(language === "ru" ? 'Пожалуйста, выберите время' : 'Please select a time');
      return;
    }

    if (scheduleType === 'once' && !scheduleDate) {
      alert(language === "ru" ? 'Пожалуйста, выберите дату' : 'Please select a date');
      return;
    }

    if (scheduleType === 'weekly' && scheduleDays.length === 0) {
      alert(language === "ru" ? 'Пожалуйста, выберите дни недели' : 'Please select days of the week');
      return;
    }

    if (activeTools.length === 0) {
      alert(language === "ru" ? 'Пожалуйста, выберите хотя бы один инструмент' : 'Please select at least one tool');
      return;
    }

    const nextRun = calculateNextRun();
    
    if (!nextRun) {
      alert(language === "ru" ? 'Пожалуйста, заполните все обязательные поля' : 'Please complete all required fields');
      return;
    }

    const now = new Date();
    if (nextRun <= now && scheduleType === 'once') {
      alert(language === "ru" ? 'Время сканирования должно быть в будущем' : 'Scan time must be in the future');
      return;
    }

    const newTask = {
      type: scheduleType,
      time: scheduleTime,
      date: scheduleDate,
      days: scheduleDays,
      monthDay: scheduleMonthDay,
      urls: validUrls,  // Используем массив URL'ов вместо query
      activeTools: [...activeTools],
      allowInternal: allowInternal,
      nextRun: nextRun.toISOString(),
      createdAt: now.toISOString(),
      status: 'pending',
      lastRun: null
    };

    try {
      // Отправляем задачу на backend
      const response = await fetch('http://localhost:8000/api/tasks', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(newTask)
      });

      if (!response.ok) {
        throw new Error('Failed to create task on server');
      }

      const data = await response.json();
      
      // Перезагружаем список задач с backend
      await fetchTasks();
      
      if (onSchedule) {
        onSchedule(newTask);
      }

      alert(language === "ru" ? '✅ Сканирование успешно запланировано!' : '✅ Scan successfully scheduled!');
      
      // Сброс формы
      setScheduleType('once');
      setScheduleTime('');
      setScheduleDate('');
      setScheduleDays([]);
      setScheduleMonthDay(1);
    } catch (error) {
      console.error('Ошибка при создании задачи:', error);
      alert(language === "ru" ? 'Ошибка при сохранении задачи' : 'Error saving task');
    }
  };

  // Удаление задачи
  const deleteTask = async (taskId) => {
    if (window.confirm(language === "ru" ? 'Вы уверены, что хотите удалить это запланированное сканирование?' : 'Are you sure you want to delete this scheduled scan?')) {
      try {
        const response = await fetch(`http://localhost:8000/api/tasks/${taskId}`, {
          method: 'DELETE'
        });

        if (!response.ok) {
          throw new Error('Failed to delete task');
        }

        // Перезагружаем список задач
        await fetchTasks();
      } catch (error) {
        console.error('Ошибка при удалении задачи:', error);
        alert(language === "ru" ? 'Ошибка при удалении задачи' : 'Error deleting task');
      }
    }
  };

  // Редактирование задачи
  const editTask = async (task) => {
    setScheduleType(task.type);
    setScheduleTime(task.time);
    setScheduleDate(task.date || '');
    setScheduleDays(task.days || []);
    setScheduleMonthDay(task.monthDay || 1);
    setQuery(task.query);
    setActiveTools(task.activeTools);
    setAllowInternal(task.allowInternal);
    
    await deleteTask(task.id);
    setViewMode('create');
  };

  // Форматирование даты
  const formatNextRun = (nextRun) => {
    const date = new Date(nextRun);
    return date.toLocaleString(language === "ru" ? 'ru-RU' : 'en-US', {
      day: '2-digit',
      month: '2-digit',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  // Получение текста расписания
  const getScheduleText = (task) => {
    switch (task.type) {
      case 'once':
        const dateStr = language === "ru" 
          ? new Date(task.date).toLocaleDateString('ru-RU')
          : new Date(task.date).toLocaleDateString('en-US');
        return `${language === "ru" ? 'Однократно' : 'Once'} ${dateStr}`;
      case 'daily':
        return `${language === "ru" ? 'Ежедневно' : 'Daily'} в ${task.time}`;
      case 'weekly':
        const days = task.days.map(d => weekDays.find(w => w.id === d)?.name).join(', ');
        return `${language === "ru" ? 'Еженедельно' : 'Weekly'} (${days}) в ${task.time}`;
      case 'monthly':
        return `${language === "ru" ? 'Ежемесячно' : 'Monthly'} ${task.monthDay}-${language === "ru" ? 'го числа' : ''} в ${task.time}`;
      default:
        return '';
    }
  };

  // Переключение дня недели
  const toggleDay = (day) => {
    if (scheduleDays.includes(day)) {
      setScheduleDays(scheduleDays.filter(d => d !== day));
    } else {
      setScheduleDays([...scheduleDays, day]);
    }
  };

  if (!activeScheduleScanner) return null;

  return (
    <div className="schedule__scanner-menu active">
      <div className="schedule-header">
        <h3>📅 {language === "ru" ? 'Планировщик' : 'Scheduler'}</h3>
        <button 
          className="close-btn"
          onClick={() => setActiveScheduleScanner(false)}
        >
          ✕
        </button>
      </div>

      <div className="schedule-tabs">
        <button 
          className={viewMode === 'create' ? 'active' : ''}
          onClick={() => setViewMode('create')}
        >
          {language === "ru" ? '➕ Создать' : '➕ Create'}
        </button>
        <button 
          className={viewMode === 'list' ? 'active' : ''}
          onClick={() => setViewMode('list')}
        >
          {language === "ru" ? '📋 Задачи' : '📋 Tasks'} ({scheduledTasks.length})
        </button>
      </div>

      {viewMode === 'create' ? (
        <div className="schedule-form">
          {/* Цель сканирования - несколько URL'ов */}
          <div className="form-group">
            <label>🎯 {language === "ru" ? 'Цели' : 'Targets'}</label>
            <div className="urls-list">
              {Array.isArray(query) ? query.map((url, idx) => (
                <div key={idx} style={{ marginBottom: '8px', display: 'flex', gap: '8px' }}>
                  <input
                    type="text"
                    value={url}
                    onChange={(e) => {
                      const newUrls = [...query];
                      newUrls[idx] = e.target.value;
                      setQuery(newUrls);
                    }}
                    placeholder="https://example.com"
                    className="schedule-input"
                    style={{ flex: 1 }}
                  />
                  {query.length > 1 && (
                    <button
                      type="button"
                      onClick={() => setQuery(query.filter((_, i) => i !== idx))}
                      style={{
                        padding: '4px 8px',
                        backgroundColor: '#dc3545',
                        color: 'white',
                        border: 'none',
                        borderRadius: '3px',
                        cursor: 'pointer'
                      }}
                    >
                      ✕
                    </button>
                  )}
                </div>
              )) : (
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery([e.target.value])}
                  placeholder="https://example.com"
                  className="schedule-input"
                />
              )}
            </div>
            <button
              type="button"
              onClick={() => {
                const newUrls = Array.isArray(query) ? [...query, ''] : [query, ''];
                setQuery(newUrls);
              }}
              style={{
                marginTop: '6px',
                padding: '4px 12px',
                backgroundColor: '#6c757d',
                color: 'white',
                border: 'none',
                borderRadius: '3px',
                cursor: 'pointer',
                fontSize: '12px'
              }}
            >
              + {language === "ru" ? 'Добавить URL' : 'Add URL'}
            </button>
          </div>

          {/* Тип расписания */}
          <div className="form-group">
            <label>🔄 {language === "ru" ? 'Периодичность' : 'Frequency'}</label>
            <div className="schedule-type-buttons">
              <button 
                className={scheduleType === 'once' ? 'active' : ''}
                onClick={() => setScheduleType('once')}
              >
                {language === "ru" ? 'Однократно' : 'Once'}
              </button>
              <button 
                className={scheduleType === 'daily' ? 'active' : ''}
                onClick={() => setScheduleType('daily')}
              >
                {language === "ru" ? 'Ежедневно' : 'Daily'}
              </button>
              <button 
                className={scheduleType === 'weekly' ? 'active' : ''}
                onClick={() => setScheduleType('weekly')}
              >
                {language === "ru" ? 'Еженедельно' : 'Weekly'}
              </button>
              <button 
                className={scheduleType === 'monthly' ? 'active' : ''}
                onClick={() => setScheduleType('monthly')}
              >
                {language === "ru" ? 'Ежемесячно' : 'Monthly'}
              </button>
            </div>
          </div>

          {/* Дата и время */}
          <div className="form-row">
            <div className="form-group">
              <label>⏰ {language === "ru" ? 'Время' : 'Time'}</label>
              <input
                type="time"
                value={scheduleTime}
                onChange={(e) => setScheduleTime(e.target.value)}
                className="schedule-input time-input"
              />
            </div>

            {scheduleType === 'once' && (
              <div className="form-group">
                <label>📅 {language === "ru" ? 'Дата' : 'Date'}</label>
                <input
                  type="date"
                  value={scheduleDate}
                  onChange={(e) => setScheduleDate(e.target.value)}
                  min={new Date().toISOString().split('T')[0]}
                  className="schedule-input"
                />
              </div>
            )}

            {scheduleType === 'monthly' && (
              <div className="form-group">
                <label>📅 {language === "ru" ? 'День' : 'Day'}</label>
                <select 
                  value={scheduleMonthDay} 
                  onChange={(e) => setScheduleMonthDay(parseInt(e.target.value))}
                  className="schedule-select"
                >
                  {[...Array(28)].map((_, i) => (
                    <option key={i + 1} value={i + 1}>{i + 1}</option>
                  ))}
                </select>
              </div>
            )}
          </div>

          {/* Дни недели */}
          {scheduleType === 'weekly' && (
            <div className="form-group">
              <label>📆 {language === "ru" ? 'Дни недели' : 'Days of Week'}</label>
              <div className="weekdays-buttons">
                {weekDays.map(day => (
                  <button
                    key={day.id}
                    className={scheduleDays.includes(day.id) ? 'active' : ''}
                    onClick={() => toggleDay(day.id)}
                  >
                    {day.name}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Инструменты */}
          <div className="form-group">
            <label>🛠️ {language === "ru" ? 'Инструменты' : 'Tools'}</label>
            <div className="tools-selector">
              {toolsList.map(tool => (
                <button
                  key={tool.id}
                  className={`tool-btn ${activeTools.includes(tool.id) ? 'active' : ''}`}
                  onClick={() => {
                    if (activeTools.includes(tool.id)) {
                      setActiveTools(activeTools.filter(t => t !== tool.id));
                    } else {
                      setActiveTools([...activeTools, tool.id]);
                    }
                  }}
                >
                  <span className="tool-icon">{tool.icon}</span>
                  <span className="tool-label">{tool.label}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Внутренние адреса */}
          <div className="form-group checkbox-group">
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={allowInternal}
                onChange={(e) => setAllowInternal(e.target.checked)}
              />
              <span>{language === "ru" ? 'Разрешить внутренние адреса' : 'Allow internal addresses'}</span>
            </label>
          </div>

          {/* Кнопка */}
          <button className="schedule-submit-btn" onClick={addSchedule}>
            📅 {language === "ru" ? 'Запланировать' : 'Schedule'}
          </button>
        </div>
      ) : (
        <div className="scheduled-tasks-list">
          {scheduledTasks.length === 0 ? (
            <div className="empty-tasks">
              <p>📭 {language === "ru" ? 'Нет запланированных задач' : 'No scheduled tasks'}</p>
              <button onClick={() => setViewMode('create')}>
                {language === "ru" ? 'Создать задачу' : 'Create Task'}
              </button>
            </div>
          ) : (
            scheduledTasks.map(task => (
              <div key={task.id} className="task-item">
                <div className="task-header">
                  <div className="task-target">
                    <span className="target-icon">🎯</span>
                    <span className="target-text">
                      {task.urls ? task.urls.join(', ') : task.query}
                    </span>
                  </div>
                  <div className="task-actions">
                    <button 
                      className="edit-task-btn"
                      onClick={() => editTask(task)}
                      title={language === "ru" ? "Редактировать" : "Edit"}
                    >
                      ✏️
                    </button>
                    <button 
                      className="delete-task-btn"
                      onClick={() => deleteTask(task.id)}
                      title={language === "ru" ? "Удалить" : "Delete"}
                    >
                      🗑️
                    </button>
                  </div>
                </div>
                
                <div className="task-info">
                  <div className="task-schedule">
                    <span className="schedule-icon">🕐</span>
                    <span>{getScheduleText(task)}</span>
                  </div>
                  <div className="task-next-run">
                    <span className="next-icon">⏰</span>
                    <span>{language === "ru" ? 'Следующий' : 'Next'}: {formatNextRun(task.nextRun)}</span>
                  </div>
                  <div className="task-tools">
                    <span className="tools-icon">🛠️</span>
                    <span>{task.activeTools.map(t => t.toUpperCase()).join(', ')}</span>
                  </div>
                </div>

                {/* Информация о последнем сканировании */}
                {task.last_scan_folder && (
                  <div className="task-last-scan">
                    <div className="last-scan-header">
                      📁 {language === "ru" ? 'Последнее сканирование' : 'Last Scan'}
                    </div>
                    <div className="last-scan-info">
                      <div className="scan-folder">
                        <span className="folder-label">{language === "ru" ? 'Папка' : 'Folder'}:</span>
                        <span className="folder-id">{task.last_scan_folder}</span>
                      </div>
                      <div className="scan-time">
                        <span className="time-label">{language === "ru" ? 'Время' : 'Time'}:</span>
                        <span className="time-value">{task.last_scan_time}</span>
                      </div>
                      {task.scan_results && task.scan_results.length > 0 && (
                        <div className="scan-results">
                          <span className="results-label">{language === "ru" ? 'Результаты' : 'Results'}:</span>
                          <div className="results-list">
                            {task.scan_results.map((result, idx) => (
                              <div key={idx} className="result-item">
                                <span className="tool-name">{result.tool}</span>
                                <span className={`result-status ${result.success ? 'success' : 'error'}`}>
                                  {result.success ? '✓' : '✗'}
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
};

export default ScheduleScanner;