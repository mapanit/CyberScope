import React, { useState, useEffect } from 'react';
import './ScheduleScanner.scss';

const ScheduleScanner = ({ activeScheduleScanner, setActiveScheduleScanner, activeTools, setActiveTools, query, setQuery, allowInternal, setAllowInternal, onSchedule }) => {
  const [scheduleType, setScheduleType] = useState('once');
  const [scheduleTime, setScheduleTime] = useState('');
  const [scheduleDate, setScheduleDate] = useState('');
  const [scheduleDays, setScheduleDays] = useState([]);
  const [scheduleMonthDay, setScheduleMonthDay] = useState(1);
  const [scheduledTasks, setScheduledTasks] = useState([]);
  const [viewMode, setViewMode] = useState('create'); // 'create' or 'list'
  
  const weekDays = [
    { id: '0', name: 'Вс' },
    { id: '1', name: 'Пн' },
    { id: '2', name: 'Вт' },
    { id: '3', name: 'Ср' },
    { id: '4', name: 'Чт' },
    { id: '5', name: 'Пт' },
    { id: '6', name: 'Сб' }
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
    const saved = localStorage.getItem('scheduledScans');
    if (saved) {
      setScheduledTasks(JSON.parse(saved));
    }
  }, []);

  // Сохранение задач
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
  const addSchedule = () => {
    if (!query.trim()) {
      alert('Пожалуйста, введите цель сканирования');
      return;
    }

    if (!scheduleTime) {
      alert('Пожалуйста, выберите время');
      return;
    }

    if (scheduleType === 'once' && !scheduleDate) {
      alert('Пожалуйста, выберите дату');
      return;
    }

    if (scheduleType === 'weekly' && scheduleDays.length === 0) {
      alert('Пожалуйста, выберите дни недели');
      return;
    }

    if (activeTools.length === 0) {
      alert('Пожалуйста, выберите хотя бы один инструмент');
      return;
    }

    const nextRun = calculateNextRun();
    
    if (!nextRun) {
      alert('Пожалуйста, заполните все обязательные поля');
      return;
    }

    const now = new Date();
    if (nextRun <= now && scheduleType === 'once') {
      alert('Время сканирования должно быть в будущем');
      return;
    }

    const newTask = {
      id: Date.now(),
      type: scheduleType,
      time: scheduleTime,
      date: scheduleDate,
      days: scheduleDays,
      monthDay: scheduleMonthDay,
      query: query.trim(),
      activeTools: [...activeTools],
      allowInternal: allowInternal,
      nextRun: nextRun.toISOString(),
      createdAt: now.toISOString(),
      status: 'pending',
      lastRun: null
    };

    const updatedTasks = [...scheduledTasks, newTask];
    saveTasks(updatedTasks);
    
    if (onSchedule) {
      onSchedule(newTask);
    }

    alert('✅ Сканирование успешно запланировано!');
    
    // Сброс формы
    setScheduleType('once');
    setScheduleTime('');
    setScheduleDate('');
    setScheduleDays([]);
    setScheduleMonthDay(1);
  };

  // Удаление задачи
  const deleteTask = (taskId) => {
    if (window.confirm('Вы уверены, что хотите удалить это запланированное сканирование?')) {
      const updatedTasks = scheduledTasks.filter(task => task.id !== taskId);
      saveTasks(updatedTasks);
    }
  };

  // Редактирование задачи
  const editTask = (task) => {
    setScheduleType(task.type);
    setScheduleTime(task.time);
    setScheduleDate(task.date || '');
    setScheduleDays(task.days || []);
    setScheduleMonthDay(task.monthDay || 1);
    setQuery(task.query);
    setActiveTools(task.activeTools);
    setAllowInternal(task.allowInternal);
    
    deleteTask(task.id);
    setViewMode('create');
  };

  // Форматирование даты
  const formatNextRun = (nextRun) => {
    const date = new Date(nextRun);
    return date.toLocaleString('ru-RU', {
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
        return `Однократно ${new Date(task.date).toLocaleDateString('ru-RU')}`;
      case 'daily':
        return `Ежедневно в ${task.time}`;
      case 'weekly':
        const days = task.days.map(d => weekDays.find(w => w.id === d)?.name).join(', ');
        return `Еженедельно (${days}) в ${task.time}`;
      case 'monthly':
        return `Ежемесячно ${task.monthDay}-го числа в ${task.time}`;
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
        <h3>📅 Планировщик</h3>
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
          ➕ Создать
        </button>
        <button 
          className={viewMode === 'list' ? 'active' : ''}
          onClick={() => setViewMode('list')}
        >
          📋 Задачи ({scheduledTasks.length})
        </button>
      </div>

      {viewMode === 'create' ? (
        <div className="schedule-form">
          {/* Цель сканирования */}
          <div className="form-group">
            <label>🎯 Цель</label>
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="https://example.com"
              className="schedule-input"
            />
          </div>

          {/* Тип расписания */}
          <div className="form-group">
            <label>🔄 Периодичность</label>
            <div className="schedule-type-buttons">
              <button 
                className={scheduleType === 'once' ? 'active' : ''}
                onClick={() => setScheduleType('once')}
              >
                Однократно
              </button>
              <button 
                className={scheduleType === 'daily' ? 'active' : ''}
                onClick={() => setScheduleType('daily')}
              >
                Ежедневно
              </button>
              <button 
                className={scheduleType === 'weekly' ? 'active' : ''}
                onClick={() => setScheduleType('weekly')}
              >
                Еженедельно
              </button>
              <button 
                className={scheduleType === 'monthly' ? 'active' : ''}
                onClick={() => setScheduleType('monthly')}
              >
                Ежемесячно
              </button>
            </div>
          </div>

          {/* Дата и время */}
          <div className="form-row">
            <div className="form-group">
              <label>⏰ Время</label>
              <input
                type="time"
                value={scheduleTime}
                onChange={(e) => setScheduleTime(e.target.value)}
                className="schedule-input time-input"
              />
            </div>

            {scheduleType === 'once' && (
              <div className="form-group">
                <label>📅 Дата</label>
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
                <label>📅 День</label>
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
              <label>📆 Дни недели</label>
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
            <label>🛠️ Инструменты</label>
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
              <span>Разрешить внутренние адреса</span>
            </label>
          </div>

          {/* Кнопка */}
          <button className="schedule-submit-btn" onClick={addSchedule}>
            📅 Запланировать
          </button>
        </div>
      ) : (
        <div className="scheduled-tasks-list">
          {scheduledTasks.length === 0 ? (
            <div className="empty-tasks">
              <p>📭 Нет запланированных задач</p>
              <button onClick={() => setViewMode('create')}>
                Создать задачу
              </button>
            </div>
          ) : (
            scheduledTasks.map(task => (
              <div key={task.id} className="task-item">
                <div className="task-header">
                  <div className="task-target">
                    <span className="target-icon">🎯</span>
                    <span className="target-text">{task.query}</span>
                  </div>
                  <div className="task-actions">
                    <button 
                      className="edit-task-btn"
                      onClick={() => editTask(task)}
                      title="Редактировать"
                    >
                      ✏️
                    </button>
                    <button 
                      className="delete-task-btn"
                      onClick={() => deleteTask(task.id)}
                      title="Удалить"
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
                    <span>Следующий: {formatNextRun(task.nextRun)}</span>
                  </div>
                  <div className="task-tools">
                    <span className="tools-icon">🛠️</span>
                    <span>{task.activeTools.map(t => t.toUpperCase()).join(', ')}</span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      )}
    </div>
  );
};

export default ScheduleScanner;