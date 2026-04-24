/**
 * Сервис для запуска сканирования
 */
export const scanService = {
    async runScan(target, tools, allowInternal, abortSignal) {
        const toolsParam = tools.join(',');
        const endpoint = `/api/run-selected-tools?target=${encodeURIComponent(target)}&tools=${encodeURIComponent(toolsParam)}&allow_internal=${allowInternal}`;
        
        // Получаем токен из localStorage
        const token = localStorage.getItem('token');
        if (!token) {
            throw new Error('Требуется аутентификация. Пожалуйста, войдите.');
        }
        
        const response = await fetch(`http://localhost:8000${endpoint}`, {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            signal: abortSignal
        });

        if (!response.ok) {
            let errorDetail = 'Ошибка при запросе';
            try {
                const errorData = await response.json();
                errorDetail = errorData.detail || errorDetail;
            } catch (e) {
                errorDetail = await response.text() || errorDetail;
            }
            throw new Error(`HTTP ${response.status}: ${errorDetail}`);
        }

        return await response.json();
    },

    validateInput(target, tools) {
        if (!target.trim()) {
            throw new Error('Пожалуйста, введите адрес сайта');
        }
        if (tools.length === 0) {
            throw new Error('Пожалуйста, выберите хотя бы один инструмент');
        }
    }
};
