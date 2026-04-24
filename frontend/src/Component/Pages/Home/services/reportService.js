
/**
 * Сервис для управления отчетами
 */
export const reportService = {
    async downloadWordReport(filename) {
        const response = await fetch(
            `http://localhost:8000/api/download-word-report?filename=${encodeURIComponent(filename)}`,
            {
                method: 'GET',
                headers: {
                    'Accept': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
                }
            }
        );
        if (!response.ok) throw new Error(`Ошибка при скачивании файла: ${response.statusText}`);
        const blob = await response.blob();
        
        // Убеждаемся что файл имеет расширение .docx
        const finalFilename = filename.endsWith('.docx') ? filename : filename + '.docx';
        this._downloadBlob(blob, finalFilename);
    },

    async downloadCombinedReport(filename, reportType = 'json') {
        const types = {
            'json': 'application/json',
            'txt': 'text/plain',
            'word': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        };
        
        const response = await fetch(
            `http://localhost:8000/api/download-combined-report?filename=${encodeURIComponent(filename)}&report_type=${reportType}`,
            {
                method: 'GET',
                headers: {
                    'Accept': types[reportType] || 'application/octet-stream'
                }
            }
        );
        if (!response.ok) throw new Error(`Ошибка при скачивании файла: ${response.statusText}`);
        const blob = await response.blob();
        
        // Определяем правильное расширение файла
        const extension = (reportType === 'word' || reportType === 'docx') ? '.docx' : `.${reportType}`;
        const finalFilename = filename.endsWith(extension) ? filename : filename + extension;
        
        this._downloadBlob(blob, finalFilename);
    },

    async downloadTxtReport(tool, filename) {
        const response = await fetch(
            `http://localhost:8000/api/download-txt-report?tool=${encodeURIComponent(tool)}&filename=${encodeURIComponent(filename)}`
        );
        if (!response.ok) throw new Error('Ошибка при скачивании файла');
        const blob = await response.blob();
        this._downloadBlob(blob, filename);
    },

    async deleteWordReport(filename) {
        const response = await fetch(
            `http://localhost:8000/api/delete-word-report?filename=${encodeURIComponent(filename)}`,
            { method: 'DELETE' }
        );
        if (!response.ok) throw new Error('Ошибка при удалении файла');
    },

    async deleteTxtReport(tool, filename) {
        const response = await fetch(
            `http://localhost:8000/api/delete-txt-report?tool=${encodeURIComponent(tool)}&filename=${encodeURIComponent(filename)}`,
            { method: 'DELETE' }
        );
        if (!response.ok) throw new Error('Ошибка при удалении файла');
    },

    async deleteCombinedReport(filename, reportType = 'json') {
        const response = await fetch(
            `http://localhost:8000/api/delete-combined-report?filename=${encodeURIComponent(filename)}&report_type=${reportType}`,
            { method: 'DELETE' }
        );
        if (!response.ok) throw new Error('Ошибка при удалении файла');
    },

    async deleteAllWordReports() {
        const response = await fetch(`http://localhost:8000/api/delete-word-report`, {
            method: 'DELETE'
        });
        if (!response.ok) throw new Error('Ошибка при удалении файлов');
    },

    async clearAllReports() {
        const response = await fetch(`http://localhost:8000/api/clear-all-reports`, {
            method: 'DELETE'
        });
        if (!response.ok) throw new Error('Ошибка при очистке отчетов');
        return await response.json();
    },

    async getReportContent(filename, reportType = 'json') {
        try {
            const response = await fetch(
                `http://localhost:8000/api/get-report-content?filename=${encodeURIComponent(filename)}&report_type=${reportType}`
            );
            if (!response.ok) throw new Error(`Ошибка при загрузке отчета: ${response.statusText}`);
            const data = await response.text();
            return data;
        } catch (error) {
            console.error('Ошибка при загрузке содержимого отчета:', error);
            throw error;
        }
    },

    _downloadBlob(blob, filename) {
        try {
            const url = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = filename || 'report';
            document.body.appendChild(link);
            link.click();
            
            // Очищаем ресурсы
            setTimeout(() => {
                document.body.removeChild(link);
                window.URL.revokeObjectURL(url);
            }, 100);
        } catch (error) {
            console.error('Ошибка при скачивании файла:', error);
            throw new Error(`Ошибка при скачивании файла: ${error.message}`);
        }
    }
};