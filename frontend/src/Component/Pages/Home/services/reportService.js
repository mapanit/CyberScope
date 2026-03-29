
/**
 * Сервис для управления отчетами
 */
export const reportService = {
    async downloadWordReport(filename) {
        const response = await fetch(`http://localhost:8000/api/download-word-report?filename=${encodeURIComponent(filename)}`);
        if (!response.ok) throw new Error('Ошибка при скачивании файла');
        const blob = await response.blob();
        this._downloadBlob(blob, filename);
    },

    async downloadCombinedReport(filename, reportType = 'json') {
        const response = await fetch(
            `http://localhost:8000/api/download-combined-report?filename=${encodeURIComponent(filename)}&report_type=${reportType}`
        );
        if (!response.ok) throw new Error('Ошибка при скачивании файла');
        const blob = await response.blob();
        this._downloadBlob(blob, filename);
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

    _downloadBlob(blob, filename) {
        const link = document.createElement('a');
        link.href = window.URL.createObjectURL(blob);
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(link.href);
    }
};
