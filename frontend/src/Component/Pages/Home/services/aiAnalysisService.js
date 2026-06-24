import axios from "axios";

const API_BASE_URL = "http://localhost:8000";

const aiAnalysisService = {
  
  async analyzeReport(filePath) {
    try {
      const token = localStorage.getItem("token");
      const response = await axios.post(
        `${API_BASE_URL}/api/analyze-report`,
        {
          file_path: filePath,
        },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );
      return response.data;
    } catch (error) {
      console.error("Error analyzing report:", error);
      throw error;
    }
  },

  /**
   * Проверить статус LM Studio
   * @returns {Promise} - Статус подключения к LM Studio
   */
  async checkLMStudioStatus() {
    try {
      const response = await axios.get(
        `${API_BASE_URL}/api/lm-studio-status`
      );
      return response.data;
    } catch (error) {
      console.error("Error checking LM Studio status:", error);
      return {
        status: "offline",
        message: "LM Studio не доступен",
      };
    }
  },

  /**
   * Проанализировать JSON отчет с предоставленными данными
   * @param {Object} reportData - Данные отчета в JSON формате
   * @returns {Promise} - Результат анализа
   */
  async analyzeReportData(reportData) {
    try {
      const token = localStorage.getItem("token");
      const response = await axios.post(
        `${API_BASE_URL}/api/analyze-report`,
        reportData,
        {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        }
      );
      return response.data;
    } catch (error) {
      console.error("Error analyzing report data:", error);
      throw error;
    }
  },
};

export default aiAnalysisService;
