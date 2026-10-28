import { apiFetch } from "../../../../api";

/**
 * Сервис для запуска сканирования
 */
export const scanService = {
  async runScan(target, tools, allowInternal, abortSignal, scanId, onProgress) {
    const toolsParam = tools.join(",");
    const params = new URLSearchParams({
      target,
      tools: toolsParam,
      allow_internal: String(allowInternal),
      scan_id: scanId,
    });
    const response = await apiFetch(`/api/scans?${params}`, {
      method: "POST",
      headers: {
        Accept: "application/json",
      },
      signal: abortSignal,
    });

    const queued = await this.readResponse(response);
    onProgress?.(queued);

    while (true) {
      await this.delay(1000, abortSignal);
      const statusParams = new URLSearchParams({ scan_id: scanId });
      const statusResponse = await apiFetch(`/api/scan-status?${statusParams}`, {
        signal: abortSignal,
      });
      const status = await this.readResponse(statusResponse);
      onProgress?.(status);

      if (["success", "completed", "cancelled", "timeout", "error"].includes(status.scan_status)) {
        const resultsResponse = await apiFetch(`/api/scan-results?${statusParams}`, {
          signal: abortSignal,
        });
        return this.readResponse(resultsResponse);
      }
    }
  },

  async readResponse(response) {
    if (!response.ok) {
      let errorDetail = "Ошибка при запросе";
      try {
        const errorData = await response.json();
        errorDetail = errorData.detail || errorDetail;
      } catch {
        errorDetail = (await response.text()) || errorDetail;
      }
      throw new Error(`HTTP ${response.status}: ${errorDetail}`);
    }
    return response.json();
  },

  delay(milliseconds, signal) {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) {
        reject(new DOMException("Aborted", "AbortError"));
        return;
      }
      const timeout = setTimeout(() => {
        signal?.removeEventListener("abort", abort);
        resolve();
      }, milliseconds);
      const abort = () => {
        clearTimeout(timeout);
        reject(new DOMException("Aborted", "AbortError"));
      };
      signal?.addEventListener("abort", abort, { once: true });
    });
  },

  validateInput(target, tools) {
    if (!target.trim()) {
      throw new Error("Пожалуйста, введите адрес сайта");
    }
    if (tools.length === 0) {
      throw new Error("Пожалуйста, выберите хотя бы один инструмент");
    }
  },
};
