import { apiFetch } from "../../../../api";
import { reportService } from "./reportService";

jest.mock("../../../../api", () => ({ apiFetch: jest.fn() }));

describe("reportService Markdown combined reports", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  test("downloads Markdown with its content type and extension", async () => {
    apiFetch.mockResolvedValue({
      ok: true,
      blob: jest.fn().mockResolvedValue(new Blob(["# Report"])),
    });
    const downloadBlob = jest.spyOn(reportService, "_downloadBlob").mockImplementation(() => {});

    await reportService.downloadCombinedReport("combined_report", "md");

    expect(apiFetch).toHaveBeenCalledWith(
      "/api/download-combined-report?filename=combined_report&report_type=md",
      expect.objectContaining({ headers: { Accept: "text/markdown" } }),
    );
    expect(downloadBlob).toHaveBeenCalledWith(expect.any(Blob), "combined_report.md");
  });

  test("deletes Markdown reports through the combined report endpoint", async () => {
    apiFetch.mockResolvedValue({ ok: true });

    await reportService.deleteCombinedReport("combined_report.md", "md");

    expect(apiFetch).toHaveBeenCalledWith(
      "/api/delete-combined-report?filename=combined_report.md&report_type=md",
      { method: "DELETE" },
    );
  });
});
