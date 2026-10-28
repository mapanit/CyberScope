import { apiFetch } from "../../../../api";
import { scanService } from "./scanService";

jest.mock("../../../../api", () => ({
  apiFetch: jest.fn(),
}));

describe("scanService queued scans", () => {
  beforeEach(() => {
    apiFetch.mockReset();
    jest.spyOn(scanService, "delay").mockResolvedValue();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test("submits a scan, reports progress, and fetches terminal results", async () => {
    apiFetch
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ status: "queued", scan_id: "scan-1" }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ scan_status: "success", progress: 100 }),
      })
      .mockResolvedValueOnce({
        ok: true,
        json: async () => ({ status: "success", results: { scanner: {} } }),
      });
    const onProgress = jest.fn();

    const result = await scanService.runScan(
      "https://example.org",
      ["scanner"],
      false,
      undefined,
      "scan-1",
      onProgress,
    );

    expect(apiFetch.mock.calls[0][0]).toContain("/api/scans?");
    expect(apiFetch.mock.calls[1][0]).toContain("/api/scan-status?");
    expect(apiFetch.mock.calls[2][0]).toContain("/api/scan-results?");
    expect(onProgress).toHaveBeenCalledWith({ status: "queued", scan_id: "scan-1" });
    expect(result.results.scanner).toEqual({});
  });

  test("surfaces API errors when queue submission fails", async () => {
    apiFetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      json: async () => ({ detail: "Unknown scanner" }),
    });

    await expect(
      scanService.runScan("https://example.org", ["missing"], false, undefined, "scan-2"),
    ).rejects.toThrow("HTTP 400: Unknown scanner");
  });
});
