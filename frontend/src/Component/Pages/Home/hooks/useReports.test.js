import { renderHook, waitFor } from "@testing-library/react";
import { apiFetch } from "../../../../api";
import { useReports } from "./useReports";

jest.mock("../../../../api", () => ({ apiFetch: jest.fn() }));

describe("useReports combined report mapping", () => {
  beforeEach(() => {
    apiFetch.mockImplementation((path) => {
      if (path === "/api/combined-reports") {
        return Promise.resolve({
          json: () => Promise.resolve({
            status: "success",
            json_reports: ["combined.json"],
            txt_reports: ["combined.txt"],
            word_reports: ["combined.docx"],
            md_reports: ["combined.md"],
          }),
        });
      }

      return Promise.resolve({
        json: () => Promise.resolve({ status: "success", reports: [] }),
      });
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  test("includes Markdown filenames from the combined reports response", async () => {
    const { result } = renderHook(() => useReports());

    await waitFor(() => {
      expect(result.current.combinedReports).toEqual({
        json: ["combined.json"],
        txt: ["combined.txt"],
        word: ["combined.docx"],
        md: ["combined.md"],
      });
    });
  });
});
