import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom";
import CompletedScanCard from "./CompletedScanCard";

describe("CompletedScanCard report downloads", () => {
  test("offers a Markdown download when the combined Markdown report exists", () => {
    const onDownloadReport = jest.fn();
    render(
      <CompletedScanCard
        results={{
          target: "example.org",
          scan_id: "scan-123",
          combined_reports: { md: "/reports/combined_report.md" },
        }}
        onDownloadReport={onDownloadReport}
        onDownloadContent={jest.fn()}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /markdown/i }));

    expect(onDownloadReport).toHaveBeenCalledWith("combined_report.md", "md");
  });

  test("offers Word, JSON and TXT downloads when report files are present", () => {
    const onDownloadReport = jest.fn();
    render(
      <CompletedScanCard
        results={{
          target: "example.org",
          scan_id: "scan-123",
          tools_executed: ["wappalyzer"],
          combined_reports: {
            json: "/reports/combined_report.json",
            txt: "/reports/combined_report.txt",
            docx: "/reports/combined_report.docx",
          },
        }}
        onDownloadReport={onDownloadReport}
        onDownloadContent={jest.fn()}
      />,
    );

    expect(screen.getByRole("button", { name: /word/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /json/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /txt/i })).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /word/i }));
    fireEvent.click(screen.getByRole("button", { name: /json/i }));
    fireEvent.click(screen.getByRole("button", { name: /txt/i }));

    expect(onDownloadReport).toHaveBeenNthCalledWith(1, "combined_report.docx", "word");
    expect(onDownloadReport).toHaveBeenNthCalledWith(2, "combined_report.json", "json");
    expect(onDownloadReport).toHaveBeenNthCalledWith(3, "combined_report.txt", "txt");
  });

  test("creates a TXT download from scan results when no TXT file exists", () => {
    const onDownloadContent = jest.fn();
    render(
      <CompletedScanCard
        results={{
          target: "example.org",
          scan_id: "scan-123",
          tools_executed: ["wappalyzer"],
          results: { wappalyzer: { status: "no_findings" } },
          combined_reports: { json: "/reports/combined_report.json" },
        }}
        onDownloadReport={jest.fn()}
        onDownloadContent={onDownloadContent}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /txt/i }));

    expect(onDownloadContent).toHaveBeenCalledWith(
      expect.stringContaining("example.org"),
      "CyberScope_scan-123.txt",
      "text/plain;charset=utf-8",
    );
  });

  test("shows a partial-error status without hiding the downloads", () => {
    render(
      <CompletedScanCard
        results={{
          status: "error",
          target: "example.org",
          scan_id: "scan-123",
          tools_executed: ["whois"],
          combined_reports: {
            json: "/reports/combined_report.json",
            txt: "/reports/combined_report.txt",
          },
        }}
        onDownloadReport={jest.fn()}
        onDownloadContent={jest.fn()}
      />,
    );

    expect(screen.getByText("Завершено с ошибками")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /json/i })).toBeEnabled();
    expect(screen.getByRole("button", { name: /txt/i })).toBeEnabled();
  });
});
