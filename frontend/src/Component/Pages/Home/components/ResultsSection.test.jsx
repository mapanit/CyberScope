import React from "react";
import { render, screen } from "@testing-library/react";
import "@testing-library/jest-dom";
import ResultsSection from "./ResultsSection";

describe("ResultsSection scan statuses", () => {
  test("renders the completed report card before per-tool results", () => {
    const renderCombinedResults = jest.fn(() => <div>Отчет готов</div>);
    render(
      <ResultsSection
        results={{
          status: "success",
          target: "example.org",
          results: { wappalyzer: { status: "success" } },
          combined_reports: { json: "/reports/report.json", txt: "/reports/report.txt" },
        }}
        scanAborted={false}
        expandedJsonTools={{}}
        setExpandedJsonTools={() => {}}
        renderScannerResults={() => null}
        renderCombinedResults={renderCombinedResults}
      />,
    );

    expect(screen.getByText("Отчет готов")).toBeInTheDocument();
    expect(renderCombinedResults).toHaveBeenCalled();
    expect(screen.queryByText("WAPPALYZER")).not.toBeInTheDocument();
  });

  test("keeps report downloads available when a tool fails", () => {
    const renderCombinedResults = jest.fn(() => <div>Отчет доступен</div>);
    render(
      <ResultsSection
        results={{
          status: "error",
          target: "example.org",
          results: { whois: { status: "error", error: "WHOIS parser error" } },
          combined_reports: { json: "/reports/report.json", txt: "/reports/report.txt" },
        }}
        scanAborted={false}
        expandedJsonTools={{}}
        setExpandedJsonTools={() => {}}
        renderScannerResults={() => null}
        renderCombinedResults={renderCombinedResults}
      />,
    );

    expect(screen.getByText("Отчет доступен")).toBeInTheDocument();
    expect(renderCombinedResults).toHaveBeenCalled();
  });

  test("shows the backend error when queued scan result generation fails", () => {
    render(
      <ResultsSection
        results={{
          status: "error",
          target: "example.org",
          results: {},
          combined_reports: {},
          error: "report generation failed",
        }}
        scanAborted={false}
        expandedJsonTools={{}}
        setExpandedJsonTools={() => {}}
        renderScannerResults={() => null}
        renderCombinedResults={() => null}
      />,
    );

    expect(screen.getByRole("alert")).toHaveTextContent(
      "report generation failed",
    );
  });

  test.each([
    ["success", "Успешно"],
    ["no_findings", "Находок нет"],
    ["error", "Ошибка"],
    ["timeout", "Тайм-аут"],
    ["cancelled", "Отменено"],
  ])("shows %s status", (status, label) => {
    render(
      <ResultsSection
        results={{
          status: "error",
          target: "example.org",
          results: {
            scanner: { status, message: "test status" },
          },
        }}
        scanAborted={false}
        expandedJsonTools={{}}
        setExpandedJsonTools={() => {}}
        renderScannerResults={() => null}
        renderCombinedResults={() => null}
      />,
    );

    expect(screen.getAllByText(label).length).toBeGreaterThan(0);
  });
});
