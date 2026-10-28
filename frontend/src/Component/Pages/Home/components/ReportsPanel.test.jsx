import React from "react";
import { fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom";
import ReportsPanel from "./ReportsPanel";

const renderReportsPanel = (overrides = {}) => {
  const props = {
    wordReports: [],
    loadingReports: false,
    txtReports: {},
    loadingTxtReports: false,
    combinedReports: {
      json: ["combined_report.json"],
      txt: [],
      word: [],
      md: ["combined_report.md"],
    },
    loadingCombined: false,
    combinedReportFilter: "all",
    setCombinedReportFilter: jest.fn(),
    fetchWordReports: jest.fn(),
    fetchCombinedReports: jest.fn(),
    fetchTxtReports: jest.fn(),
    downloadWordReport: jest.fn(),
    downloadCombinedReport: jest.fn(),
    downloadTxtReport: jest.fn(),
    deleteWordReport: jest.fn(),
    deleteCombinedReport: jest.fn(),
    deleteTxtReport: jest.fn(),
    deleteAllWordReports: jest.fn(),
    openReportViewer: jest.fn(),
    openAIAnalysis: jest.fn(),
    clearAllReports: jest.fn(),
    ...overrides,
  };
  return { ...render(<ReportsPanel {...props} language="en" />), props };
};

describe("ReportsPanel Markdown reports", () => {
  test("filters, downloads, and deletes Markdown combined reports", () => {
    const { props, rerender } = renderReportsPanel();

    fireEvent.click(screen.getByRole("button", { name: /MD \(1\)/i }));
    expect(props.setCombinedReportFilter).toHaveBeenCalledWith("md");
    rerender(<ReportsPanel {...props} language="en" combinedReportFilter="md" />);
    expect(screen.getByTitle("combined_report.md")).toBeInTheDocument();
    expect(screen.queryByTitle("combined_report.json")).not.toBeInTheDocument();

    const row = screen.getByTitle("combined_report.md").parentElement.parentElement;
    const [viewButton, downloadButton, deleteButton] = row.querySelectorAll("button");
    fireEvent.click(viewButton);
    fireEvent.click(downloadButton);
    fireEvent.click(deleteButton);

    expect(props.openReportViewer).toHaveBeenCalledWith("combined_report.md", "md");
    expect(props.downloadCombinedReport).toHaveBeenCalledWith("combined_report.md", "md");
    expect(props.deleteCombinedReport).toHaveBeenCalledWith("combined_report.md", "md");
  });

  test("can load a saved JSON report into the results panel", () => {
    const onSelectCombinedReport = jest.fn();
    const { props } = renderReportsPanel({ onSelectCombinedReport });
    const selectButton = screen.getByRole("button", {
      name: "Показать результаты combined_report.json",
    });

    fireEvent.click(selectButton);

    expect(onSelectCombinedReport).toHaveBeenCalledWith("combined_report.json");
    expect(props.openReportViewer).not.toHaveBeenCalled();
  });
});
