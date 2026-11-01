window.CapybaraReports = {
  csv(findings) {
    const columns = [
      "id", "priority", "cvss", "epss", "kev", "product", "version",
      "source", "confidence", "detectionMethod", "observedAt", "description",
      "recommendation", "remediationPriority", "remediationSlaDays",
      "remediationDueDate", "remediationStatus", "verificationRequired",
      "technicalEvidence", "riskReasons"
    ];
    const quote = (value) => {
      let text = String(value ?? "");
      if (/^[\u0000-\u0020]*[=+\-@]/.test(text)) text = `'${text}`;
      return `"${text.replaceAll('"', '""')}"`;
    };
    const rows = findings.map((finding) => [
      finding.id,
      finding.risk?.level,
      finding.score,
      finding.epss?.score,
      finding.kev?.known,
      finding.product,
      finding.productVersion,
      finding.source,
      finding.confidence,
      finding.detectionMethod,
      finding.observedAt,
      finding.description,
      finding.remediation?.action,
      finding.remediation?.priority,
      finding.remediation?.slaDays,
      finding.remediation?.dueDate,
      finding.remediation?.status,
      finding.remediation?.verificationRequired,
      JSON.stringify(finding.technicalEvidence ?? {}),
      finding.risk?.reasons?.join("; ")
    ]);
    return [columns, ...rows].map((row) => row.map(quote).join(",")).join("\r\n");
  },

  download(content, fileName, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = fileName;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  },

  exportJson(report) {
    this.download(JSON.stringify(report, null, 2), "capybara-security-report.json", "application/json");
  },

  exportCsv(findings) {
    this.download(this.csv(findings), "capybara-findings.csv", "text/csv;charset=utf-8");
  }
};
