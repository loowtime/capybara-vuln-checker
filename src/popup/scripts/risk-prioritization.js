window.CapybaraRisk = {
  prioritize(finding, context = {}) {
    const reasons = [];
    const score = typeof finding.score === "number" ? finding.score : null;
    const epss = typeof finding.epss?.score === "number" ? finding.epss.score : null;
    const kev = finding.kev === true || finding.kev?.known === true;
    const confidence = finding.confidence ?? "unknown";
    const networkReachable = finding.attackHints?.includes("Netzwerk-Vektor") ?? false;
    const observedInBrowser = context.exposure === "browser-observed";

    if (kev) reasons.push("CISA führt die CVE im Known Exploited Vulnerabilities-Katalog.");
    if (epss !== null) {
      reasons.push(`FIRST EPSS schätzt die Ausnutzungswahrscheinlichkeit auf ${(epss * 100).toFixed(2)} %.`);
    }
    if (score !== null) reasons.push(`CVSS ${finding.version ?? ""} bewertet die Schwachstelle mit ${score.toFixed(1)}.`);
    if (networkReachable) reasons.push("Der CVSS-Vektor nennt Netzwerkzugriff.");
    if (observedInBrowser) reasons.push("Die betroffene Komponente wurde im Browser-Kontext beobachtet; öffentliche Erreichbarkeit ist damit nicht bewiesen.");
    reasons.push(`Erkennungsvertrauen: ${confidence}.`);

    let level = "unbestimmt";
    if (kev && networkReachable && confidence !== "low") {
      level = "kritisch";
    } else if (kev || (score !== null && score >= 9 && confidence === "high")) {
      level = "hoch";
    } else if (
      (score !== null && score >= 7 && (epss === null || epss >= 0.01)) ||
      (epss !== null && epss >= 0.1 && networkReachable)
    ) {
      level = "hoch";
    } else if ((score !== null && score >= 4) || (epss !== null && epss >= 0.01)) {
      level = "mittel";
    } else if (score !== null || epss !== null || finding.kev === false) {
      level = "niedrig";
    }
    if (confidence === "low" && level === "kritisch") level = "hoch";

    if (!score && epss === null && !finding.kev) {
      reasons.push("Für diese Einstufung fehlen quantitative CVSS-, EPSS- und KEV-Daten.");
    }
    return { level, reasons, observedInBrowser };
  },

  prioritizeAll(findings, context = {}) {
    return findings.map((finding) => ({
      ...finding,
      risk: this.prioritize(finding, context)
    })).sort((left, right) => {
      const order = { kritisch: 0, hoch: 1, mittel: 2, niedrig: 3, unbestimmt: 4 };
    return Number(right.kev === true || right.kev?.known === true) -
      Number(left.kev === true || left.kev?.known === true) ||
      (order[left.risk.level] ?? 4) - (order[right.risk.level] ?? 4) ||
      (right.score ?? -1) - (left.score ?? -1);
    });
  }
};
