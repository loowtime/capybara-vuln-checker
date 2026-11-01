window.CapybaraRisk = {
  prioritize(finding, context = {}) {
    const reasons = [];
    const score = typeof finding.score === "number" ? finding.score : null;
    const epss = typeof finding.epss?.score === "number" ? finding.epss.score : null;
    const kev = finding.kev === true || finding.kev?.known === true;
    const kevKnown = kev || finding.kev === false || finding.kev?.known === false;
    const confidence = finding.confidence ?? "unknown";
    const matchConfidence = finding.matchConfidence?.level ?? "unknown";
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
    if (finding.matchConfidence) {
      reasons.push(`Match-Confidence: ${finding.matchConfidence.level} (${finding.matchConfidence.score}/100), kein Verwundbarkeitsnachweis.`);
    }

    let level = "unbestimmt";
    const weakMatch = confidence === "low" ||
      matchConfidence === "low" ||
      matchConfidence === "unknown";
    if (kev && networkReachable && !weakMatch) {
      level = "kritisch";
    } else if (kev) {
      level = weakMatch ? "mittel" : "hoch";
      if (weakMatch) reasons.push("Die KEV-Einstufung bleibt relevant, aber die schwache Komponenten-/Versionszuordnung senkt die unmittelbare Triage-Priorität.");
    } else if (score !== null && score >= 9 && !weakMatch) {
      level = "hoch";
    } else if (
      ((score !== null && score >= 7 && (epss === null || epss >= 0.01)) ||
        (epss !== null && epss >= 0.1 && networkReachable)) &&
      !weakMatch
    ) {
      level = "hoch";
    } else if ((score !== null && score >= 4) || (epss !== null && epss >= 0.01)) {
      level = "mittel";
      if (weakMatch) {
        level = "niedrig";
        reasons.push("Die schwache Komponenten-/Versionszuordnung senkt die Priorität bis zur Verifikation.");
      }
    } else if (score !== null || epss !== null || kevKnown) {
      level = "niedrig";
    }

    if (score === null && epss === null && !kevKnown) {
      reasons.push("Für diese Einstufung fehlen quantitative CVSS-, EPSS- und KEV-Daten.");
    }
    const decision = level === "kritisch"
      ? "KEV plus Netzwerk-Angriffsvektor und ausreichende Zuordnungsqualität."
      : level === "hoch"
        ? "Hoher CVSS-/EPSS-Hinweis oder KEV-Status bei ausreichender Zuordnungsqualität."
        : level === "mittel"
          ? "Moderater CVSS-/EPSS-Hinweis oder KEV mit schwacher Produkt-/Versionszuordnung."
          : level === "niedrig"
            ? "Messbare Daten liegen vor, die Schwellen für mittlere Priorität werden aber nicht erreicht oder die Zuordnung ist schwach."
            : "Für eine belastbare Einstufung fehlen verwertbare CVSS-, EPSS- und KEV-Daten.";
    return { level, reasons, decision, observedInBrowser };
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
