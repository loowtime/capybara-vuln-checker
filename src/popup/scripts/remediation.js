
window.CapybaraRemediation = (() => {
  const SLA_DAYS = {
    kritisch: 1,
    hoch: 7,
    mittel: 30,
    niedrig: 90,
    unbestimmt: null
  };

  function plan(finding, observedAt = new Date().toISOString()) {
    const level = finding.risk?.level ?? "unbestimmt";
    const days = SLA_DAYS[level];

    const kevKnown = finding.kev === true ||
      finding.kev?.known === true;

    const confidence = finding.confidence ?? "unknown";
    const versionStatus =
      finding.technicalEvidence?.versionStatus ?? "unknown";

    let action = "Manuelle Sicherheitsbewertung durchführen.";

    if (kevKnown) {
      action = "Bekannt ausgenutzte Schwachstelle priorisiert beheben. Patch- und Herstellerhinweise prüfen.";
    } else if (level === "kritisch") {
      action = "Sofortige technische Bewertung und schnellstmögliche Behebung.";
    } else if (level === "hoch") {
      action = "Zeitnahe Aktualisierung auf eine nachweislich sichere Version.";
    } else if (level === "mittel") {
      action = "Update im nächsten geplanten Wartungsfenster einplanen.";
    } else if (level === "niedrig") {
      action = "Update im regulären Wartungszyklus berücksichtigen.";
    }

    const baseDate = new Date(observedAt);
    const dueDate = days === null || Number.isNaN(baseDate.getTime())
      ? null
      : new Date(
          baseDate.getTime() + days * 24 * 60 * 60 * 1000
        ).toISOString();

    const verificationRequired =
      confidence === "low" ||
      versionStatus.includes("unverified") ||
      versionStatus === "unknown";

    return {
      priority: level,
      slaDays: days,
      dueDate,
      action,
      verificationRequired,
      status: "open",
      basis: kevKnown
        ? "CISA KEV"
        : "Risk prioritization",
      note: verificationRequired
        ? "Detected version or installation status requires manual verification."
        : "Validate the fix after deployment."
    };
  }

  function enrichAll(findings, observedAt) {
    return findings.map((finding) => ({
      ...finding,
      remediation: plan(finding, observedAt)
    }));
  }

  return {
    plan,
    enrichAll,
    SLA_DAYS
  };
})();
