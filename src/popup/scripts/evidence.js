window.CapybaraEvidence = {
  attach(finding, context = {}) {
    const source = finding.source ?? "Lokale passive Prüfung";
    const detectionMethod = finding.detectionMethod ?? context.detectionMethod ??
      (source.includes("NVD")
        ? "NVD-Abgleich mit erkannter CPE"
        : source.includes("OSV")
          ? "OSV-Abgleich mit Paketkoordinate und Version"
          : "Passive Auswertung sichtbarer HTTP-Header oder DOM-Metadaten");
    const confidence = finding.confidence ?? context.confidence ?? "medium";
    const technicalEvidence = {
      ...(context.technicalEvidence ?? {}),
      ...(finding.technicalEvidence ?? {})
    };

    if (finding.product) technicalEvidence.product = finding.product;
    if (finding.productVersion) {
      technicalEvidence.version = finding.productVersion;
      technicalEvidence.versionStatus = context.versionStatus ?? "observed-unverified";
    }
    if (finding.cpe) technicalEvidence.cpe = finding.cpe;
    if (finding.id) technicalEvidence.advisoryId = finding.id;
    if (finding.score !== undefined && finding.score !== null) {
      technicalEvidence.cvss = {
        score: finding.score,
        version: finding.version ?? null,
        vector: finding.vectorString ?? null
      };
    }
    if (finding.epss) technicalEvidence.epss = finding.epss;
    if (finding.kev) technicalEvidence.cisaKev = finding.kev;
    if (finding.description) technicalEvidence.advisoryDescription = finding.description;

    return {
      ...finding,
      source,
      detectionMethod,
      observedAt: finding.observedAt ?? context.observedAt ?? new Date().toISOString(),
      confidence,
      technicalEvidence
    };
  },

  attachAll(findings, context = {}) {
    const observedAt = context.observedAt ?? new Date().toISOString();
    return findings.map((finding) => this.attach(finding, { ...context, observedAt }));
  }
};
