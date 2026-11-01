window.CapybaraOsv = {
  normalizeComponent(component) {
    if (!component || typeof component !== "object" || Array.isArray(component)) return false;
    const ecosystem = component.osvPackage?.ecosystem;
    const version = component.version ?? "";
    const validVersion = ecosystem === "npm"
      ? /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version)
      : /^[0-9A-Za-z][0-9A-Za-z.+_-]{0,99}$/.test(version);
    return (
      typeof ecosystem === "string" &&
      typeof component.osvPackage?.name === "string" &&
      Boolean(component.osvPackage.name.trim()) &&
      validVersion
    );
  },

  mapVulnerabilities(vulnerabilities, component) {
    return (Array.isArray(vulnerabilities) ? vulnerabilities : [])
      .filter((vulnerability) =>
        vulnerability &&
        typeof vulnerability.id === "string" &&
        !vulnerability.withdrawn
      )
      .map((vulnerability) => {
        const aliases = Array.isArray(vulnerability.aliases)
          ? vulnerability.aliases.filter((alias) => typeof alias === "string")
          : [];
        const cveId = aliases.find((alias) => /^CVE-\d{4}-\d+$/i.test(alias));
        const id = cveId ?? vulnerability.id;
        const description = typeof vulnerability.summary === "string"
          ? vulnerability.summary
          : typeof vulnerability.details === "string"
            ? vulnerability.details.slice(0, 300)
            : "Keine Beschreibung verfügbar.";
        const severity = typeof vulnerability.database_specific?.severity === "string"
          ? vulnerability.database_specific.severity
          : null;
        const fromSbom = component.versionStatus === "declared-unverified";
        return {
          id,
          score: null,
          version: null,
          severity,
          description,
          published: vulnerability.published ?? vulnerability.modified ?? null,
          status: "OSV",
          source: `OSV/${component.osvPackage.ecosystem}`,
          sourceUrl: `https://osv.dev/vulnerability/${encodeURIComponent(vulnerability.id)}`,
          detectionMethod: "Exakte OSV-Paketkoordinate und deklarierte/erkannte Version abgefragt",
          product: component.name,
          productVersion: component.version,
          confidence: component.confidence ?? "low",
          technicalEvidence: {
            package: component.osvPackage,
            versionStatus: component.versionStatus ?? "unverified-hint",
            withdrawn: false,
            aliases
          },
          impactHints: window.CapybaraNvd.assessImpact(description),
          assessment: fromSbom
            ? `OSV ordnet die deklarierte SBOM-Version diesem Advisory zu. Paket und Version müssen im Deployment verifiziert werden.${severity ? ` OSV-Einstufung: ${severity}.` : ""}`
            : `OSV ordnet diese Paketversion dem Advisory zu. Die erkannte Versionsnummer ist ein nicht verifizierter Hinweis.${severity ? ` OSV-Einstufung: ${severity}.` : ""}`,
          potentiallyAffected: true,
          relatedIds: aliases.filter((alias) => alias !== id)
        };
      });
  },

  async lookupPackage(component) {
    if (!this.normalizeComponent(component)) return [];
    const response = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package: component.osvPackage,
        version: component.version
      })
    });
    if (!response.ok) throw new Error(`OSV antwortet mit HTTP ${response.status}.`);
    const data = await response.json();
    if (data?.vulns !== undefined && !Array.isArray(data.vulns)) {
      throw new Error("OSV-Antwort hat ein unerwartetes Format.");
    }
    return this.mapVulnerabilities(data.vulns ?? [], component);
  },

  async lookupPackages(components) {
    if (!Array.isArray(components)) {
      throw new Error("OSV-Batch benötigt eine Liste von Komponenten.");
    }
    const valid = components.filter((component) => this.normalizeComponent(component));
    const resultsByComponent = new Map(components.map((component) => [component, []]));
    for (let offset = 0; offset < valid.length; offset += 100) {
      const batch = valid.slice(offset, offset + 100);
      const response = await fetch("https://api.osv.dev/v1/querybatch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          queries: batch.map((component) => ({
            package: component.osvPackage,
            version: component.version
          }))
        })
      });
      if (!response.ok) {
        throw new Error(`OSV antwortet mit HTTP ${response.status}.`);
      }
      const data = await response.json();
      if (!Array.isArray(data?.results) || data.results.length !== batch.length) {
        throw new Error("OSV-Batch-Antwort hat ein unerwartetes Format.");
      }
      batch.forEach((component, index) => {
        const vulns = data.results[index]?.vulns;
        if (vulns !== undefined && !Array.isArray(vulns)) {
          throw new Error("OSV-Batch-Ergebnis enthält ein ungültiges Advisory-Format.");
        }
        resultsByComponent.set(
          component,
          this.mapVulnerabilities(vulns ?? [], component)
        );
      });
    }
    return components.map((component) => resultsByComponent.get(component) ?? []);
  }
};
