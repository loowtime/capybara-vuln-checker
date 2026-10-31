window.CapybaraOsv = {
  async lookupPackage(component) {
    if (
      !component.osvPackage?.ecosystem ||
      typeof component.osvPackage?.name !== "string" ||
      !/^[0-9A-Za-z][0-9A-Za-z.+_-]{0,99}$/.test(component.version ?? "")
    ) {
      return [];
    }

    const response = await fetch("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        package: component.osvPackage,
        version: component.version
      })
    });
    if (!response.ok) {
      throw new Error(`OSV antwortet mit HTTP ${response.status}.`);
    }

    const data = await response.json();
    if (data?.vulns !== undefined && !Array.isArray(data.vulns)) {
      throw new Error("OSV-Antwort hat ein unerwartetes Format.");
    }
    return (data.vulns ?? [])
      .filter((vulnerability) => !vulnerability.withdrawn)
      .map((vulnerability) => {
      const aliases = vulnerability.aliases ?? [];
      const cveId = aliases.find((alias) => /^CVE-\d{4}-\d+$/i.test(alias));
      const id = cveId ?? vulnerability.id;
      const severity = vulnerability.database_specific?.severity ?? null;
      return {
        id,
        score: null,
        version: null,
        severity,
        description: vulnerability.summary ??
          vulnerability.details?.slice(0, 300) ??
          "Keine Beschreibung verfügbar.",
        published: vulnerability.published ?? vulnerability.modified ?? null,
        status: "OSV",
        source: "OSV/npm",
        sourceUrl: `https://osv.dev/vulnerability/${encodeURIComponent(vulnerability.id)}`,
        product: component.name,
        productVersion: component.version,
        impactHints: window.CapybaraNvd.assessImpact(
          vulnerability.summary ?? vulnerability.details ?? ""
        ),
        assessment: `OSV ordnet diese Paketversion dem Advisory zu. Die erkannte Versionsnummer stammt aus einer öffentlichen Asset-URL und muss im Deployment bestätigt werden.${severity ? ` OSV-Einstufung: ${severity}.` : ""}`,
        potentiallyAffected: true,
        relatedIds: aliases.filter((alias) => alias !== id)
      };
    });
  }
};
