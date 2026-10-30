window.CapybaraNvd = (() => {
  const advisoryWatchlist = [
    {
      id: "CVE-2026-60137",
      product: "WordPress",
      score: 5.9,
      cvss: "CVSS 3.1",
      status: "Analyzed",
      description: "SQL-Injection-Risiko in WP_Query durch unzureichende Bereinigung von author__not_in.",
      versionRanges: [
        ["6.8.0", "6.8.6"],
        ["6.9.0", "6.9.5"],
        ["7.0.0", "7.0.2"]
      ]
    },
    {
      id: "CVE-2026-63030",
      product: "WordPress",
      score: 9.8,
      cvss: "CVSS 3.1",
      status: "Analyzed",
      description: "REST-API-Batch-Route-Confusion in Kombination mit CVE-2026-60137.",
      versionRanges: [
        ["6.9.0", "6.9.5"],
        ["7.0.0", "7.0.2"]
      ]
    },
    {
      id: "CVE-2026-109618",
      product: "PHP",
      score: 9.2,
      cvss: "CVSS 4.0",
      status: "Analyzed",
      description: "Fehlerhafte Behandlung von Out-of-Memory-Zuständen kann zu unsicherem Request-Speicherzustand führen.",
      versionRanges: [
        ["7.3.0", "8.2.35"],
        ["8.3.0", "8.3.36"],
        ["8.4.0", "8.4.27"],
        ["8.5.0", "8.5.12"]
      ]
    },
    {
      id: "CVE-2026-109619",
      product: "PHP",
      score: 9.2,
      cvss: "CVSS 4.0",
      status: "Analyzed",
      description: "Fehlerhafte globale Zustände können nach der Freigabe auf Request-Speicher verweisen.",
      versionRanges: [
        ["5.4.0", "8.2.35"],
        ["8.3.0", "8.3.36"],
        ["8.4.0", "8.4.27"],
        ["8.5.0", "8.5.12"]
      ]
    },
    {
      id: "CVE-2025-12057",
      product: "WordPress-Plugin: waveplayer",
      score: 9.8,
      cvss: "CVSS 3.1",
      status: "Deferred",
      description: "Fehlende Autorisierungs- und Dateivalidierungsprüfungen im WavePlayer-Plugin.",
      slug: ["waveplayer"],
      affected: "Versionen vor 3.8.0",
      versionRange: ["0", "3.8.0"]
    },
    {
      id: "CVE-2020-36847",
      product: "WordPress-Plugin: simple-file-list",
      score: 9.8,
      cvss: "CVSS 3.1",
      status: "Analyzed",
      description: "Simple File List Plugin ist bis einschließlich Version 4.2.2 von einer Remote-Code-Ausführung betroffen.",
      slug: ["simple-file-list"],
      affected: "Versionen bis einschließlich 4.2.2",
      versionRange: ["0", "4.2.3"]
    },
    {
      id: "CVE-2025-13486",
      product: "WordPress-Plugin: acf-extended",
      score: 9.8,
      cvss: "CVSS 3.1",
      status: "Deferred",
      description: "Remote-Code-Ausführung im Advanced Custom Fields: Extended-Plugin.",
      slug: ["acf-extended"],
      affected: "Versionen 0.9.0.5 bis einschließlich 0.9.1.1",
      versionRange: ["0.9.0.5", "0.9.1.2"]
    },
    {
      id: "CVE-2025-6389",
      product: "WordPress-Plugin: sneeit-framework",
      score: 9.8,
      cvss: "CVSS 3.1",
      status: "Deferred",
      description: "Remote-Code-Ausführung im Sneeit-Framework-Plugin.",
      slug: ["sneeit-framework", "sneeit"],
      affected: "Versionen bis einschließlich 8.3",
      versionRange: ["0", "8.4"]
    },
    {
      id: "CVE-2026-48907",
      product: "Joomla JCE",
      score: 10.0,
      cvss: "CVSS 4.0",
      status: "Analyzed",
      description: "JCE-Editor-Schwachstelle kann das Anlegen unautorisierter Profile und das Hochladen ausführbaren Codes ermöglichen.",
      slug: ["jce"],
      affected: "Betroffene JCE-Version anhand des Hersteller-Advisory prüfen."
    }
  ];

  function getCvss(metrics) {
    const sources = [
      ["CVSS 4.0", metrics.cvssMetricV40],
      ["CVSS 3.1", metrics.cvssMetricV31],
      ["CVSS 3.0", metrics.cvssMetricV30],
      ["CVSS 2.0", metrics.cvssMetricV2]
    ];
    for (const [version, entries] of sources) {
      if (!entries?.length) continue;
      const metric = entries.find((entry) => entry.type === "Primary") ?? entries[0];
      const score = metric.cvssData?.baseScore;
      if (typeof score === "number") return { score, version };
    }
    return null;
  }

  function compareVersions(left, right) {
    const a = left.split(/[.-]/).map((part) => Number.parseInt(part, 10) || 0);
    const b = right.split(/[.-]/).map((part) => Number.parseInt(part, 10) || 0);
    for (let index = 0; index < Math.max(a.length, b.length); index += 1) {
      const difference = (a[index] ?? 0) - (b[index] ?? 0);
      if (difference) return Math.sign(difference);
    }
    return 0;
  }

  function versionIsAffected(version, advisory) {
    if (!version) return false;
    if (!/^\d+(?:\.\d+)*$/.test(version)) return null;
    if (advisory.versionRanges) {
      return advisory.versionRanges.some(([firstAffected, fixed]) =>
        compareVersions(version, firstAffected) >= 0 &&
        compareVersions(version, fixed) < 0
      );
    }
    if (advisory.versionRange) {
      return compareVersions(version, advisory.versionRange[0]) >= 0 &&
        compareVersions(version, advisory.versionRange[1]) < 0;
    }
    return false;
  }

  function advisoryFindings(components) {
    const findings = [];
    for (const advisory of advisoryWatchlist) {
      const component = components.find((item) => {
        if (advisory.slug) {
          return advisory.slug.includes(item.slug) ||
            (advisory.slug.includes("jce") && item.name === "Joomla JCE");
        }
        return item.name === advisory.product;
      });
      if (!component) continue;

      const affected = versionIsAffected(component.version, advisory);
      const hasKnownRange = Boolean(advisory.versionRanges || advisory.versionRange);
      if (component.version && hasKnownRange && !affected) continue;
      const versionMessage = component.version
        ? affected
          ? `Versionshinweis ${component.version} liegt im bekannten betroffenen Bereich (${advisory.affected}).`
          : hasKnownRange
            ? `Versionshinweis ${component.version} liegt nicht im hinterlegten Bereich (${advisory.affected}); Version im Deployment verifizieren.`
            : `Versionshinweis ${component.version}; für dieses Advisory ist kein verlässlicher Versionsbereich hinterlegt. Herstellerhinweise prüfen.`
        : `Version unbekannt. ${advisory.affected}`;
      findings.push({
        id: advisory.id,
        score: advisory.score,
        version: advisory.cvss,
        description: advisory.description,
        published: null,
        status: advisory.status,
        product: component.name,
        productVersion: component.version ?? "unbekannt",
        source: "Kuratiertes Advisory",
        assessment: versionMessage,
        confidence: component.confidence ?? "low",
        potentiallyAffected: component.version && hasKnownRange ? affected : null
      });
    }
    return findings;
  }

  async function fetchProductCves(cpe) {
    const params = new URLSearchParams({ cpeName: cpe, resultsPerPage: "100" });
    const response = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?${params.toString()}`
    );
    if (!response.ok) {
      throw new Error(response.status === 404
        ? "Die NVD hat die Abfrageparameter nicht akzeptiert."
        : `NVD antwortet mit HTTP ${response.status}.`);
    }

    const data = await response.json();
    const findings = (data.vulnerabilities ?? [])
      .filter(({ cve }) => cve.vulnStatus !== "Rejected")
      .map(({ cve }) => {
        const cvss = getCvss(cve.metrics ?? {});
        return {
          id: cve.id,
          score: cvss?.score ?? null,
          version: cvss?.version ?? null,
          description: cve.descriptions?.find((item) => item.lang === "en")?.value ??
            cve.descriptions?.[0]?.value ?? "Keine Beschreibung verfügbar.",
          published: cve.published,
          status: cve.vulnStatus ?? "Unknown",
          source: "NVD-CPE-Abgleich"
        };
      });

    return {
      findings,
      totalResults: data.totalResults ?? findings.length,
      highSeverityCount: findings.filter((finding) =>
        finding.score !== null && finding.score > 8
      ).length
    };
  }

  return { advisoryFindings, fetchProductCves };
})();
