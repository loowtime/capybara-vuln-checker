/* Builds a transparent per-run coverage report for the popup.
 * The result documents which passive sources ran completely, partially or not
 * at all. It is not a security score and never implies full vulnerability
 * coverage; missing sources keep the result explicitly incomplete.
 */
window.CapybaraCoverage = (() => {
  const STATE_LABELS = {
    complete: "vollständig",
    partial: "teilweise",
    unavailable: "nicht verfügbar",
    skipped: "nicht angewendet",
    unverified: "nicht verifiziert"
  };

  function entry(label, state, detail) {
    const normalized = Object.hasOwn(STATE_LABELS, state) ? state : "unavailable";
    return {
      label,
      state: normalized,
      statusLabel: STATE_LABELS[normalized],
      detail: typeof detail === "string" && detail.trim()
        ? detail.trim()
        : "Keine weiteren Angaben."
    };
  }

  function count(value) {
    return Number.isInteger(value) && value >= 0 ? value : 0;
  }

  function headerCheck(headers) {
    const entries = headers && typeof headers === "object" && !Array.isArray(headers)
      ? Object.keys(headers).length
      : 0;
    return entries
      ? entry(
        "HTTP-Response-Header",
        "complete",
        `${entries} ausgewählte Antwort-Header der Hauptseite ausgewertet.`
      )
      : entry(
        "HTTP-Response-Header",
        "unavailable",
        "Es wurden keine ausgewerteten Antwort-Header erfasst."
      );
  }

  function pageCheck(pageAnalysis) {
    return pageAnalysis === false
      ? entry(
        "Passive Seitenanalyse",
        "unavailable",
        "DOM, Formulare und geladene Ressourcen konnten für diesen Lauf nicht ausgewertet werden."
      )
      : entry(
        "Passive Seitenanalyse",
        "complete",
        "DOM, Formulare und bereits geladene Ressourcen passiv ausgewertet; keine zusätzlichen Requests."
      );
  }

  function tlsCheck(report) {
    if (!report || typeof report !== "object") {
      return entry(
        "TLS-Verbindungsmetadaten",
        "skipped",
        "TLS-Metadaten wurden für diesen Lauf nicht angefordert."
      );
    }
    if (!report.available) {
      return entry(
        "TLS-Verbindungsmetadaten",
        "unavailable",
        report.reason ?? "Firefox hat keine TLS-Metadaten geliefert."
      );
    }
    const protocol = report.metadata?.protocolVersion ?? "Protokoll unbekannt";
    const issues = Array.isArray(report.issues) ? report.issues.length : 0;
    return entry(
      "TLS-Verbindungsmetadaten",
      "complete",
      `${protocol} ausgewertet; ${issues} TLS-Hinweis(e). Es wurde nur die Hauptseiten-Verbindung geprüft.`
    );
  }

  function queryCheck(label, input, noun) {
    if (!input || typeof input !== "object") {
      return entry(label, "skipped", `${noun} wurde für diesen Lauf nicht abgefragt.`);
    }
    const queries = count(input.queries);
    const failed = Math.min(count(input.failed), queries);
    if (!queries) {
      return entry(
        label,
        "skipped",
        `Keine passende ${noun}-Abfrage möglich; es wurden keine Anfragen ausgelöst.`
      );
    }
    if (!failed) {
      return entry(label, "complete", `${queries} ${noun}-Abfrage(n) ohne Fehler.`);
    }
    if (failed === queries) {
      return entry(
        label,
        "unavailable",
        `Alle ${queries} ${noun}-Abfrage(n) sind fehlgeschlagen; das Ergebnis ist unvollständig.`
      );
    }
    return entry(
      label,
      "partial",
      `${failed} von ${queries} ${noun}-Abfrage(n) fehlgeschlagen; das Ergebnis ist unvollständig.`
    );
  }

  function threatIntelCheck(input) {
    const label = "CISA KEV & FIRST EPSS";
    if (!input || input.required !== true) {
      return entry(
        label,
        "skipped",
        "Keine CVE-IDs vorhanden; die Feeds wurden nicht abgefragt."
      );
    }
    const kev = input.kev === true;
    const epss = input.epss === true;
    if (kev && epss) {
      return entry(
        label,
        "complete",
        "CISA-KEV-Katalog und FIRST-EPSS-Werte erfolgreich abgefragt."
      );
    }
    if (!kev && !epss) {
      return entry(
        label,
        "unavailable",
        "CISA KEV und FIRST EPSS konnten nicht abgefragt werden; die Priorität beruht nur auf CVSS und Zuordnungsqualität."
      );
    }
    const missing = [!kev ? "CISA KEV" : null, !epss ? "FIRST EPSS" : null]
      .filter(Boolean);
    return entry(
      label,
      "partial",
      `${missing.join(" und ")} nicht verfügbar; die übrigen Signale wurden ausgewertet.`
    );
  }

  function advisoryCheck(input) {
    if (!input || typeof input !== "object") {
      return entry(
        "Kuratierter Advisory-Katalog",
        "skipped",
        "Der lokale Advisory-Katalog wurde für diesen Lauf nicht geprüft."
      );
    }
    return entry(
      "Kuratierter Advisory-Katalog",
      "complete",
      `${count(input.matches)} Kandidat(en) aus dem lokal gepflegten Katalog geprüft; keine externe Abfrage.`
    );
  }

  function historyCheck(input) {
    if (!input || typeof input !== "object") {
      return entry(
        "Lokale Scan-Historie",
        "skipped",
        "Die lokale Historie wurde für diesen Lauf nicht geschrieben."
      );
    }
    if (input.state === "recorded") {
      return entry(
        "Lokale Scan-Historie",
        "complete",
        "Snapshot lokal gespeichert (maximal 30 pro Website-Ursprung, nicht synchronisiert)."
      );
    }
    if (input.state === "failed") {
      return entry(
        "Lokale Scan-Historie",
        "unavailable",
        `Snapshot konnte nicht gespeichert werden: ${input.detail ?? "unbekannter Fehler"}.`
      );
    }
    return entry(
      "Lokale Scan-Historie",
      "skipped",
      "Die lokale Historie wurde für diesen Lauf nicht geschrieben."
    );
  }

  function sbomCheck(input) {
    if (!input || typeof input !== "object") {
      return entry(
        "SBOM-Import",
        "skipped",
        "Es wurde keine SBOM analysiert."
      );
    }
    return entry(
      "SBOM-Import",
      "complete",
      `${input.format ?? "SBOM"} lokal eingelesen; ${count(input.components)} Komponente(n). Die Datei wurde nicht hochgeladen.`
    );
  }

  function build(input = {}) {
    const source = input && typeof input === "object" && !Array.isArray(input) ? input : {};
    if (source.mode === "sbom") {
      return {
        checks: [
          sbomCheck(source.sbom),
          entry(
            "SBOM-Versionsangaben",
            "unverified",
            "Versionsangaben stammen aus der SBOM-Deklaration und wurden nicht gegen ein Deployment verifiziert."
          ),
          queryCheck("OSV-Paketabgleich", source.osv, "OSV"),
          threatIntelCheck(source.threatIntel)
        ]
      };
    }

    return {
      checks: [
        headerCheck(source.headers),
        pageCheck(source.pageAnalysis),
        tlsCheck(source.tls),
        queryCheck("NVD-CPE-Abgleich", source.nvd, "NVD"),
        queryCheck("OSV-Paketabgleich", source.osv, "OSV"),
        threatIntelCheck(source.threatIntel),
        advisoryCheck(source.advisory),
        historyCheck(source.history)
      ]
    };
  }

  return { build, STATE_LABELS };
})();
