window.CapybaraUI = {
  renderComponents(element, components) {
    element.replaceChildren();
    const disclosure = document.createElement("details");
    disclosure.className = "section-disclosure";
    const summary = document.createElement("summary");
    summary.textContent = `Erkannte CMS, Plugins & Bibliotheken · ${components.length}`;
    disclosure.append(summary);

    if (!components.length) {
      const empty = document.createElement("p");
      empty.textContent =
        "Keine CMS-/Plugin-Versionen in Generator-Metadaten oder geladenen Ressourcen erkannt.";
      disclosure.append(empty);
      element.append(disclosure);
      return;
    }

    for (const component of components) {
      const item = document.createElement("div");
      item.className = "component-info";
      const title = document.createElement("strong");
      title.textContent = component.name;
      const details = document.createElement("p");
      details.textContent = `${component.category} · ${
        component.version ? `Versionshinweis ${component.version} (nicht verifiziert)` : "Version unbekannt"
      } · ${component.source} · Vertrauen: ${component.confidence ?? "unbekannt"}`;
      item.append(title, details);

      if (component.note) {
        const note = document.createElement("p");
        note.className = "assessment";
        note.textContent = component.note;
        item.append(note);
      }
      disclosure.append(item);
    }
    element.append(disclosure);
  },

  renderServer(element, headers, inspection) {
    element.replaceChildren();
    const heading = document.createElement("h2");
    heading.textContent = "Ergebnisübersicht";
    element.append(heading);

    if (!inspection.products.length && !inspection.infrastructure.length) {
      const empty = document.createElement("p");
      empty.textContent = "Keine bekannten Dienste in den erfassten Antwort-Headern erkannt.";
      element.append(empty);
    }

    for (const product of inspection.products) {
      const box = document.createElement("div");
      box.className = "server-info";
      const topLine = document.createElement("div");
      topLine.className = "service-topline";
      const title = document.createElement("strong");
      title.textContent = product.name;
      const result = product.version ? inspection.results.get(product.name) : null;
      const state = document.createElement("span");
      state.className = "service-state";
      if (!product.version) {
        state.textContent = "Version unbekannt";
      } else if (!product.cpe) {
        state.textContent = "Kein NVD-Abgleich";
      } else if (result?.error) {
        state.textContent = "NVD nicht erreichbar";
        state.classList.add("service-state-error");
      } else if (!result) {
        state.textContent = "Abgleich ausstehend";
      } else {
        state.textContent = result.totalResults === 0
          ? "Keine exakte NVD-CPE-Zuordnung"
          : `NVD: ${result.totalResults} CVE(s) · ${result.highSeverityCount} > 8,0`;
        if (result.highSeverityCount > 0) state.classList.add("service-state-warning");
      }
      topLine.append(title, state);

      const detail = document.createElement("p");
      detail.textContent = product.version
        ? `${product.category} · Version ${product.version} · erkannt in ${product.source}`
        : product.versions?.length > 1
          ? `${product.category} · widersprüchliche Versionsangaben (${product.versions.join(", ")}); kein CVE-Abgleich`
          : `${product.category} · Dienst erkannt, aber keine eindeutige Versionsnummer im Header.`;
      box.append(topLine, detail);

      if (product.raw && /\b(?:debian|ubuntu|alpine|red hat|rhel|centos)\b/i.test(product.raw)) {
        box.append(this.createNote(
          "Hinweis zum Distributionspaket",
          "Sicherheitskorrekturen können zurückportiert sein. Upstream-Version und NVD-Treffer allein belegen daher keine Verwundbarkeit."
        ));
      }

      if (product.version || result?.error) {
        let explanation;
        if (result?.error) {
          explanation = `NVD-Abfrage fehlgeschlagen: ${result.error}`;
        } else if (!product.cpe) {
          explanation = "Version erkannt, aber kein Produktprofil für den NVD-Abgleich hinterlegt.";
        } else if (!result) {
          explanation = "Für diese Produktversion liegt noch kein NVD-Abgleich vor.";
        } else if (result.totalResults === 0) {
          explanation =
            "Die NVD hat dieser exakten Produkt-/Versionsangabe keine CVEs zugeordnet. Das bestätigt nicht, dass die Software aktuell oder sicher ist; ein Advisory-Kandidat kann unabhängig davon in der CVE-Liste erscheinen.";
        } else if (result.totalResults > 100) {
          explanation =
            `${result.totalResults} CVEs insgesamt; die ersten 100 NVD-Ergebnisse wurden ausgewertet. ${result.highSeverityCount} davon haben CVSS über 8,0.`;
        } else {
          explanation =
            `${result.totalResults} CVEs sind dieser Produkt-/Versionsangabe in der NVD zugeordnet; ${result.highSeverityCount} davon haben CVSS über 8,0. Prüfe bei jedem Treffer die betroffene Version und Herstellerhinweise.`;
        }
        box.append(this.createNote("Einordnung", explanation));
      }
      element.append(box);
    }

    if (inspection.infrastructure.length) {
      element.append(this.createNote(
        `Proxy/CDN-Hinweis · ${inspection.infrastructure.length}`,
        `${inspection.infrastructure.join(", ")}. Der sichtbare Server kann ein Proxy/CDN statt des Ursprungsservers sein.`
      ));
    }

    if (Object.keys(headers).length) {
      const disclosure = document.createElement("details");
      const summary = document.createElement("summary");
      summary.textContent = "Erfasste Response-Header anzeigen";
      const list = document.createElement("ul");
      for (const [name, values] of Object.entries(headers)) {
        const item = document.createElement("li");
        item.textContent = `${name}: ${values.join(", ")}`;
        list.append(item);
      }
      disclosure.append(summary, list);
      element.append(disclosure);
    }
  },

  renderPosture(element, findings) {
    element.replaceChildren();
    const disclosure = document.createElement("details");
    disclosure.className = "section-disclosure";
    const heading = document.createElement("summary");
    heading.textContent = `Sicherheits-Checkliste · ${findings.length} Hinweis(e)`;
    disclosure.append(heading);

    if (!findings.length) {
      const item = document.createElement("p");
      item.textContent =
        "Bei diesen Prüfungen wurden keine Auffälligkeiten erkannt. Das ist kein vollständiges Sicherheitsaudit.";
      disclosure.append(item);
      element.append(disclosure);
      return;
    }

    for (const finding of findings) {
      const item = document.createElement("details");
      item.className = `posture-item posture-${finding.level}`;
      const title = document.createElement("strong");
      title.textContent = `${finding.level === "warning" ? "Prüfen" : "Hinweis"}: ${finding.title}`;
      const summary = document.createElement("summary");
      summary.append(title);
      const detail = document.createElement("p");
      detail.textContent = finding.detail;
      item.append(summary, detail);
      if (finding.evidence) {
        item.append(this.createEvidenceDisclosure(finding));
      }
      disclosure.append(item);
    }
    element.append(disclosure);
  },

  renderFindings(element, findings, queryCount, failedCount, sourceErrors = []) {
    element.replaceChildren();
    const heading = document.createElement("h2");
    heading.textContent = `CVE- und Advisory-Kandidaten · ${findings.length}`;
    element.append(heading);

    if (findings.length) {
      const priority = document.createElement("div");
      priority.className = "finding-priority";
      const rootHints = findings.filter((finding) =>
        finding.impactHints?.includes("Root-/Admin-Zugriff im Advisory erwähnt")
      ).length;
      const remoteUnauthenticated = findings.filter((finding) =>
        finding.attackHints?.includes("Netzwerk-Vektor") &&
        (finding.attackHints.includes("Keine Privilegien erforderlich") ||
          finding.attackHints.includes("Keine Anmeldung erforderlich")) &&
        finding.attackHints.includes("Keine Nutzerinteraktion erforderlich")
      ).length;
      const highSeverity = findings.filter((finding) =>
        finding.score !== null && finding.score > 8
      ).length;
      const summary = document.createElement("strong");
      summary.textContent = "Triage-Hinweise";
      const stats = document.createElement("p");
      stats.textContent =
        `Root/Admin im Advisory-Text: ${rootHints} · ` +
        `Netzwerk, ohne Zugangsdaten/Interaktion: ${remoteUnauthenticated} · ` +
        `CVSS > 8,0: ${highSeverity}`;
      const caveat = document.createElement("small");
      caveat.textContent = "Text- und CVSS-Hinweise zur Priorisierung, kein Nachweis der Ausnutzbarkeit.";
      priority.append(summary, stats, caveat);
      element.append(priority);
    }

    if (!findings.length) {
      const empty = document.createElement("p");
      const note = document.createElement("details");
      note.className = "inline-note";
      const summary = document.createElement("summary");
      summary.textContent = "Warum kein Treffer?";
      const explanation = document.createElement("p");
      if (queryCount === 0) {
        empty.textContent = "Keine CVE-Abfrage möglich";
        explanation.textContent =
          "Es wurde keine exakt unterstützte Produktversion erkannt. Die Dienstübersicht zeigt, welche Erkennung fehlt.";
      } else if (failedCount === queryCount && failedCount > 0) {
        empty.textContent = "Alle CVE-Abfragen fehlgeschlagen";
        explanation.textContent =
          "Es liegt kein verlässliches CVE-Ergebnis vor. Öffne die Quellenhinweise für Fehlerdetails.";
      } else if (failedCount > 0) {
        empty.textContent = "Mindestens eine Abfrage fehlgeschlagen";
        explanation.textContent =
          "Das Ergebnis ist unvollständig. Öffne die Einordnung beim betroffenen Dienst für den Fehler.";
      } else {
        empty.textContent = "Keine CVE-Kandidaten gefunden";
        explanation.textContent =
          "NVD, OSV und der Advisory-Katalog haben für die erkannten Produkte keine Kandidaten zurückgegeben. Das bedeutet nicht, dass die Komponenten sicher oder aktuell sind.";
      }
      note.append(summary, explanation);
      element.append(empty, note);
      if (sourceErrors.length) {
        element.append(this.createNote("Fehler bei CVE-Quellen", sourceErrors.join(" · ")));
      }
      return;
    }

    for (const finding of findings) {
      const article = document.createElement("details");
      article.className = "finding";
      const summary = document.createElement("summary");
      summary.className = "finding-heading";
      const link = document.createElement("a");
      link.href = finding.sourceUrl ??
        `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(finding.id)}`;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = finding.id;

      const score = document.createElement("span");
      score.className = `score ${
        finding.score === null
          ? ""
          : finding.score >= 9
            ? "score-critical"
            : finding.score > 8
              ? "score-high"
              : ""
      }`;
      score.textContent = finding.score === null
        ? finding.severity
          ? `CVSS nicht verfügbar · ${finding.severity}`
          : "Kein CVSS"
        : `${this.severityLabel(finding.score)} · ${finding.score.toFixed(1)} · ${finding.version}`;
      summary.append(link, score);

      const description = document.createElement("p");
      description.textContent = finding.description.length > 300
        ? `${finding.description.slice(0, 297)}…`
        : finding.description;
      const provenance = document.createElement("small");
      const published = finding.published
        ? ` · veröffentlicht ${new Date(finding.published).toLocaleDateString("de-DE")}`
        : "";
      provenance.textContent =
        `${finding.product} ${finding.productVersion ?? "Version unbekannt"} · ${finding.status} · ${finding.source}${published}`;
      article.append(summary, description, provenance);

      const priority = document.createElement("span");
      priority.className = `risk-label risk-${finding.risk?.level ?? "unbestimmt"}`;
      priority.textContent = `Priorität: ${finding.risk?.level ?? "unbestimmt"}`;
      article.append(priority);

      const cpeAssessment = finding.technicalEvidence?.cpeAssessment;
      if (cpeAssessment) {
        const cpeInfo = document.createElement("p");
        cpeInfo.className = "assessment";
        cpeInfo.textContent =
          `CPE match: ${cpeAssessment.score}/100 (${cpeAssessment.level}) · ` +
          cpeAssessment.reasons.join(" ");
        article.append(cpeInfo);
      }

      const hints = [...(finding.impactHints ?? []), ...(finding.attackHints ?? [])];
      if (hints.length) {
        const badges = document.createElement("ul");
        badges.className = "finding-hints";
        for (const hint of hints) {
          const badge = document.createElement("li");
          badge.textContent = hint;
          badges.append(badge);
        }
        article.append(badges);
      }

      if (finding.assessment) {
        const assessment = document.createElement("p");
        assessment.className = "assessment";
        assessment.textContent = finding.assessment;
        article.append(assessment);
      }
      if (finding.epss) {
        const epss = document.createElement("p");
        epss.textContent =
          `FIRST EPSS: ${(finding.epss.score * 100).toFixed(2)} % Ausnutzungswahrscheinlichkeit` +
          `${finding.epss.percentile === null ? "" : ` · Perzentil ${(finding.epss.percentile * 100).toFixed(1)} %`}` +
          `${finding.epss.date ? ` · Stand ${finding.epss.date}` : ""}`;
        article.append(epss);
      }
      if (finding.kev) {
        const kev = document.createElement("p");
        kev.textContent = finding.kev.known
          ? `CISA KEV: bekannt ausgenutzt${finding.kev.dateAdded ? ` · aufgenommen ${finding.kev.dateAdded}` : ""}${finding.kev.knownRansomwareCampaignUse ? ` · Ransomware-Kampagnen: ${finding.kev.knownRansomwareCampaignUse}` : ""}`
          : "CISA KEV: kein Eintrag im abgerufenen Katalog";
        article.append(kev);
      }
      if (finding.risk?.reasons?.length) {
        const reasons = document.createElement("ul");
        reasons.className = "risk-reasons";
        for (const reason of finding.risk.reasons) {
          const item = document.createElement("li");
          item.textContent = reason;
          reasons.append(item);
        }
        article.append(reasons);
      }
      const recommendation = document.createElement("p");
      recommendation.className = "recommendation";
      recommendation.textContent = finding.recommendation ??
        (finding.kev?.known
          ? "Empfehlung: Herstellerhinweise und verfügbare Sicherheitsupdates priorisiert prüfen; Deployment-Version und mögliche Backports verifizieren."
          : "Empfehlung: Hersteller-Advisory, betroffene/fixe Versionen und Deployment-Patchstand prüfen, bevor eine Maßnahme festgelegt wird.");
      article.append(recommendation);
      if (finding.evidence) article.append(this.createEvidenceDisclosure(finding));
      if (finding.relatedIds?.length) {
        const aliases = document.createElement("small");
        aliases.textContent = `Weitere Advisory-IDs: ${finding.relatedIds.join(", ")}`;
        article.append(aliases);
      }
      element.append(article);
    }

    element.append(this.createNote(
      "Zur Einordnung der CVE-Treffer",
      "NVD-, OSV- und Advisory-Treffer sind Kandidaten, kein Nachweis einer verwundbaren Installation. Versionshinweise aus Asset-URLs sind unsicher. Prüfe Paketversionen, Hersteller-Advisories, Distribution-Patches und Konfiguration."
    ));
    if (sourceErrors.length) {
      element.append(this.createNote("Fehler bei CVE-Quellen", sourceErrors.join(" · ")));
    }
  },

  renderHistory(element, change) {
    element.replaceChildren();
    const disclosure = document.createElement("details");
    disclosure.className = "section-disclosure";
    const summary = document.createElement("summary");
    summary.textContent = "Lokale Scan-Historie";
    disclosure.append(summary);
    const text = document.createElement("p");
    if (!change) {
      text.textContent = "Noch kein Verlauf für diese Website. Es werden nur lokale Kurz-Snapshots gespeichert.";
    } else if (change.baseline) {
      text.textContent = `Lokaler Verlauf vorhanden · letzter Scan ${new Date(change.scannedAt).toLocaleString("de-DE")}.`;
    } else {
      text.textContent =
        `${change.newFindings.length} neue · ${change.resolvedFindings.length} nicht mehr erkannte CVE(s), ` +
        `${change.versionChanges.length} Versionsänderung(en), ${change.headerChanges.length} Header-Änderung(en).`;
    }
    disclosure.append(text);
    if (change && !change.baseline) {
      const lists = [
        ["Neue CVE-Kandidaten", change.newFindings],
        ["Nicht mehr erkannte Kandidaten", change.resolvedFindings],
        ["Versionsänderungen", change.versionChanges.map((item) =>
          `${item.component}: ${item.from ?? "unbekannt"} → ${item.to ?? "unbekannt"}`
        )],
        ["Geänderte Security-Header", change.headerChanges]
      ];
      for (const [title, values] of lists) {
        if (!values.length) continue;
        const note = document.createElement("p");
        note.textContent = `${title}: ${values.map((item) =>
          typeof item === "string" ? item : item.id
        ).join(", ")}`;
        disclosure.append(note);
      }
      if (change.previousScanAt) {
        const timestamp = document.createElement("small");
        timestamp.textContent = `Vergleich mit ${new Date(change.previousScanAt).toLocaleString("de-DE")}`;
        disclosure.append(timestamp);
      }
    }
    element.append(disclosure);
  },

  createEvidenceDisclosure(finding) {
    const disclosure = document.createElement("details");
    disclosure.className = "evidence-disclosure";
    const summary = document.createElement("summary");
    summary.textContent = "Evidenz & technische Details";
    const facts = document.createElement("dl");
    const entries = [
      ["Quelle", finding.source],
      ["Erkennung", finding.detectionMethod],
      ["Beobachtet", finding.observedAt],
      ["Vertrauen", finding.confidence],
      ["Weitere Quellen", finding.relatedSources?.filter((source) => source !== finding.source).join(", ") || "—"]
    ];
    for (const [label, value] of entries) {
      const term = document.createElement("dt");
      term.textContent = label;
      const description = document.createElement("dd");
      description.textContent = value ?? "Unbekannt";
      facts.append(term, description);
    }
    const raw = document.createElement("pre");
    raw.textContent = JSON.stringify(finding.technicalEvidence ?? {}, null, 2);
    disclosure.append(summary, facts, raw);
    return disclosure;
  },

  createNote(title, text) {
    const disclosure = document.createElement("details");
    disclosure.className = "inline-note";
    const summary = document.createElement("summary");
    summary.textContent = title;
    const detail = document.createElement("p");
    detail.textContent = text;
    disclosure.append(summary, detail);
    return disclosure;
  },

  severityLabel(score) {
    if (score >= 9) return "Kritisch";
    if (score >= 7) return "Hoch";
    if (score >= 4) return "Mittel";
    return "Niedrig";
  }
};