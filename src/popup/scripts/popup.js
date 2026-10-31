const authorizationCheckbox = document.querySelector("#authorized");
const scanButton = document.querySelector("#scan");
const statusElement = document.querySelector("#status");
const serverElement = document.querySelector("#server");
const componentsElement = document.querySelector("#components");
const postureElement = document.querySelector("#posture");
const resultsElement = document.querySelector("#results");
const historyElement = document.querySelector("#history");
const sbomFileInput = document.querySelector("#sbom-file");
const sbomStatus = document.querySelector("#sbom-status");
const analyzeSbomButton = document.querySelector("#analyze-sbom");
const exportJsonButton = document.querySelector("#export-json");
const exportCsvButton = document.querySelector("#export-csv");
const printReportButton = document.querySelector("#print-report");
let activePage = null;
let currentReport = null;

authorizationCheckbox.addEventListener("change", () => {
  scanButton.disabled = !authorizationCheckbox.checked || !activePage;
});

async function getActiveWebTab() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !tab.url) {
    throw new Error("Der aktive Tab konnte nicht gefunden werden.");
  }
  const url = new URL(tab.url);
  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Nur normale HTTP- und HTTPS-Websites können geprüft werden.");
  }
  return { tab, url };
}

async function initializePopup() {
  try {
    activePage = await getActiveWebTab();
    scanButton.disabled = !authorizationCheckbox.checked;
    await renderHistory(activePage.url.origin);
  } catch (error) {
    statusElement.textContent = error.message;
  }
}

function mergeProducts(headerProducts, pageComponents) {
  const products = [...headerProducts];
  const queryableComponents = pageComponents
    .filter((component) => component.cpe)
    .map((component) => ({
      ...component,
      raw: "",
      versions: [component.version]
    }));

  for (const component of queryableComponents) {
    const index = products.findIndex((product) => product.name === component.name);
    if (index < 0) {
      products.push(component);
    } else if (!products[index].version) {
      products[index] = component;
    }
  }
  return products;
}

function uniqueFindings(findings) {
  const unique = new Map();
  for (const finding of findings) {
    const key = `${finding.id}:${finding.product}`;
    const previous = unique.get(key);
    if (!previous) {
      unique.set(key, finding);
      continue;
    }
    const preferred = previous.score === null && finding.score !== null ? finding : previous;
    const secondary = preferred === previous ? finding : previous;
    unique.set(key, {
      ...secondary,
      ...preferred,
      relatedSources: [...new Set([
        ...(previous.relatedSources ?? []),
        ...(finding.relatedSources ?? []),
        previous.source,
        finding.source
      ])],
      relatedIds: [...new Set([
        ...(previous.relatedIds ?? []),
        ...(finding.relatedIds ?? [])
      ])]
    });
  }
  return [...unique.values()];
}

async function renderHistory(origin, change = null) {
  if (!change) {
    const snapshots = await CapybaraHistory.read(origin);
    if (!snapshots.length) {
      CapybaraUI.renderHistory(historyElement, null);
      return;
    }
    change = { baseline: true, scannedAt: snapshots.at(-1).scannedAt };
  }
  CapybaraUI.renderHistory(historyElement, change);
}

function setReport(report) {
  currentReport = report;
  const enabled = Boolean(report);
  exportJsonButton.disabled = !enabled;
  exportCsvButton.disabled = !enabled;
  printReportButton.disabled = !enabled;
}

async function scanWebsite() {
  scanButton.disabled = true;
  statusElement.textContent = "Antwort-Header werden gelesen …";
  setReport(null);
  serverElement.replaceChildren();
  componentsElement.replaceChildren();
  postureElement.replaceChildren();
  historyElement.replaceChildren();
  resultsElement.replaceChildren();

  try {
    if (!activePage) {
      throw new Error("Kein prüfbarer Website-Tab gefunden. Öffne das Popup erneut.");
    }

    const { tab, url } = activePage;
    const hostOrigins = [
      `http://${url.hostname}/*`,
      `https://${url.hostname}/*`
    ];
    const granted = await browser.permissions.request({ origins: hostOrigins });
    if (!granted) {
      throw new Error("Firefox benötigt die Website-Berechtigung, um Antwort-Header zu lesen.");
    }
    if (!(await browser.permissions.contains({ origins: hostOrigins }))) {
      throw new Error(
        "Firefox hat den Hostzugriff nicht bestätigt. Erlaube den Zugriff auf diese Website in den Add-on-Berechtigungen und starte den Scan erneut."
      );
    }

    const pageInspection = await CapybaraDetection.inspectActivePage(tab.id);

    statusElement.textContent = "Seite wird einmal neu geladen, um den Server-Header zu lesen …";
    const response = await browser.runtime.sendMessage({
      type: "scan-server-header",
      tabId: tab.id,
      origin: url.origin
    });
    const headers = response.headers ?? {};
    const inspection = CapybaraDetection.inspectResponseHeaders(headers);
    const components = pageInspection.components;
    inspection.products = CapybaraCpeMatcher.assessAll(
      mergeProducts(inspection.products, components)
    );
    inspection.results = new Map();

    const queryable = inspection.products.filter((product) =>
      product.version && product.cpeAssessment?.valid
    );
    const findings = CapybaraNvd.advisoryFindings(components);
    const sourceErrors = [];
    const observedAt = new Date().toISOString();

    for (const [index, product] of queryable.entries()) {
      statusElement.textContent =
        `NVD-Abfrage ${index + 1} von ${queryable.length}: ${product.name} ${product.version} …`;
      try {
        const result = await CapybaraNvd.fetchProductCves(product.cpe);
        inspection.results.set(product.name, {
          totalResults: result.totalResults,
          highSeverityCount: result.highSeverityCount
        });
        findings.push(...result.findings.map((finding) => ({
          ...finding,
          product: product.name,
          productVersion: product.version,
          cpe: product.cpe,
          confidence: product.confidence ?? "medium",
          technicalEvidence: {
            ...(finding.technicalEvidence ?? {}),
            detectionSource: product.source,
            versionStatus: product.versionStatus ?? "observed-unverified",
            cpeAssessment: product.cpeAssessment,
            rawBanner: product.raw ?? null
          }
        })));
      } catch (error) {
        inspection.results.set(product.name, { error: error.message });
      }

      if (index < queryable.length - 1) {
        await new Promise((resolve) => setTimeout(resolve, 6200));
      }
    }

    const osvComponents = components.filter((component) =>
      component.osvPackage && /^\d+\.\d+\.\d+$/.test(component.version ?? "")
    );
    for (const [index, component] of osvComponents.entries()) {
      statusElement.textContent =
        `OSV-Abfrage ${index + 1} von ${osvComponents.length}: ${component.name} ${component.version} …`;
      try {
        findings.push(...await CapybaraOsv.lookupPackage(component));
      } catch (error) {
        sourceErrors.push(`${component.name}: ${error.message}`);
      }
    }

    statusElement.textContent = "CISA KEV und FIRST EPSS werden abgeglichen …";
    const intel = await CapybaraThreatIntel.enrichFindings(findings);
    findings.splice(0, findings.length, ...intel.findings);
    sourceErrors.push(...intel.errors);

    const failed = [...inspection.results.values()].filter((result) => result.error).length;
    const componentsByName = new Map(components.map((component) => [component.name, component]));
    const enrichedFindings = CapybaraEvidence.attachAll(uniqueFindings(findings).map((finding) => {
      const component = componentsByName.get(finding.product) ??
        inspection.products.find((product) => product.name === finding.product);
      return {
        ...finding,
        confidence: finding.confidence ?? component?.confidence ?? "low",
        technicalEvidence: {
          ...(finding.technicalEvidence ?? {}),
          detectedVersion: finding.productVersion ?? component?.version ?? null,
          versionStatus: component?.versionStatus ?? finding.technicalEvidence?.versionStatus ?? "unknown",
          detectionSource: component?.source ?? finding.source
        }
      };
    }), { observedAt });
    const allFindings = CapybaraRisk.prioritizeAll(enrichedFindings, {
      exposure: "browser-observed"
    });
    const posture = [
      ...CapybaraPosture.assessResponse(
        headers,
        response.cookieFlags ?? {
          count: 0,
          missingSecure: 0,
          missingHttpOnly: 0,
          missingSameSite: 0,
          invalidHostPrefix: 0,
          invalidSecurePrefix: 0
        },
        url.protocol === "https:"
      ),
      ...pageInspection.security
    ].map((finding) => CapybaraEvidence.attach({
      ...finding,
      source: finding.source ?? "Passive HTTP-Header-/DOM-Prüfung",
      detectionMethod: finding.detectionMethod ?? "Header-/DOM-Auswertung ohne zusätzliche Website-Anfragen",
      confidence: finding.confidence ?? "medium",
      technicalEvidence: finding.technicalEvidence ?? {
        check: finding.title,
        observedCondition: finding.detail
      }
    }, { observedAt }));

    CapybaraUI.renderServer(serverElement, headers, inspection);
    CapybaraUI.renderComponents(componentsElement, components);
    CapybaraUI.renderPosture(postureElement, posture);
    CapybaraUI.renderFindings(
      resultsElement,
      allFindings.slice(0, 100),
      queryable.length + osvComponents.length,
      failed,
      sourceErrors
    );

    let history;
    try {
      history = await CapybaraHistory.record(url.origin, {
        scannedAt: observedAt,
        findings: allFindings,
        components,
        headers
      });
      await renderHistory(url.origin, history);
    } catch (error) {
      sourceErrors.push(`Lokale Historie: ${error.message}`);
      CapybaraUI.renderFindings(
        resultsElement,
        allFindings.slice(0, 100),
        queryable.length + osvComponents.length,
        failed,
        sourceErrors
      );
    }

    const highCount = allFindings.filter((finding) =>
      ["kritisch", "hoch"].includes(finding.risk.level)
    ).length;
    const report = {
      format: "capybara-vuln-check-report",
      version: 1,
      scannedAt: observedAt,
      scanner: "Capybara Vuln Check",
      components: CapybaraEvidence.attachAll(components, { observedAt }),
      posture,
      findings: allFindings,
      history: history ?? null,
      sourceErrors
    };
    setReport(report);
    statusElement.textContent =
      `${inspection.products.length + components.length} Komponente(n), ${allFindings.length} CVE-Kandidat(en), ` +
      `${highCount} mit hoher/kritischer Priorität` +
      `${failed ? `; ${failed} NVD-Abfrage(n) fehlgeschlagen` : ""}` +
      `${sourceErrors.length ? `; ${sourceErrors.length} Quellen-/Speicherhinweis(e)` : ""}.`;
  } catch (error) {
    statusElement.textContent =
      error.message || "Die Server-Version konnte nicht geprüft werden.";
  } finally {
    scanButton.disabled = !authorizationCheckbox.checked || !activePage;
  }
}

sbomFileInput.addEventListener("change", () => {
  const file = sbomFileInput.files?.[0];
  analyzeSbomButton.disabled = !file;
  sbomStatus.textContent = file ? `${file.name} ausgewählt · lokal verarbeitet` : "";
});

analyzeSbomButton.addEventListener("click", async () => {
  const file = sbomFileInput.files?.[0];
  if (!file) return;
  analyzeSbomButton.disabled = true;
  sbomStatus.textContent = "SBOM wird lokal eingelesen …";
  try {
    const parsed = CapybaraSbom.parse(await file.text());
    const findings = [];
    const errors = [];
    for (const component of parsed.components.filter((item) => item.osvPackage && item.version)) {
      try {
        findings.push(...await CapybaraOsv.lookupPackage({
          ...component,
          name: component.name,
          confidence: component.confidence
        }));
      } catch (error) {
        errors.push(`${component.name}: ${error.message}`);
      }
    }
    const intel = await CapybaraThreatIntel.enrichFindings(findings);
    errors.push(...intel.errors);
    const observedAt = new Date().toISOString();
    const normalized = CapybaraEvidence.attachAll(uniqueFindings(intel.findings), {
      observedAt,
      detectionMethod: "Abgleich deklarierter SBOM-Paketkoordinaten mit OSV",
      confidence: "medium"
    }).map((finding) => ({
      ...finding,
      technicalEvidence: {
        ...finding.technicalEvidence,
        sbomFormat: parsed.format,
        versionStatus: "declared-unverified"
      }
    }));
    const prioritized = CapybaraRisk.prioritizeAll(normalized, { exposure: "sbom" });
    CapybaraUI.renderComponents(componentsElement, parsed.components);
    CapybaraUI.renderFindings(resultsElement, prioritized, parsed.components.length, 0, errors);
    setReport({
      format: "capybara-sbom-report",
      version: 1,
      scannedAt: observedAt,
      scanner: "Capybara Vuln Check",
      sbomFormat: parsed.format,
      components: parsed.components,
      findings: prioritized,
      sourceErrors: errors
    });
    sbomStatus.textContent =
      `${parsed.format}: ${parsed.components.length} Komponente(n), ${prioritized.length} Advisory-Kandidat(en). ` +
      "Versionsangaben sind SBOM-Deklarationen und nicht gegen ein Deployment verifiziert.";
  } catch (error) {
    sbomStatus.textContent = error.message || "SBOM konnte nicht analysiert werden.";
  } finally {
    analyzeSbomButton.disabled = false;
  }
});

exportJsonButton.addEventListener("click", () => {
  if (currentReport) CapybaraReports.exportJson(currentReport);
});
exportCsvButton.addEventListener("click", () => {
  if (currentReport) CapybaraReports.exportCsv(currentReport.findings ?? []);
});
printReportButton.addEventListener("click", () => {
  if (currentReport) window.print();
});

scanButton.addEventListener("click", scanWebsite);
initializePopup();