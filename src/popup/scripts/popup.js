const authorizationCheckbox = document.querySelector("#authorized");
const scanButton = document.querySelector("#scan");
const statusElement = document.querySelector("#status");
const serverElement = document.querySelector("#server");
const componentsElement = document.querySelector("#components");
const postureElement = document.querySelector("#posture");
const resultsElement = document.querySelector("#results");
let activePage = null;

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
    if (!previous || finding.source === "Kuratiertes Advisory") {
      unique.set(key, { ...previous, ...finding });
    }
  }
  return [...unique.values()];
}

async function scanWebsite() {
  scanButton.disabled = true;
  statusElement.textContent = "Antwort-Header werden gelesen …";
  serverElement.replaceChildren();
  componentsElement.replaceChildren();
  postureElement.replaceChildren();
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
    inspection.products = mergeProducts(inspection.products, components);
    inspection.results = new Map();

    const queryable = inspection.products.filter((product) => product.version && product.cpe);
    const findings = CapybaraNvd.advisoryFindings(components);
    const sourceErrors = [];

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
          productVersion: product.version
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

    const failed = [...inspection.results.values()].filter((result) => result.error).length;
    const allFindings = uniqueFindings(findings).sort(
      (left, right) => (right.score ?? -1) - (left.score ?? -1)
    );
    CapybaraUI.renderServer(serverElement, headers, inspection);
    CapybaraUI.renderComponents(componentsElement, components);
    CapybaraUI.renderPosture(postureElement, [
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
    ]);
    CapybaraUI.renderFindings(
      resultsElement,
      allFindings.slice(0, 50),
      queryable.length + osvComponents.length,
      failed + sourceErrors.length,
      sourceErrors
    );

    const highCount = allFindings.filter(
      (finding) => finding.score !== null && finding.score > 8
    ).length;
    statusElement.textContent =
      `${inspection.products.length} Dienst(e), ${allFindings.length} CVE-Kandidat(en), ` +
      `davon ${highCount} mit CVSS über 8,0` +
      `${failed ? `; ${failed} NVD-Abfrage(n) fehlgeschlagen` : ""}` +
      `${sourceErrors.length ? `; ${sourceErrors.length} OSV-Abfrage(n) fehlgeschlagen` : ""}.`;
  } catch (error) {
    statusElement.textContent =
      error.message || "Die Server-Version konnte nicht geprüft werden.";
  } finally {
    scanButton.disabled = !authorizationCheckbox.checked || !activePage;
  }
}

scanButton.addEventListener("click", scanWebsite);
initializePopup();
