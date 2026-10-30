const authorizationCheckbox = document.querySelector("#authorized");
const scanButton = document.querySelector("#scan");
const statusElement = document.querySelector("#status");
const serverElement = document.querySelector("#server");
const resultsElement = document.querySelector("#results");

const serverProducts = [
  {
    name: "nginx",
    expression: /(?:^|[\s,])nginx\/(\d+(?:\.\d+){1,3})(?:$|[\s,(])/i,
    cpe: (version) => `cpe:2.3:a:f5:nginx:${version}:*:*:*:*:*:*:*`
  },
  {
    name: "Apache HTTP Server",
    expression: /(?:^|[\s,])apache\/(\d+(?:\.\d+){1,3})(?:$|[\s,(])/i,
    cpe: (version) => `cpe:2.3:a:apache:http_server:${version}:*:*:*:*:*:*:*`
  }
];

authorizationCheckbox.addEventListener("change", () => {
  scanButton.disabled = !authorizationCheckbox.checked;
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

function findServerProduct(serverHeader) {
  for (const product of serverProducts) {
    const match = serverHeader.match(product.expression);
    if (match) {
      return {
        name: product.name,
        version: match[1],
        cpe: product.cpe(match[1])
      };
    }
  }
  return null;
}

function renderServer(serverHeader, product) {
  serverElement.replaceChildren();
  const box = document.createElement("div");
  box.className = "server-info";
  const title = document.createElement("strong");
  title.textContent = "Server-Antwort";
  const value = document.createElement("span");
  value.textContent = serverHeader || "Kein Server-Header übermittelt.";
  box.append(title, value);

  if (serverHeader && !product) {
    const note = document.createElement("p");
    note.textContent =
      "Keine unterstützte, eindeutige Versionsangabe erkannt. Es wird keine CVE-Zuordnung geraten.";
    box.append(note);
  }
  serverElement.append(box);
}

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

async function fetchProductCves(cpe) {
  const params = new URLSearchParams({
    cpeName: cpe,
    resultsPerPage: "100",
    sortBy: "published",
    sortOrder: "desc"
  });
  const response = await fetch(
    `https://services.nvd.nist.gov/rest/json/cves/2.0?${params.toString()}`
  );
  if (!response.ok) {
    throw new Error(`NVD antwortet mit HTTP ${response.status}.`);
  }

  const data = await response.json();
  return (data.vulnerabilities ?? [])
    .map(({ cve }) => {
      const cvss = getCvss(cve.metrics ?? {});
      if (!cvss || cvss.score <= 8) return null;
      const description =
        cve.descriptions?.find((item) => item.lang === "en")?.value ??
        cve.descriptions?.[0]?.value ??
        "Keine Beschreibung verfügbar.";
      return {
        id: cve.id,
        score: cvss.score,
        version: cvss.version,
        description,
        published: cve.published
      };
    })
    .filter(Boolean);
}

function renderFindings(findings) {
  resultsElement.replaceChildren();
  if (!findings.length) {
    const empty = document.createElement("p");
    empty.textContent =
      "Keine passenden CVEs mit CVSS über 8,0 für diese Server-Version in der NVD gefunden.";
    resultsElement.append(empty);
    return;
  }

  for (const finding of findings) {
    const article = document.createElement("article");
    article.className = "finding";

    const heading = document.createElement("div");
    heading.className = "finding-heading";
    const link = document.createElement("a");
    link.href = `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(finding.id)}`;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = finding.id;

    const score = document.createElement("span");
    score.className = "score";
    score.textContent = `${finding.score.toFixed(1)} · ${finding.version}`;
    heading.append(link, score);

    const description = document.createElement("p");
    description.textContent =
      finding.description.length > 300
        ? `${finding.description.slice(0, 297)}…`
        : finding.description;

    const details = document.createElement("small");
    details.textContent = `Veröffentlicht ${new Date(finding.published).toLocaleDateString("de-DE")}`;
    article.append(heading, description, details);
    resultsElement.append(article);
  }
}

async function scanServer() {
  scanButton.disabled = true;
  statusElement.textContent = "Berechtigung wird geprüft …";
  serverElement.replaceChildren();
  resultsElement.replaceChildren();

  try {
    const permissionGranted = await browser.permissions.request({
      permissions: ["webRequest"]
    });
    if (!permissionGranted) {
      throw new Error("Ohne Berechtigung zum Lesen des Server-Headers ist keine Prüfung möglich.");
    }

    const { tab, url } = await getActiveWebTab();
    statusElement.textContent = "Seite wird einmal neu geladen, um den Server-Header zu lesen …";
    const response = await browser.runtime.sendMessage({
      type: "scan-server-header",
      tabId: tab.id,
      origin: url.origin
    });
    const serverHeader = response.serverHeader?.trim() ?? "";
    const product = findServerProduct(serverHeader);
    renderServer(serverHeader, product);

    if (!product) {
      statusElement.textContent =
        "Server-Version nicht eindeutig erkennbar; eine verlässliche CVE-Zuordnung ist nicht möglich.";
      return;
    }

    statusElement.textContent =
      `Prüfe ${product.name} ${product.version} gegen die NVD …`;
    const findings = await fetchProductCves(product.cpe);
    renderFindings(findings);
    statusElement.textContent =
      `${product.name} ${product.version}: ${findings.length} CVE(s) mit CVSS über 8,0 gefunden.`;
  } catch (error) {
    statusElement.textContent =
      error.message || "Die Server-Version konnte nicht geprüft werden.";
  } finally {
    scanButton.disabled = !authorizationCheckbox.checked;
  }
}

scanButton.addEventListener("click", scanServer);
