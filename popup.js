const scanButton = document.querySelector("#scan");
const statusElement = document.querySelector("#status");
const technologyElement = document.querySelector("#technologies");
const resultsElement = document.querySelector("#results");

function detectTechnologies() {
  const generator = document.querySelector('meta[name="generator" i]')?.content ?? "";
  const resourceUrls = Array.from(
    document.querySelectorAll("a[href], form[action], script[src], link[href]")
  )
    .slice(0, 300)
    .map((element) =>
      element.getAttribute("href") ??
      element.getAttribute("action") ??
      element.getAttribute("src") ??
      ""
    );
  const evidence = [generator, location.pathname, ...resourceUrls].join("\n");
  const detected = [];

  if (/\bPHP\b/i.test(generator) || /\.php(?:[?#]|$)/i.test(evidence)) {
    detected.push({ name: "PHP", evidence: "PHP-Generator oder .php-Pfad" });
  }

  const signatures = [
    ["WordPress", /wordpress/i, /\/wp-(?:content|includes)\//i],
    ["Drupal", /drupal/i, /\/sites\/(?:default|all)\//i],
    ["Joomla", /joomla/i, /\/media\/system\//i],
    ["Magento", /magento/i, /\/static\/(?:version\d+\/)?frontend\//i],
    ["Laravel", /laravel/i, /laravel/i],
    ["Symfony", /symfony/i, /symfony/i]
  ];

  for (const [name, generatorPattern, resourcePattern] of signatures) {
    if (generatorPattern.test(generator) || resourceUrls.some((url) => resourcePattern.test(url))) {
      detected.push({ name, evidence: "Generator-Metadaten oder typische Ressourcen" });
    }
  }

  return detected;
}

async function getActiveTab() {
  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) {
    throw new Error("Der aktive Tab konnte nicht gefunden werden.");
  }
  return tab;
}

async function inspectPage(tabId) {
  const [result] = await browser.tabs.executeScript(tabId, {
    code: `(${detectTechnologies.toString()})()`
  });
  return result ?? [];
}

function getCvss(metrics) {
  const sources = [
    ["CVSS 4.0", metrics.cvssMetricV40],
    ["CVSS 3.1", metrics.cvssMetricV31],
    ["CVSS 3.0", metrics.cvssMetricV30],
    ["CVSS 2.0", metrics.cvssMetricV2]
  ];
  const scores = [];

  for (const [version, entries] of sources) {
    if (!entries?.length) continue;
    const metric = entries.find((entry) => entry.type === "Primary") ?? entries[0];
    const score = metric.cvssData?.baseScore;
    if (typeof score === "number") scores.push({ score, version });
  }
  return scores.sort((a, b) => b.score - a.score)[0] ?? null;
}

function publishedRange() {
  const end = new Date();
  const start = new Date(end.getTime() - 119 * 24 * 60 * 60 * 1000);
  return { start: start.toISOString(), end: end.toISOString() };
}

async function fetchTechnologyCves(technology) {
  const range = publishedRange();
  const params = new URLSearchParams({
    keywordSearch: technology,
    pubStartDate: range.start,
    pubEndDate: range.end,
    resultsPerPage: "100",
    sortBy: "published",
    sortOrder: "desc"
  });
  const response = await fetch(
    `https://services.nvd.nist.gov/rest/json/cves/2.0?${params.toString()}`
  );
  if (!response.ok) {
    throw new Error(`NVD antwortet mit HTTP ${response.status} für ${technology}.`);
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
        published: cve.published,
        technology
      };
    })
    .filter(Boolean);
}

function renderTechnologies(technologies) {
  technologyElement.replaceChildren();
  if (!technologies.length) return;

  const heading = document.createElement("strong");
  heading.textContent = "Erkannte Hinweise";
  const list = document.createElement("div");
  list.className = "technology-list";
  for (const technology of technologies) {
    const tag = document.createElement("span");
    tag.className = "technology";
    tag.textContent = technology.name;
    list.append(tag);
  }
  technologyElement.append(heading, list);
}

function renderFindings(findings) {
  resultsElement.replaceChildren();
  if (!findings.length) {
    const empty = document.createElement("p");
    empty.textContent = "Keine CVEs mit CVSS über 8,0 im abgefragten Zeitraum gefunden.";
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
    const date = new Date(finding.published).toLocaleDateString("de-DE");
    details.textContent = `${finding.technology} · veröffentlicht ${date}`;
    article.append(heading, description, details);
    resultsElement.append(article);
  }
}

async function scanPage() {
  scanButton.disabled = true;
  statusElement.textContent = "Seite wird passiv analysiert …";
  technologyElement.replaceChildren();
  resultsElement.replaceChildren();

  try {
    const tab = await getActiveTab();
    const technologies = await inspectPage(tab.id);
    renderTechnologies(technologies);
    if (!technologies.length) {
      statusElement.textContent =
        "Keine unterstützten Technologien anhand sichtbarer Metadaten oder Ressourcen erkannt.";
      return;
    }

    const selected = technologies.slice(0, 3);
    const skipped = technologies.length - selected.length;
    statusElement.textContent = `Frage NVD nach aktuellen CVEs für ${selected
      .map((technology) => technology.name)
      .join(", ")} …`;

    const results = await Promise.allSettled(
      selected.map((technology) => fetchTechnologyCves(technology.name))
    );
    const findings = new Map();
    const failures = [];
    results.forEach((result, index) => {
      if (result.status === "rejected") {
        failures.push(result.reason.message);
        return;
      }
      for (const finding of result.value) {
        const existing = findings.get(finding.id);
        if (existing) {
          existing.technology = `${existing.technology}, ${finding.technology}`;
        } else {
          findings.set(finding.id, finding);
        }
      }
    });

    const sortedFindings = [...findings.values()]
      .sort((a, b) => new Date(b.published) - new Date(a.published))
      .slice(0, 20);
    renderFindings(sortedFindings);

    const notes = [];
    if (failures.length) notes.push(failures.join(" "));
    if (skipped) notes.push(`${skipped} weitere erkannte Technologie(n) nicht abgefragt.`);
    if (notes.length) {
      statusElement.textContent = notes.join(" ");
    } else {
      statusElement.textContent = `${sortedFindings.length} mögliche CVE(s) aus den letzten 120 Tagen.`;
    }
  } catch (error) {
    statusElement.textContent =
      error.message || "Die Seite konnte nicht analysiert werden.";
  } finally {
    scanButton.disabled = false;
  }
}

scanButton.addEventListener("click", scanPage);
scanPage();
