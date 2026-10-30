const authorizationCheckbox = document.querySelector("#authorized");
const scanButton = document.querySelector("#scan");
const statusElement = document.querySelector("#status");
const serverElement = document.querySelector("#server");
const componentsElement = document.querySelector("#components");
const postureElement = document.querySelector("#posture");
const resultsElement = document.querySelector("#results");
let activePage = null;

const serviceSignatures = [
  {
    name: "nginx",
    category: "Webserver",
    expression: /(?:^|[\s,(])nginx\/(\d+(?:\.\d+){1,3})(?:$|[\s,(])/i,
    cpe: (version) => `cpe:2.3:a:f5:nginx:${version}:*:*:*:*:*:*:*`
  },
  {
    name: "Apache HTTP Server",
    category: "Webserver",
    expression: /(?:^|[\s,(])apache\/(\d+(?:\.\d+){1,3})(?:$|[\s,(])/i,
    cpe: (version) => `cpe:2.3:a:apache:http_server:${version}:*:*:*:*:*:*:*`
  },
  {
    name: "Microsoft IIS",
    category: "Webserver",
    expression: /(?:^|[\s,(])microsoft-iis\/(\d+(?:\.\d+){1,3})(?:$|[\s,(])/i,
    cpe: (version) => `cpe:2.3:a:microsoft:iis:${version}:*:*:*:*:*:*:*`
  },
  {
    name: "Apache Tomcat",
    category: "Java-Application-Server",
    expression: /(?:^|[\s,(])(?:apache[- ]?)?tomcat\/(\d+(?:\.\d+){1,3})(?:$|[\s,(])/i,
    cpe: (version) => `cpe:2.3:a:apache:tomcat:${version}:*:*:*:*:*:*:*`
  },
  {
    name: "PHP",
    category: "Runtime",
    expression: /(?:^|[\s,(])php\/(\d+(?:\.\d+){1,3})(?:$|[\s,(])/i,
    cpe: (version) => `cpe:2.3:a:php:php:${version}:*:*:*:*:*:*:*`
  },
  {
    name: "OpenSSL",
    category: "Kryptografie-Bibliothek",
    expression: /(?:^|[\s,(])openssl\/(\d+(?:\.\d+){1,3})(?:$|[\s,(])/i,
    cpe: (version) => `cpe:2.3:a:openssl:openssl:${version}:*:*:*:*:*:*:*`
  },
  {
    name: "Node.js",
    category: "Runtime",
    expression: /(?:^|[\s,(])node\.?js\/v?(\d+(?:\.\d+){1,3})(?:$|[\s,(])/i,
    cpe: (version) => `cpe:2.3:a:nodejs:node.js:${version}:*:*:*:*:*:*:*`
  },
  {
    name: "Caddy",
    category: "Webserver",
    expression: /(?:^|[\s,(])caddy\/(\d+(?:\.\d+){1,3})(?:$|[\s,(])/i,
    cpe: (version) => `cpe:2.3:a:caddyserver:caddy:${version}:*:*:*:*:*:*:*`
  },
  {
    name: "Lighttpd",
    category: "Webserver",
    expression: /(?:^|[\s,(])lighttpd\/(\d+(?:\.\d+){1,3})(?:$|[\s,(])/i,
    cpe: (version) => `cpe:2.3:a:lighttpd:lighttpd:${version}:*:*:*:*:*:*:*`
  },
  {
    name: "OpenResty",
    category: "Webserver / Nginx-Derivat",
    expression: /(?:^|[\s,(])openresty\/(\d+(?:\.\d+){1,3})(?:$|[\s,(])/i
  }
];

const productNamesWithoutVersion = [
  ["Apache HTTP Server", /\bapache(?:\/\d| http server\b|$)/i],
  ["nginx", /\bnginx\b/i],
  ["Microsoft IIS", /\bmicrosoft-iis\b|\biis\b/i],
  ["Apache Tomcat", /\btomcat\b/i],
  ["PHP", /\bphp\b/i],
  ["OpenSSL", /\bopenssl\b/i],
  ["Node.js", /\bnode\.?js\b/i],
  ["Caddy", /\bcaddy\b/i],
  ["Lighttpd", /\blighttpd\b/i],
  ["OpenResty", /\bopenresty\b/i],
  ["Microsoft ASP.NET", /\basp\.net\b|\bx-aspnet-version\b/i],
  ["Express", /\bexpress\b/i],
  ["WordPress", /\bwordpress\b/i],
  ["Drupal", /\bdrupal\b/i]
];
const productCategories = {
  "Apache HTTP Server": "Webserver",
  nginx: "Webserver",
  "Microsoft IIS": "Webserver",
  "Apache Tomcat": "Java-Application-Server",
  PHP: "Runtime",
  OpenSSL: "Kryptografie-Bibliothek",
  "Node.js": "Runtime",
  Caddy: "Webserver",
  Lighttpd: "Webserver",
  OpenResty: "Webserver / Nginx-Derivat",
  "Microsoft ASP.NET": "Web-Framework",
  Express: "Node.js-Framework",
  WordPress: "CMS",
  Drupal: "CMS"
};

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

function inspectResponseHeaders(headers) {
  const products = new Map();
  const text = Object.entries(headers)
    .map(([name, values]) => `${name}: ${values.join(", ")}`)
    .join("\n");

  for (const signature of serviceSignatures) {
    for (const [headerName, values] of Object.entries(headers)) {
      for (const value of values) {
        const match = value.match(signature.expression);
        if (match) {
          const previous = products.get(signature.name);
          if (previous) {
            previous.versions = [...new Set([...previous.versions, match[1]])];
            previous.version = previous.versions.length === 1 ? match[1] : null;
            previous.cpe = previous.version ? signature.cpe?.(previous.version) : null;
            previous.source = [...new Set([...previous.source.split(", "), headerName])].join(", ");
            previous.raw = [...new Set([...previous.raw.split("\n"), value])].join("\n");
          } else {
            products.set(signature.name, {
              ...signature,
              version: match[1],
              versions: [match[1]],
              cpe: signature.cpe?.(match[1]),
              source: headerName,
              raw: value
            });
          }
        }
      }
    }
  }

  for (const [name, expression] of productNamesWithoutVersion) {
    if (!products.has(name) && expression.test(text)) {
      products.set(name, {
        name,
        category: productCategories[name],
        version: null,
        source: "HTTP-Header"
      });
    }
  }

  return {
    products: [...products.values()],
    infrastructure: detectInfrastructure(headers)
  };
}

function inspectPageComponents() {
  const generator =
    document.querySelector('meta[name="generator" i]')?.content ?? "";
  const resourceUrls = Array.from(
    document.querySelectorAll("script[src], link[href]")
  )
    .slice(0, 500)
    .map((element) => element.src || element.href)
    .filter(Boolean);
  const components = new Map();
  const addComponent = (component) => {
    const existing = components.get(component.name);
    if (!existing || (!existing.version && component.version)) {
      components.set(component.name, component);
    }
  };

  const wordpressVersion = generator.match(/\bWordPress\s+(\d+(?:\.\d+){1,2})/i)?.[1];
  if (wordpressVersion) {
    addComponent({
      name: "WordPress",
      category: "CMS",
      version: wordpressVersion,
      source: "Generator-Metadatum",
      cpe: `cpe:2.3:a:wordpress:wordpress:${wordpressVersion}:*:*:*:*:*:*:*`
    });
  }

  const joomlaVersion = generator.match(/\bJoomla!?\s*(\d+(?:\.\d+){1,2})/i)?.[1];
  if (joomlaVersion) {
    addComponent({
      name: "Joomla",
      category: "CMS",
      version: joomlaVersion,
      source: "Generator-Metadatum",
      cpe: `cpe:2.3:a:joomla:joomla:${joomlaVersion}:*:*:*:*:*:*:*`
    });
  }

  for (const resource of resourceUrls) {
    let url;
    try {
      url = new URL(resource, location.href);
    } catch {
      continue;
    }

    const wpPlugin = url.pathname.match(/\/wp-content\/plugins\/([^/]+)/i);
    if (wpPlugin) {
      const slug = wpPlugin[1];
      addComponent({
        name: `WordPress-Plugin: ${slug}`,
        category: "WordPress-Plugin",
        version: url.searchParams.get("ver"),
        source: "geladene Plugin-Ressource",
        note: url.searchParams.has("ver")
          ? "Versionshinweis aus Asset-URL; kann eine Datei-/Cacheversion statt der installierten Plugin-Version sein."
          : "Plugin-Pfad sichtbar, Versionsnummer nicht erkennbar."
      });
    }

    if (/\/(?:components\/com_jce\/|plugins\/editors\/jce\/)/i.test(url.pathname)) {
      addComponent({
        name: "Joomla JCE",
        category: "Joomla-Editor-Plugin",
        version: url.searchParams.get("ver"),
        source: "geladene JCE-Ressource",
        note: "JCE erkannt; aus öffentlichen Ressourcen ist die installierte Version oft nicht verlässlich ableitbar."
      });
    }
  }

  return [...components.values()];
}

function inspectPageSecurity() {
  const findings = [];
  const isHttps = location.protocol === "https:";
  if (!isHttps) {
    findings.push({
      level: "warning",
      title: "Website wird über HTTP geladen",
      detail: "HTTPS schützt die Verbindung vor Mitlesen und Manipulation. Prüfe, ob die Website vollständig auf HTTPS umgestellt werden kann."
    });
  }

  const resources = Array.from(
    document.querySelectorAll(
      "script[src], link[href], img[src], iframe[src], audio[src], video[src], source[src]"
    )
  ).slice(0, 1000);
  let mixedContentCount = 0;
  let externalScriptsWithoutSri = 0;
  for (const element of resources) {
    const rawUrl = element.src || element.href;
    if (!rawUrl) continue;
    let resourceUrl;
    try {
      resourceUrl = new URL(rawUrl, location.href);
    } catch {
      continue;
    }

    if (isHttps && resourceUrl.protocol === "http:") mixedContentCount += 1;
    if (
      element.tagName === "SCRIPT" &&
      resourceUrl.origin !== location.origin &&
      !element.integrity
    ) {
      externalScriptsWithoutSri += 1;
    }
  }
  if (mixedContentCount) {
    findings.push({
      level: "warning",
      title: "Gemischte Inhalte (Mixed Content)",
      detail: `${mixedContentCount} Ressource(n) werden per HTTP in die HTTPS-Seite eingebunden. Stelle die Ressourcen auf HTTPS um oder entferne sie.`
    });
  }
  if (externalScriptsWithoutSri) {
    findings.push({
      level: "warning",
      title: "Externe Skripte ohne SRI-Integritätsprüfung",
      detail: `${externalScriptsWithoutSri} externes Skript(e) haben kein Subresource Integrity (SRI). Bei stabil versionierten CDN-Dateien SRI erwägen; dynamische Skripte sind nicht immer dafür geeignet.`
    });
  }

  const passwordForms = Array.from(document.forms).filter((form) =>
    form.querySelector('input[type="password"]')
  );
  const getPasswordForms = passwordForms.filter(
    (form) => (form.method || "get").toLowerCase() === "get"
  ).length;
  const insecurePasswordForms = passwordForms.filter((form) => {
    try {
      return new URL(form.action || location.href, location.href).protocol === "http:";
    } catch {
      return false;
    }
  }).length;
  if (getPasswordForms) {
    findings.push({
      level: "warning",
      title: "Passwortformular mit GET-Methode",
      detail: `${getPasswordForms} Passwortformular(e) verwenden GET. Zugangsdaten dürfen nicht in URL, Browser-Verlauf oder Referrer gelangen; verwende POST über HTTPS.`
    });
  }
  if (insecurePasswordForms) {
    findings.push({
      level: "warning",
      title: "Passwortformular sendet über HTTP",
      detail: `${insecurePasswordForms} Passwortformular(e) senden an eine HTTP-Adresse. Zieladresse auf HTTPS umstellen.`
    });
  }

  return findings;
}

async function inspectActivePage(tabId) {
  const [result] = await browser.tabs.executeScript(tabId, {
    code: `({
      components: (${inspectPageComponents.toString()})(),
      security: (${inspectPageSecurity.toString()})()
    })`
  });
  return result ?? { components: [], security: [] };
}

function assessResponseSecurity(headers, cookieFlags, isHttps) {
  const findings = [];
  const header = (name) => headers[name]?.join(", ") ?? "";
  const csp = header("content-security-policy");
  const cspReportOnly = header("content-security-policy-report-only");

  if (!isHttps) {
    findings.push({
      level: "warning",
      title: "HSTS nicht sinnvoll über HTTP prüfbar",
      detail: "Rufe die Website über HTTPS auf. Strict-Transport-Security wird von Browsern nur über sichere Verbindungen berücksichtigt."
    });
  } else {
    const hsts = header("strict-transport-security");
    const maxAge = Number(hsts.match(/(?:^|;)\s*max-age=(\d+)/i)?.[1] ?? 0);
    if (!hsts) {
      findings.push({
        level: "warning",
        title: "HSTS fehlt",
        detail: "Strict-Transport-Security kann Browser auf HTTPS festlegen. Prüfe eine passende max-age und ob includeSubDomains für deine Subdomains geeignet ist."
      });
    } else if (maxAge < 15_552_000) {
      findings.push({
        level: "warning",
        title: "HSTS max-age ist kürzer als sechs Monate",
        detail: "Prüfe, ob eine längere max-age passend ist. HSTS-Preload nur nach Prüfung aller Subdomains erwägen."
      });
    }
  }

  if (!csp) {
    findings.push({
      level: cspReportOnly ? "info" : "warning",
      title: cspReportOnly ? "CSP ist nur im Report-Only-Modus aktiv" : "Content Security Policy fehlt",
      detail: cspReportOnly
        ? "Content-Security-Policy-Report-Only erzwingt die Richtlinie nicht. Nach Prüfung der Reports kann eine CSP schrittweise durchgesetzt werden."
        : "Eine passende CSP kann die Auswirkungen bestimmter Injection-Fehler begrenzen. Zunächst im Report-Only-Modus testen und an die Anwendung anpassen."
    });
  } else {
    const directives = new Map(
      csp.split(";").map((part) => {
        const [name, ...values] = part.trim().split(/\s+/);
        return [name?.toLowerCase(), values.join(" ")];
      })
    );
    if (!directives.has("default-src")) {
      findings.push({
        level: "info",
        title: "CSP ohne default-src",
        detail: "Prüfe, ob eine restriktive default-src als Fallback für nicht explizit gesetzte Ressourcentypen sinnvoll ist."
      });
    }
    if (/'unsafe-inline'|'unsafe-eval'/.test(directives.get("script-src") ?? "")) {
      findings.push({
        level: "warning",
        title: "CSP erlaubt unsichere Skript-Ausnahmen",
        detail: "script-src enthält unsafe-inline oder unsafe-eval. Nonces/Hashes und das Entfernen von Inline-Skripten können die Richtlinie stärken."
      });
    }
  }

  if (!header("x-content-type-options").split(",").some((value) => value.trim().toLowerCase() === "nosniff")) {
    findings.push({
      level: "warning",
      title: "X-Content-Type-Options: nosniff fehlt",
      detail: "nosniff reduziert MIME-Type-Sniffing durch Browser."
    });
  }
  if (!header("x-frame-options") && !/frame-ancestors\b/i.test(csp)) {
    findings.push({
      level: "warning",
      title: "Clickjacking-Schutz nicht erkannt",
      detail: "Setze eine passende CSP frame-ancestors-Richtlinie oder X-Frame-Options, falls Einbettung nicht benötigt wird."
    });
  }
  if (!header("referrer-policy")) {
    findings.push({
      level: "info",
      title: "Referrer-Policy fehlt",
      detail: "Eine explizite Referrer-Policy, zum Beispiel strict-origin-when-cross-origin, macht die Referrer-Freigabe vorhersehbarer."
    });
  }
  if (!header("permissions-policy")) {
    findings.push({
      level: "info",
      title: "Permissions-Policy fehlt",
      detail: "Prüfe, ob nicht benötigte Browser-Funktionen wie Kamera oder Mikrofon für diese Website eingeschränkt werden sollten."
    });
  }
  if (!header("cross-origin-opener-policy")) {
    findings.push({
      level: "info",
      title: "Cross-Origin-Opener-Policy fehlt",
      detail: "Für Anwendungen mit Bedarf an Browser-Isolation kann COOP sinnvoll sein; prüfe mögliche Auswirkungen auf Pop-ups und Anmeldungen."
    });
  }

  if (cookieFlags.count) {
    if (isHttps && cookieFlags.missingSecure) {
      findings.push({
        level: "warning",
        title: "Cookies ohne Secure-Attribut",
        detail: `${cookieFlags.missingSecure} von ${cookieFlags.count} gesetzten Cookies haben kein Secure-Attribut. Für Sitzungscookies über HTTPS sollte es aktiviert sein.`
      });
    }
    if (cookieFlags.missingHttpOnly) {
      findings.push({
        level: "info",
        title: "Cookies ohne HttpOnly-Attribut",
        detail: `${cookieFlags.missingHttpOnly} von ${cookieFlags.count} gesetzten Cookies sind für JavaScript zugänglich. Für Sitzungscookies HttpOnly prüfen.`
      });
    }
    if (cookieFlags.missingSameSite) {
      findings.push({
        level: "info",
        title: "Cookies ohne explizites SameSite",
        detail: `${cookieFlags.missingSameSite} von ${cookieFlags.count} gesetzten Cookies setzen SameSite nicht explizit. Für Sitzungscookies Lax oder Strict prüfen; Cross-Site-Flows benötigen ggf. None; Secure.`
      });
    }
  }

  const server = header("server");
  if (/\b(?:nginx|apache|microsoft-iis|caddy|lighttpd)\/\d/i.test(server)) {
    findings.push({
      level: "info",
      title: "Detaillierter Server-Banner offengelegt",
      detail: "Die Antwort verrät Produkt und Version. Banner-Reduktion erschwert passive Fingerprints, ersetzt aber keine Updates."
    });
  }

  return findings;
}

function renderPosture(findings) {
  postureElement.replaceChildren();
  const heading = document.createElement("strong");
  heading.className = "posture-heading";
  heading.textContent = "Passive Sicherheits-Checkliste";
  postureElement.append(heading);

  if (!findings.length) {
    const item = document.createElement("p");
    item.textContent = "Bei diesen Prüfungen wurden keine Auffälligkeiten erkannt. Das ist kein vollständiges Sicherheitsaudit.";
    postureElement.append(item);
    return;
  }

  for (const finding of findings) {
    const item = document.createElement("article");
    item.className = `posture-item posture-${finding.level}`;
    const title = document.createElement("strong");
    title.textContent = `${finding.level === "warning" ? "Prüfen" : "Hinweis"}: ${finding.title}`;
    const detail = document.createElement("p");
    detail.textContent = finding.detail;
    item.append(title, detail);
    postureElement.append(item);
  }
}

function detectInfrastructure(headers) {
  const text = Object.entries(headers)
    .map(([name, values]) => `${name}: ${values.join(", ")}`)
    .join("\n");
  const hints = [];

  if (/cloudflare/i.test(text) || headers["cf-ray"]) {
    hints.push("Cloudflare/CDN oder Reverse-Proxy");
  }
  if (/cloudfront/i.test(text) || headers["x-amz-cf-id"]) {
    hints.push("Amazon CloudFront/CDN");
  }
  if (/varnish/i.test(text) || headers["x-varnish"]) {
    hints.push("Varnish-Cache/Reverse-Proxy");
  }
  if (headers.via) hints.push("Proxy-Gateway (Via-Header)");

  return [...new Set(hints)];
}

function renderComponents(components) {
  componentsElement.replaceChildren();
  const heading = document.createElement("strong");
  heading.textContent = "CMS & geladene Erweiterungen";
  componentsElement.append(heading);

  if (!components.length) {
    const empty = document.createElement("p");
    empty.textContent =
      "Keine CMS-/Plugin-Versionen in Generator-Metadaten oder geladenen Ressourcen erkannt.";
    componentsElement.append(empty);
    return;
  }

  for (const component of components) {
    const item = document.createElement("div");
    item.className = "component-info";
    const title = document.createElement("strong");
    title.textContent = component.name;
    const details = document.createElement("p");
    details.textContent = `${component.category} · ${
      component.version
        ? `Version ${component.version}`
        : "Version unbekannt"
    } · ${component.source}`;
    item.append(title, details);

    if (component.note) {
      const note = document.createElement("p");
      note.className = "assessment";
      note.textContent = component.note;
      item.append(note);
    } else if (component.version && component.category.includes("Plugin")) {
      const note = document.createElement("p");
      note.className = "assessment";
      note.textContent =
        "Versionswert aus öffentlicher Asset-URL; bitte im CMS/Deployment bestätigen, bevor du ein Update planst.";
      item.append(note);
    }
    componentsElement.append(item);
  }
}

function renderServer(headers, inspection) {
  serverElement.replaceChildren();
  const heading = document.createElement("strong");
  heading.textContent = "Erkannte Dienste und Hinweise";
  serverElement.append(heading);

  if (inspection.products.length === 0 && inspection.infrastructure.length === 0) {
    const empty = document.createElement("p");
    empty.textContent = "Keine bekannten Dienste in den erfassten Antwort-Headern erkannt.";
    serverElement.append(empty);
  }

  for (const product of inspection.products) {
    const box = document.createElement("div");
    box.className = "server-info";
    const title = document.createElement("strong");
    title.textContent = product.name;
    const detail = document.createElement("p");
    detail.textContent = product.version
      ? `${product.category} · Version ${product.version} · erkannt in ${product.source}`
      : product.versions?.length > 1
        ? `${product.category} · widersprüchliche Versionsangaben (${product.versions.join(", ")}); kein CVE-Abgleich`
        : `${product.category} · Dienst erkannt, aber keine eindeutige Versionsnummer im Header.`;
    box.append(title, detail);

    if (product.raw && /\b(?:debian|ubuntu|alpine|red hat|rhel|centos)\b/i.test(product.raw)) {
      const distro = document.createElement("p");
      distro.className = "assessment";
      distro.textContent =
        "Distributionspaket erkannt: Sicherheitskorrekturen können zurückportiert sein. Upstream-Version und NVD-Treffer allein belegen daher keine Verwundbarkeit.";
      box.append(distro);
    }

    const result = product.version ? inspection.results.get(product.name) : null;
    if (result?.error) {
      const note = document.createElement("p");
      note.className = "assessment";
      note.textContent = `NVD-Abfrage fehlgeschlagen: ${result.error}`;
      box.append(note);
    } else if (result) {
      const note = document.createElement("p");
      note.className = "assessment";
      note.textContent = result.totalResults > 100
        ? `${result.totalResults} NVD-Einträge für diese Produkt-/Versions-Kombination; die ersten 100 (nach Veröffentlichungsdatum) geprüft.`
        : `${result.totalResults} NVD-Einträge für diese Produkt-/Versions-Kombination geprüft.`;
      box.append(note);
    } else if (product.version && !product.cpe) {
      const note = document.createElement("p");
      note.className = "assessment";
      note.textContent = "Version erkannt, aber noch kein sicher zugeordnetes NVD-Produktprofil vorhanden.";
      box.append(note);
    }

    serverElement.append(box);
  }

  if (inspection.infrastructure.length) {
    const proxyNote = document.createElement("p");
    proxyNote.className = "assessment";
    proxyNote.textContent =
      `Infrastruktur-Hinweise: ${inspection.infrastructure.join(", ")}. Der sichtbare Server kann ein Proxy/CDN statt des Ursprungsservers sein.`;
    serverElement.append(proxyNote);
  }

  if (Object.keys(headers).length) {
    const summary = document.createElement("details");
    const summaryLabel = document.createElement("summary");
    summaryLabel.textContent = "Erfasste Response-Header anzeigen";
    const list = document.createElement("ul");
    for (const [name, values] of Object.entries(headers)) {
      const item = document.createElement("li");
      item.textContent = `${name}: ${values.join(", ")}`;
      list.append(item);
    }
    summary.append(summaryLabel, list);
    serverElement.append(summary);
  }
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
  const findings = (data.vulnerabilities ?? [])
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
  return { findings, totalResults: data.totalResults ?? findings.length };
}

function severityLabel(score) {
  if (score >= 9) return "Kritisch";
  if (score >= 7) return "Hoch";
  if (score >= 4) return "Mittel";
  return "Niedrig";
}

function renderFindings(findings, queryCount, failedCount) {
  resultsElement.replaceChildren();
  if (!findings.length) {
    const empty = document.createElement("p");
    if (queryCount === 0) {
      empty.textContent =
        "Keine CVE-Abfrage möglich: Es wurde keine exakt unterstützte Produktversion erkannt.";
    } else if (failedCount === queryCount) {
      empty.textContent = "Die NVD-Abfragen sind fehlgeschlagen; es liegt kein CVE-Ergebnis vor.";
    } else if (failedCount > 0) {
      empty.textContent =
        "Für erfolgreiche NVD-Abfragen wurden keine CVEs mit CVSS über 8,0 gefunden; mindestens eine Abfrage ist fehlgeschlagen.";
    } else {
      empty.textContent =
        "In den erfolgreichen NVD-Abfragen wurden keine CVEs mit CVSS über 8,0 gefunden.";
    }
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
    score.className = `score ${finding.score >= 9 ? "score-critical" : "score-high"}`;
    score.textContent =
      `${severityLabel(finding.score)} · ${finding.score.toFixed(1)} · ${finding.version}`;
    heading.append(link, score);

    const description = document.createElement("p");
    description.textContent =
      finding.description.length > 300
        ? `${finding.description.slice(0, 297)}…`
        : finding.description;

    const details = document.createElement("small");
    details.textContent =
      `${finding.product} ${finding.productVersion} · veröffentlicht ${new Date(finding.published).toLocaleDateString("de-DE")}`;
    article.append(heading, description, details);
    resultsElement.append(article);
  }

  const note = document.createElement("p");
  note.className = "assessment";
  note.textContent =
    "Ein CVSS-Score bewertet die Schwachstelle allgemein. Er bestätigt nicht, dass die Website betroffen ist; Distribution-Patches, Konfiguration und Proxy-Aufbau können das Ergebnis ändern.";
  resultsElement.prepend(note);
}

async function scanServer() {
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
    const hostPermission = browser.permissions.request({
      origins: [`*://${url.hostname}/*`]
    });
    if (!(await hostPermission)) {
      throw new Error("Firefox benötigt die Website-Berechtigung, um Antwort-Header zu lesen.");
    }

    statusElement.textContent = "Seite wird einmal neu geladen, um den Server-Header zu lesen …";
    const response = await browser.runtime.sendMessage({
      type: "scan-server-header",
      tabId: tab.id,
      origin: url.origin
    });
    const headers = response.headers ?? {};
    const inspection = inspectResponseHeaders(headers);
    const pageInspection = await inspectActivePage(tab.id);
    const components = pageInspection.components;
    const cmsProducts = components
      .filter((component) => component.cpe)
      .map((component) => ({
        ...component,
        cpe: component.cpe,
        raw: "",
        versions: [component.version]
      }));
    for (const cmsProduct of cmsProducts) {
      const existingIndex = inspection.products.findIndex(
        (product) => product.name === cmsProduct.name
      );
      if (existingIndex < 0) {
        inspection.products.push(cmsProduct);
      } else if (!inspection.products[existingIndex].version) {
        inspection.products[existingIndex] = cmsProduct;
      }
    }
    const queryable = inspection.products.filter((product) => product.version && product.cpe);
    inspection.results = new Map();

    statusElement.textContent = queryable.length
      ? `Prüfe ${queryable.length} erkannte Dienst(e) in der NVD …`
      : "Dienste werden eingeordnet …";
    const findings = [];
    for (const [index, product] of queryable.entries()) {
      statusElement.textContent =
        `NVD-Abfrage ${index + 1} von ${queryable.length}: ${product.name} ${product.version} …`;
      try {
        const result = await fetchProductCves(product.cpe);
        inspection.results.set(product.name, { totalResults: result.totalResults });
        for (const finding of result.findings) {
          findings.push({
            ...finding,
            product: product.name,
            productVersion: product.version
          });
        }
      } catch (error) {
        inspection.results.set(product.name, { error: error.message });
      }

      if (index < queryable.length - 1) {
        await new Promise((resolve) => setTimeout(resolve, 6200));
      }
    }

    const failed = [...inspection.results.values()].filter((result) => result.error).length;
    renderServer(headers, inspection);
    renderComponents(components);
    renderPosture([
      ...assessResponseSecurity(
        headers,
        response.cookieFlags ?? {
          count: 0,
          missingSecure: 0,
          missingHttpOnly: 0,
          missingSameSite: 0
        },
        url.protocol === "https:"
      ),
      ...pageInspection.security
    ]);
    renderFindings(findings.sort((a, b) => b.score - a.score).slice(0, 30), queryable.length, failed);
    statusElement.textContent = `${inspection.products.length} Dienst(e) erkannt, ${findings.length} CVE(s) mit CVSS über 8,0${failed ? `; ${failed} NVD-Abfrage(n) fehlgeschlagen` : ""}.`;
  } catch (error) {
    statusElement.textContent =
      error.message || "Die Server-Version konnte nicht geprüft werden.";
  } finally {
    scanButton.disabled = !authorizationCheckbox.checked;
  }
}

scanButton.addEventListener("click", scanServer);
initializePopup();
