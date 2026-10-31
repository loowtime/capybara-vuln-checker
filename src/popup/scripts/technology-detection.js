window.CapybaraDetection = (() => {
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
    },
    {
      name: "LiteSpeed",
      category: "Webserver",
      expression: /(?:^|[\s,(])litespeed(?: web server)?\/(\d+(?:\.\d+){1,3})(?:$|[\s,(])/i
    },
    {
      name: "Varnish",
      category: "HTTP-Cache / Reverse-Proxy",
      expression: /(?:^|[\s,(])varnish\/(\d+(?:\.\d+){1,3})(?:$|[\s,(])/i
    },
    {
      name: "Envoy",
      category: "HTTP-Proxy",
      expression: /(?:^|[\s,(])envoy\/v?(\d+(?:\.\d+){1,3})(?:$|[\s,(])/i
    },
    {
      name: "Traefik",
      category: "HTTP-Proxy",
      expression: /(?:^|[\s,(])traefik\/v?(\d+(?:\.\d+){1,3})(?:$|[\s,(])/i
    },
    {
      name: "Gunicorn",
      category: "Python-Application-Server",
      expression: /(?:^|[\s,(])gunicorn\/(\d+(?:\.\d+){1,3})(?:$|[\s,(])/i
    },
    {
      name: "uWSGI",
      category: "Python-Application-Server",
      expression: /(?:^|[\s,(])uwsgi\/(\d+(?:\.\d+){1,3})(?:$|[\s,(])/i
    },
    {
      name: "Eclipse Jetty",
      category: "Java-Application-Server",
      expression: /(?:^|[\s,(])jetty(?:\(|\/)(\d+(?:\.\d+){1,3})(?:$|[\s,(.)])/i
    }
  ];

  const productsWithoutVersion = [
    ["Apache HTTP Server", /\bapache(?:\/\d| http server\b|$)/i, "Webserver"],
    ["nginx", /\bnginx\b/i, "Webserver"],
    ["Microsoft IIS", /\bmicrosoft-iis\b|\biis\b/i, "Webserver"],
    ["Apache Tomcat", /\b(?:tomcat|apache-coyote)\b/i, "Java-Application-Server"],
    ["PHP", /\bphp\b/i, "Runtime"],
    ["OpenSSL", /\bopenssl\b/i, "Kryptografie-Bibliothek"],
    ["Node.js", /\bnode\.?js\b/i, "Runtime"],
    ["Caddy", /\bcaddy\b/i, "Webserver"],
    ["Lighttpd", /\blighttpd\b/i, "Webserver"],
    ["OpenResty", /\bopenresty\b/i, "Webserver / Nginx-Derivat"],
    ["Microsoft ASP.NET", /\basp\.net\b|\bx-aspnet-version\b/i, "Web-Framework"],
    ["Express", /\bexpress\b/i, "Node.js-Framework"],
    ["WordPress", /\bwordpress\b/i, "CMS"],
    ["Drupal", /\bdrupal\b/i, "CMS"],
    ["Joomla", /\bjoomla\b/i, "CMS"],
    ["Atlassian Confluence", /\bconfluence\b/i, "Collaboration-Software"],
    ["Atlassian Bitbucket", /\bbitbucket\b/i, "Developer-Platform"],
    ["Oracle WebLogic", /\bweblogic\b/i, "Java-Application-Server"],
    ["Microsoft Exchange", /\b(exchange|outlook web access|owa)\b/i, "Mail-Server"]
  ];

  function normalizeHeaders(headers) {
    if (!headers || typeof headers !== "object" || Array.isArray(headers)) return {};
    return Object.fromEntries(Object.entries(headers).map(([name, values]) => [
      name.toLowerCase(),
      (Array.isArray(values) ? values : [values])
        .filter((value) => typeof value === "string")
    ]));
  }

  function inspectResponseHeaders(headers) {
    headers = normalizeHeaders(headers);
    const products = new Map();
    const text = Object.entries(headers)
      .map(([name, values]) => `${name}: ${values.join(", ")}`)
      .join("\n");

    for (const signature of serviceSignatures) {
      for (const [headerName, values] of Object.entries(headers)) {
        for (const value of values) {
          const match = value.match(signature.expression);
          if (!match) continue;

          const previous = products.get(signature.name);
          if (previous) {
            previous.versions = [...new Set([...previous.versions, match[1]])];
            previous.version = previous.versions.length === 1 ? match[1] : null;
            previous.cpe = previous.version ? signature.cpe?.(previous.version) : null;
            previous.versionStatus = previous.version ? "header-observed-unverified" : "ambiguous";
            previous.confidence = previous.version ? "medium" : "low";
            previous.source = [...new Set([...previous.source.split(", "), headerName])].join(", ");
            previous.raw = [...new Set([...previous.raw.split("\n"), value])].join("\n");
          } else {
            products.set(signature.name, {
              ...signature,
              version: match[1],
              versions: [match[1]],
              confidence: "medium",
              versionStatus: "header-observed-unverified",
              detectionMethod: `HTTP-Response-Header "${headerName}"`,
              cpe: signature.cpe?.(match[1]),
              source: headerName,
              raw: value
            });
          }
        }
      }
    }

    for (const [name, expression, category] of productsWithoutVersion) {
      if (!products.has(name) && expression.test(text)) {
        products.set(name, {
          name,
          category,
          version: null,
          confidence: "low",
          versionStatus: "unknown",
          detectionMethod: "Technologiebegriff in HTTP-Response-Headern",
          source: "HTTP-Header"
        });
      }
    }

    return { products: [...products.values()], infrastructure: detectInfrastructure(headers) };
  }

  function detectInfrastructure(headers) {
    const text = Object.entries(headers)
      .map(([name, values]) => `${name}: ${values.join(", ")}`)
      .join("\n");
    const hints = [];

    if (/cloudflare/i.test(text) || headers["cf-ray"]) hints.push("Cloudflare/CDN oder Reverse-Proxy");
    if (/cloudfront/i.test(text) || headers["x-amz-cf-id"]) hints.push("Amazon CloudFront/CDN");
    if (/varnish/i.test(text) || headers["x-varnish"]) hints.push("Varnish-Cache/Reverse-Proxy");
    if (headers.via) hints.push("Proxy-Gateway (Via-Header)");

    return [...new Set(hints)];
  }

  function inspectPage() {
    const clientLibraries = [
      {
        name: "JavaScript: jQuery",
        category: "JavaScript-Abhängigkeit",
        osvPackage: { name: "jquery", ecosystem: "npm" },
        assetPattern: /(?:^|\/)jquery(?:\.min)?\.js$/i,
        expression: /(?:^|\/)jquery(?:[-.]v?)(\d+\.\d+(?:\.\d+)?)(?:[./-]|$)/i
      },
      {
        name: "JavaScript: Bootstrap",
        category: "JavaScript-Abhängigkeit",
        osvPackage: { name: "bootstrap", ecosystem: "npm" },
        assetPattern: /(?:^|\/)bootstrap(?:\.min)?\.js$/i,
        expression: /(?:^|\/)bootstrap(?:[-.]v?)(\d+\.\d+(?:\.\d+)?)(?:[./-]|$)/i
      },
      {
        name: "JavaScript: Lodash",
        slug: "lodash",
        category: "JavaScript-Abhängigkeit",
        osvPackage: { name: "lodash", ecosystem: "npm" },
        assetPattern: /(?:^|\/)lodash(?:\.min)?\.js$/i,
        expression: /(?:^|\/)lodash(?:[-.]v?)(\d+\.\d+(?:\.\d+)?)(?:[./-]|$)/i,
        cpe: (version) => `cpe:2.3:a:lodash:lodash:${version}:*:*:*:*:*:*:*`
      },
      {
        name: "JavaScript: AngularJS",
        category: "JavaScript-Abhängigkeit",
        osvPackage: { name: "angular", ecosystem: "npm" },
        assetPattern: /(?:^|\/)angular(?:\.min)?\.js$/i,
        expression: /(?:^|\/)angular(?:[-.]v?)(\d+\.\d+(?:\.\d+)?)(?:[./-]|$)/i
      }
    ];
    const generator = document.querySelector('meta[name="generator" i]')?.content ?? "";
    const resourceUrls = Array.from(document.querySelectorAll("script[src], link[href]"))
      .slice(0, 500)
      .map((element) => element.src || element.href)
      .filter(Boolean);
    const components = new Map();
    const addComponent = (component) => {
      const current = components.get(component.name);
      if (!current || (!current.version && component.version)) {
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
        confidence: "medium",
        versionStatus: "generator-unverified",
        detectionMethod: "Generator-Meta-Element im Seiten-DOM",
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
        confidence: "medium",
        versionStatus: "generator-unverified",
        detectionMethod: "Generator-Meta-Element im Seiten-DOM",
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

      const pluginMatch = url.pathname.match(/\/wp-content\/plugins\/([^/]+)/i);
      if (pluginMatch) {
        const slug = pluginMatch[1].toLowerCase();
        const queryVersion = url.searchParams.get("ver");
        const version = /^\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.-]+)?$/.test(queryVersion ?? "")
          ? queryVersion
          : null;
        addComponent({
          name: `WordPress-Plugin: ${slug}`,
          slug,
          category: "WordPress-Plugin",
          version,
          source: "geladene Plugin-Ressource",
          confidence: "low",
          versionStatus: version ? "asset-query-unverified" : "unknown",
          detectionMethod: "Plugin-Pfad und optionaler ver-Parameter einer bereits geladenen Ressource",
          note: version
            ? "Versionshinweis aus Asset-URL; kann eine Datei-/Cacheversion statt der installierten Plugin-Version sein."
            : "Plugin-Pfad sichtbar, Versionsnummer nicht erkennbar."
        });
      }

      if (/\/(?:components\/com_jce\/|plugins\/editors\/jce\/)/i.test(url.pathname)) {
        const queryVersion = url.searchParams.get("ver");
        addComponent({
          name: "Joomla JCE",
          slug: "jce",
          category: "Joomla-Editor-Plugin",
          version: /^\d+(?:\.\d+){0,3}(?:-[0-9A-Za-z.-]+)?$/.test(queryVersion ?? "")
            ? queryVersion
            : null,
          source: "geladene JCE-Ressource",
          confidence: "low",
          versionStatus: "asset-query-unverified",
          detectionMethod: "Pfad einer bereits geladenen Joomla-JCE-Ressource",
          note: "JCE erkannt; aus öffentlichen Ressourcen ist die installierte Version oft nicht verlässlich ableitbar."
        });
      }

      for (const library of clientLibraries) {
        const match = url.pathname.match(library.expression);
        const queryVersion = url.searchParams.get("ver");
        const versionHint = match?.[1] ?? queryVersion;
        const version = /^\d+(?:\.\d+){1,2}$/.test(versionHint ?? "")
          ? versionHint
          : null;
        if (match || library.assetPattern.test(url.pathname)) {
          addComponent({
            name: library.name,
            slug: library.slug,
            category: library.category,
            osvPackage: library.osvPackage,
            version,
            source: "geladene JavaScript-Ressource",
            confidence: "low",
            versionStatus: version ? "asset-url-unverified" : "unknown",
            detectionMethod: "Dateiname/Query-Parameter einer bereits geladenen Ressource",
            cpe: version && library.cpe ? library.cpe(version) : null,
            note: version
              ? "Versionshinweis aus einer öffentlich eingebundenen Asset-URL; vor einer Update-Entscheidung im Deployment bestätigen."
              : "Bibliothek erkannt, aber keine verlässliche Versionsnummer in der geladenen Ressource gefunden."
          });
        }
      }
    }

    const security = [];
    const isHttps = location.protocol === "https:";
    if (!isHttps) {
      security.push({
        level: "warning",
        title: "Website wird über HTTP geladen",
        detail: "HTTPS schützt die Verbindung vor Mitlesen und Manipulation. Prüfe, ob die Website vollständig auf HTTPS umgestellt werden kann."
      });
    }

    const resources = Array.from(document.querySelectorAll(
      "script[src], link[href], img[src], iframe[src], audio[src], video[src], source[src]"
    )).slice(0, 1000);
    let mixedContentCount = 0;
    let externalScriptCount = 0;
    let externalScriptsWithoutSri = 0;
    let externalStylesheetCount = 0;
    let externalStylesheetsWithoutSri = 0;
    let externalIframeCount = 0;
    let externalIframesWithoutSandbox = 0;
    const externalOrigins = new Set();
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
        ["http:", "https:"].includes(resourceUrl.protocol) &&
        resourceUrl.origin !== location.origin
      ) {
        if (element.tagName === "SCRIPT") {
          externalOrigins.add(resourceUrl.origin);
          externalScriptCount += 1;
          if (!element.integrity) externalScriptsWithoutSri += 1;
        } else if (element.tagName === "LINK" &&
          element.rel?.toLowerCase().split(/\s+/).includes("stylesheet")) {
          externalOrigins.add(resourceUrl.origin);
          externalStylesheetCount += 1;
          if (!element.integrity) externalStylesheetsWithoutSri += 1;
        } else if (element.tagName === "IFRAME") {
          externalOrigins.add(resourceUrl.origin);
          externalIframeCount += 1;
          if (!element.hasAttribute("sandbox")) externalIframesWithoutSandbox += 1;
        }
      }
    }
    if (externalOrigins.size) {
      security.push({
        level: "info",
        title: "Drittanbieter-Ressourcen erkannt",
        detail: `${externalOrigins.size} externe Herkunft(en) über ${externalScriptCount} Skript(e), ${externalStylesheetCount} Stylesheet(s) und ${externalIframeCount} Frame(s). Prüfe Anbieter, Zweck und CSP-Freigaben; es wurden keine zusätzlichen Anfragen gesendet.`
      });
    }
    if (mixedContentCount) {
      security.push({
        level: "warning",
        title: "Gemischte Inhalte (Mixed Content)",
        detail: `${mixedContentCount} Ressource(n) werden per HTTP in die HTTPS-Seite eingebunden. Stelle die Ressourcen auf HTTPS um oder entferne sie.`
      });
    }
    if (externalScriptsWithoutSri || externalStylesheetsWithoutSri) {
      security.push({
        level: "warning",
        title: "Externe Skripte/Stylesheets ohne SRI",
        detail: `${externalScriptsWithoutSri} Skript(e) und ${externalStylesheetsWithoutSri} Stylesheet(s) haben keine Subresource Integrity (SRI). Bei stabil versionierten CDN-Dateien SRI erwägen; dynamische Ressourcen sind nicht immer dafür geeignet.`
      });
    }
    if (externalIframesWithoutSandbox) {
      security.push({
        level: "info",
        title: "Externe Frames ohne sandbox",
        detail: `${externalIframesWithoutSandbox} externe Frame(s) haben kein sandbox-Attribut. Prüfe, ob die Einbettung nötig ist und sich mit einer möglichst restriktiven Sandbox betreiben lässt.`
      });
    }

    let crossOriginFormCount = 0;
    for (const form of Array.from(document.forms).slice(0, 200)) {
      try {
        const actionUrl = new URL(form.action || location.href, location.href);
        if (
          ["http:", "https:"].includes(actionUrl.protocol) &&
          actionUrl.origin !== location.origin
        ) {
          crossOriginFormCount += 1;
        }
      } catch {
        continue;
      }
    }
    if (crossOriginFormCount) {
      security.push({
        level: "info",
        title: "Formulare mit Cross-Origin-Ziel",
        detail: `${crossOriginFormCount} Formular(e) senden an eine andere Herkunft. Das kann beabsichtigt sein, etwa bei Zahlungsdiensten; gleiche jedes Ziel mit einer bekannten Allowlist ab und übermittle keine unnötigen Daten.`
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
      security.push({
        level: "warning",
        title: "Passwortformular mit GET-Methode",
        detail: `${getPasswordForms} Passwortformular(e) verwenden GET. Zugangsdaten dürfen nicht in URL, Browser-Verlauf oder Referrer gelangen; verwende POST über HTTPS.`
      });
    }
    if (insecurePasswordForms) {
      security.push({
        level: "warning",
        title: "Passwortformular sendet über HTTP",
        detail: `${insecurePasswordForms} Passwortformular(e) senden an eine HTTP-Adresse. Zieladresse auf HTTPS umstellen.`
      });
    }

    const pathInputNames = new Set([
      "file", "filepath", "filename", "path", "directory", "dir", "folder",
      "template", "include", "download", "document", "resource", "asset"
    ]);
    const hasPathInputName = (name) => name
      .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .some((part) => pathInputNames.has(part));
    const hasPathQueryParameter = (url) => {
      let found = false;
      url.searchParams.forEach((_value, name) => {
        if (hasPathInputName(name)) found = true;
      });
      return found;
    };
    const endpointsWithPathInputs = new Set();

    for (const form of Array.from(document.forms).slice(0, 200)) {
      const fieldNames = Array.from(form.querySelectorAll("[name]"))
        .map((field) => field.name)
        .filter(hasPathInputName);
      let actionUrl;
      try {
        actionUrl = new URL(form.action || location.href, location.href);
      } catch {
        continue;
      }

      if (fieldNames.length || hasPathQueryParameter(actionUrl)) {
        endpointsWithPathInputs.add("Formular");
      }
    }

    for (const link of Array.from(document.querySelectorAll("a[href]")).slice(0, 500)) {
      let linkUrl;
      try {
        linkUrl = new URL(link.href, location.href);
      } catch {
        continue;
      }
      if (hasPathQueryParameter(linkUrl)) {
        endpointsWithPathInputs.add("Link");
      }
    }

    if (endpointsWithPathInputs.size) {
      security.push({
        level: "info",
        title: "Datei-/Pfad-Eingaben zur manuellen Prüfung erkannt",
        detail: `Bereits gerenderte ${[...endpointsWithPathInputs].join(" und ")} enthalten Felder oder URL-Parameter mit Datei-/Pfadbezug. Das ist kein Nachweis für Path Traversal. Prüfe serverseitig feste Basisverzeichnisse, erlaubte Dateinamen und kanonische Pfadvalidierung. Es wurden keine Testwerte gesendet.`
      });
    }

    return { components: [...components.values()], security };
  }

  async function inspectActivePage(tabId) {
    const [result] = await browser.tabs.executeScript(tabId, {
      code: `(${inspectPage.toString()})()`
    });
    return result ?? { components: [], security: [] };
  }

  return { inspectResponseHeaders, inspectActivePage };
})();
