const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const root = path.join(__dirname, "..");

function loadModules(fetch) {
  const context = vm.createContext({
    window: {},
    URL,
    URLSearchParams,
    fetch
  });
  for (const file of [
    "src/popup/scripts/nvd.js",
    "src/popup/scripts/osv.js",
    "src/popup/scripts/technology-detection.js",
    "src/popup/scripts/security-posture.js"
  ]) {
    vm.runInContext(
      fs.readFileSync(path.join(root, file), "utf8"),
      context,
      { filename: file }
    );
  }
  return context;
}

test("detects server and runtime versions in response headers", () => {
  const { window } = loadModules();
  const result = window.CapybaraDetection.inspectResponseHeaders({
    server: ["nginx/1.30.6"],
    "x-powered-by": ["PHP/8.4.26"],
    via: ["1.1 varnish/7.1.0"],
    "x-proxy": ["Traefik/v2.10.5"]
  });

  assert.equal(result.products.find((product) => product.name === "nginx").version, "1.30.6");
  assert.equal(result.products.find((product) => product.name === "PHP").version, "8.4.26");
  assert.equal(result.products.find((product) => product.name === "Varnish").version, "7.1.0");
  assert.equal(result.products.find((product) => product.name === "Traefik").version, "2.10.5");
  assert(result.infrastructure.includes("Proxy-Gateway (Via-Header)"));
});

test("detects JavaScript library versions from already-loaded asset URLs", async () => {
  const context = loadModules();
  const resources = [
    {
      src: "https://cdn.example.test/lodash-4.17.20.min.js",
      href: "",
      tagName: "SCRIPT",
      integrity: ""
    },
    {
      src: "https://cdn.example.test/jquery.min.js?ver=3.5.1",
      href: "",
      tagName: "SCRIPT",
      integrity: ""
    }
  ];
  const document = {
    querySelector: () => null,
    querySelectorAll: () => resources,
    forms: []
  };
  context.browser = {
    tabs: {
      executeScript: async (_tabId, options) => [vm.runInNewContext(options.code, {
        document,
        URL,
        location: {
          href: "https://site.example.test/",
          origin: "https://site.example.test",
          protocol: "https:"
        }
      })]
    }
  };

  const result = await context.window.CapybaraDetection.inspectActivePage(1);
  const lodash = result.components.find((component) => component.slug === "lodash");
  const jquery = result.components.find((component) => component.name === "JavaScript: jQuery");

  assert.equal(lodash.version, "4.17.20");
  assert.equal(lodash.cpe, "cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:*:*:*");
  assert.deepEqual(JSON.parse(JSON.stringify(lodash.osvPackage)), {
    name: "lodash",
    ecosystem: "npm"
  });
  assert.equal(jquery.version, "3.5.1");
  assert.equal(jquery.cpe, null);
});

test("passively flags file and path inputs without sending requests", async () => {
  const context = loadModules();
  class LegacyURL extends URL {
    get searchParams() {
      const params = super.searchParams;
      return {
        get: params.get.bind(params),
        forEach: params.forEach.bind(params),
        keys: () => ({})
      };
    }
  }
  const form = {
    action: "https://site.example.test/download?file=report.pdf",
    method: "get",
    querySelector: () => null,
    querySelectorAll: () => [{ name: "template_name" }, { name: "display_name" }]
  };
  const links = [
    { href: "https://site.example.test/view?document_id=12" }
  ];
  const document = {
    querySelector: () => null,
    querySelectorAll: (selector) => selector === "a[href]" ? links : [],
    forms: [form]
  };
  context.browser = {
    tabs: {
      executeScript: async (_tabId, options) => [vm.runInNewContext(options.code, {
        document,
        URL: LegacyURL,
        location: {
          href: "https://site.example.test/",
          origin: "https://site.example.test",
          protocol: "https:"
        }
      })]
    }
  };

  const result = await context.window.CapybaraDetection.inspectActivePage(1);
  const finding = result.security.find((item) =>
    item.title === "Datei-/Pfad-Eingaben zur manuellen Prüfung erkannt"
  );

  assert(finding);
  assert.match(finding.detail, /kein Nachweis für Path Traversal/);
  assert.match(finding.detail, /keine Testwerte gesendet/);
});

test("audits third-party assets, frames, and form destinations without requests", async () => {
  const context = loadModules();
  const resources = [
    {
      src: "https://cdn.example.test/app.js",
      href: "",
      tagName: "SCRIPT",
      integrity: ""
    },
    {
      src: "",
      href: "https://styles.example.test/site.css",
      tagName: "LINK",
      rel: "stylesheet",
      integrity: "sha384-example"
    },
    {
      src: "https://embed.example.test/widget",
      href: "",
      tagName: "IFRAME",
      integrity: "",
      hasAttribute: () => false
    },
    {
      src: "about:blank",
      href: "",
      tagName: "IFRAME",
      integrity: "",
      hasAttribute: () => true
    }
  ];
  const forms = [{
    action: "https://pay.example.test/checkout",
    method: "post",
    querySelector: () => null,
    querySelectorAll: () => []
  }, {
    action: "mailto:security@example.test",
    method: "post",
    querySelector: () => null,
    querySelectorAll: () => []
  }];
  const document = {
    querySelector: () => null,
    querySelectorAll: (selector) => selector === "a[href]" ? [] : resources,
    forms
  };
  context.browser = {
    tabs: {
      executeScript: async (_tabId, options) => [vm.runInNewContext(options.code, {
        document,
        URL,
        location: {
          href: "https://site.example.test/",
          origin: "https://site.example.test",
          protocol: "https:"
        }
      })]
    }
  };

  const result = await context.window.CapybaraDetection.inspectActivePage(1);
  const thirdParty = result.security.find((finding) =>
    finding.title === "Drittanbieter-Ressourcen erkannt"
  );
  assert.match(thirdParty.detail, /3 externe Herkunft/);
  assert.match(thirdParty.detail, /1 Skript\(e\), 1 Stylesheet\(s\) und 1 Frame\(s\)/);
  assert.doesNotMatch(thirdParty.detail, /example\.test/);
  assert(result.security.some((finding) =>
    finding.title === "Externe Skripte/Stylesheets ohne SRI"
  ));
  assert(result.security.some((finding) =>
    finding.title === "Externe Frames ohne sandbox"
  ));
  assert(result.security.some((finding) =>
    finding.title === "Formulare mit Cross-Origin-Ziel"
  ));
});

test("only reports watchlist products inside known affected ranges", () => {
  const { window } = loadModules();
  const nvd = window.CapybaraNvd;
  const affected = nvd.advisoryFindings([
    { name: "PHP", version: "8.4.26", confidence: "medium" }
  ]);
  const fixed = nvd.advisoryFindings([
    { name: "PHP", version: "8.4.27", confidence: "medium" }
  ]);

  assert(affected.some((finding) => finding.id === "CVE-2026-109618"));
  assert(affected.some((finding) => finding.id === "CVE-2026-109619"));
  assert(!fixed.some((finding) => finding.id.startsWith("CVE-2026-1096")));
});

test("retains advisories without a reliable version range as unconfirmed candidates", () => {
  const { window } = loadModules();
  const findings = window.CapybaraNvd.advisoryFindings([
    {
      name: "Joomla JCE",
      slug: "jce",
      version: "2.9.70",
      confidence: "low"
    }
  ]);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].id, "CVE-2026-48907");
  assert.equal(findings[0].potentiallyAffected, null);
});

test("excludes rejected CVEs returned by NVD", async () => {
  const { window } = loadModules(async () => ({
    ok: true,
    json: async () => ({
      totalResults: 2,
      vulnerabilities: [
        {
          cve: {
            id: "CVE-TEST-REJECTED",
            vulnStatus: "Rejected",
            descriptions: [],
            metrics: {}
          }
        },
        {
          cve: {
            id: "CVE-TEST-VALID",
            vulnStatus: "Analyzed",
            published: "2026-01-01T00:00:00.000",
            descriptions: [{ lang: "en", value: "Sample issue" }],
            metrics: {
              cvssMetricV31: [{
                type: "Primary",
                cvssData: {
                  baseScore: 9.1,
                  vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
              }]
            }
          }
        }
      ]
    })
  }));
  const result = await window.CapybaraNvd.fetchProductCves(
    "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"
  );

  assert.deepEqual(result.findings.map((finding) => finding.id), ["CVE-TEST-VALID"]);
  assert.deepEqual(Array.from(result.findings[0].attackHints), [
    "Netzwerk-Vektor",
    "Keine Privilegien erforderlich",
    "Keine Nutzerinteraktion erforderlich"
  ]);
});

test("classifies root and privilege escalation as description hints, not confirmed access", () => {
  const { window } = loadModules();
  const rootHints = window.CapybaraNvd.assessImpact(
    "A local attacker can gain root access and escalate privileges."
  );
  const unrelatedHints = window.CapybaraNvd.assessImpact(
    "The vulnerability has a root cause in request handling."
  );

  assert(rootHints.includes("Root-/Admin-Zugriff im Advisory erwähnt"));
  assert(rootHints.includes("Privilege-Eskalation im Advisory erwähnt"));
  assert.deepEqual(Array.from(unrelatedHints), []);
  assert.deepEqual(
    Array.from(window.CapybaraNvd.getAttackHints("CVSS:4.0/AV:N/PR:N/UI:N/VC:H")),
    ["Netzwerk-Vektor", "Keine Privilegien erforderlich", "Keine Nutzerinteraktion erforderlich"]
  );
  assert.deepEqual(
    Array.from(window.CapybaraNvd.getAttackHints("AV:N/AC:L/Au:N/C:P/I:P/A:P")),
    ["Netzwerk-Vektor", "Keine Anmeldung erforderlich"]
  );
});

test("queries OSV by npm package and version and includes CVE aliases", async () => {
  let requestUrl;
  let requestBody;
  const { window } = loadModules(async (url, options) => {
    requestUrl = url;
    requestBody = JSON.parse(options.body);
    return {
      ok: true,
      json: async () => ({
        vulns: [{
          id: "GHSA-example",
          aliases: ["CVE-2025-12345"],
          summary: "Example package issue",
          published: "2025-01-01T00:00:00Z",
          database_specific: { severity: "HIGH" }
        }]
      })
    };
  });
  const findings = await window.CapybaraOsv.lookupPackage({
    name: "JavaScript: Lodash",
    version: "4.17.20",
    osvPackage: { name: "lodash", ecosystem: "npm" }
  });

  assert.equal(requestUrl, "https://api.osv.dev/v1/query");
  assert.deepEqual(requestBody, {
    package: { name: "lodash", ecosystem: "npm" },
    version: "4.17.20"
  });
  assert.equal(findings[0].id, "CVE-2025-12345");
  assert.equal(findings[0].sourceUrl, "https://osv.dev/vulnerability/GHSA-example");
  assert.equal(findings[0].severity, "HIGH");
  assert.equal(findings[0].potentiallyAffected, true);
});

test("does not query OSV for incomplete versions and reports HTTP errors", async () => {
  const { window } = loadModules(async () => ({
    ok: false,
    status: 503
  }));
  const component = {
    version: "4.17",
    osvPackage: { name: "lodash", ecosystem: "npm" }
  };
  assert.equal((await window.CapybaraOsv.lookupPackage(component)).length, 0);

  await assert.rejects(
    window.CapybaraOsv.lookupPackage({ ...component, version: "4.17.20" }),
    /OSV antwortet mit HTTP 503/
  );
});

test("reports passive CORS policy inconsistencies", () => {
  const { window } = loadModules();
  const findings = window.CapybaraPosture.assessResponse({
    "access-control-allow-origin": ["*"],
    "access-control-allow-credentials": ["true"]
  }, { count: 0 }, true);

  assert(findings.some((finding) => finding.title === "CORS-Header-Kombination prüfen"));
});

test("flags incomplete CSP directives and invalid cookie prefixes", () => {
  const { window } = loadModules();
  const findings = window.CapybaraPosture.assessResponse({
    "content-security-policy": ["default-src 'self'; script-src 'self'"]
  }, {
    count: 2,
    missingSecure: 0,
    missingHttpOnly: 0,
    missingSameSite: 0,
    invalidHostPrefix: 1,
    invalidSecurePrefix: 1
  }, true);

  assert(findings.some((finding) => finding.title === "CSP beschränkt object-src nicht auf none"));
  assert(findings.some((finding) => finding.title === "CSP ohne base-uri"));
  assert(findings.some((finding) => finding.title === "Ungültige __Host-Cookie-Attribute"));
  assert(findings.some((finding) => finding.title === "Ungültige __Secure-Cookie-Attribute"));
});
