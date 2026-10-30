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
  assert.equal(jquery.version, "3.5.1");
  assert.equal(jquery.cpe, null);
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
                cvssData: { baseScore: 9.1 }
              }]
            }
          }
        }
      ]
    })
  }));
  const result = await window.CapybaraNvd.fetchProductCves("cpe:test");

  assert.deepEqual(result.findings.map((finding) => finding.id), ["CVE-TEST-VALID"]);
});

test("reports passive CORS policy inconsistencies", () => {
  const { window } = loadModules();
  const findings = window.CapybaraPosture.assessResponse({
    "access-control-allow-origin": ["*"],
    "access-control-allow-credentials": ["true"]
  }, { count: 0 }, true);

  assert(findings.some((finding) => finding.title === "CORS-Header-Kombination prüfen"));
});
