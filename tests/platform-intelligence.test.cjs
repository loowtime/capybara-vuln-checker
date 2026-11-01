const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const scriptPaths = [
  "src/popup/scripts/nvd.js",
  "src/popup/scripts/evidence.js",
  "src/popup/scripts/confidence-intelligence.js",
  "src/popup/scripts/risk-prioritization.js",
  "src/popup/scripts/threat-intelligence.js",
  "src/popup/scripts/sbom.js",
  "src/popup/scripts/history.js",
  "src/popup/scripts/reports.js",
  "src/popup/scripts/remediation.js"
];

function loadPlatform(fetcher = fetch) {
  const context = vm.createContext({
    window: {}, URL, URLSearchParams, TextEncoder, Blob, fetch: fetcher
  });
  for (const file of scriptPaths) {
    vm.runInContext(fs.readFileSync(file, "utf8"), context, { filename: file });
  }
  return context.window;
}

test("evidence retains unverified version status and adds source and timestamp", () => {
  const platform = loadPlatform();
  const evidence = platform.CapybaraEvidence.attach({
    id: "CVE-2025-1234",
    source: "NVD-CPE-Abgleich",
    product: "nginx",
    productVersion: "1.24.0",
    technicalEvidence: { versionStatus: "header-observed-unverified" }
  }, { observedAt: "2026-11-01T10:00:00.000Z" });

  assert.equal(evidence.source, "NVD-CPE-Abgleich");
  assert.equal(evidence.observedAt, "2026-11-01T10:00:00.000Z");
  assert.equal(evidence.technicalEvidence.versionStatus, "header-observed-unverified");
  assert.equal(evidence.confidence, "medium");
});

test("risk treats negative KEV results correctly and reduces weak matches", () => {
  const { CapybaraRisk } = loadPlatform();
  const negativeKev = CapybaraRisk.prioritize({
    score: null,
    epss: null,
    kev: { known: false },
    confidence: "medium",
    matchConfidence: { level: "medium", score: 60 }
  });
  assert.equal(negativeKev.level, "niedrig");
  assert.doesNotMatch(negativeKev.reasons.join(" "), /CISA führt/);

  const weakKnownExploited = CapybaraRisk.prioritize({
    score: 9.8,
    version: "CVSS 3.1",
    kev: { known: true },
    confidence: "low",
    matchConfidence: { level: "low", score: 35 },
    attackHints: ["Netzwerk-Vektor"]
  });
  assert.equal(weakKnownExploited.level, "mittel");
  assert.ok(weakKnownExploited.decision);

  const verifiedKnownExploited = CapybaraRisk.prioritize({
    score: 9.8,
    kev: { known: true },
    confidence: "high",
    matchConfidence: { level: "high", score: 90 },
    attackHints: ["Netzwerk-Vektor"]
  });
  assert.equal(verifiedKnownExploited.level, "kritisch");
});

test("parses valid KEV records and ignores malformed identifiers", () => {
  const { CapybaraThreatIntel } = loadPlatform();
  const records = CapybaraThreatIntel.parseKevFeed({
    vulnerabilities: [
      { cveID: "CVE-2024-12345", dateAdded: "2024-01-01" },
      { cveID: "not-a-cve" },
      null
    ]
  });
  assert.equal(records.size, 1);
  assert.equal(records.get("CVE-2024-12345").dateAdded, "2024-01-01");
  assert.throws(() => CapybaraThreatIntel.parseKevFeed({ vulnerabilities: {} }), /Format/);
});

test("ignores malformed EPSS rows and accepts only valid scores", async () => {
  const { CapybaraThreatIntel } = loadPlatform(async () => ({
    ok: true,
    json: async () => ({
      data: [
        null,
        { cve: "CVE-2024-12345", epss: null, percentile: "0.5" },
        { cve: "CVE-2024-12345", epss: "1.2", percentile: "0.5" },
        { cve: "not-cve", epss: "0.5", percentile: "0.5" },
        { cve: "CVE-2024-54321", epss: "0.5", percentile: null }
      ]
    })
  }));
  const results = await CapybaraThreatIntel.fetchEpss([
    "CVE-2024-12345",
    "CVE-2024-54321"
  ]);
  assert.equal(results.has("CVE-2024-12345"), false);
  assert.deepEqual(JSON.parse(JSON.stringify(results.get("CVE-2024-54321"))), {
    score: 0.5,
    percentile: null,
    date: null
  });
  await assert.rejects(CapybaraThreatIntel.fetchEpss(null), /Liste von CVE-IDs/);
  await assert.rejects(CapybaraThreatIntel.enrichFindings(null), /Liste von Befunden/);
});

test("enriches CVEs with KEV and EPSS and marks valid no-match results", async () => {
  const { CapybaraThreatIntel } = loadPlatform();
  const calls = [];
  const fetcher = async (url) => {
    calls.push(url);
    if (url.includes("cisa.gov")) {
      return {
        ok: true,
        json: async () => ({
          vulnerabilities: [{
            cveID: "CVE-2024-12345",
            dateAdded: "2024-05-01",
            knownRansomwareCampaignUse: "Known"
          }]
        })
      };
    }
    return {
      ok: true,
      json: async () => ({
        data: [{ cve: "CVE-2024-12345", epss: "0.42", percentile: "0.91", date: "2026-10-31" }]
      })
    };
  };
  const result = await CapybaraThreatIntel.enrichFindings([
    { id: "CVE-2024-12345", product: "nginx" }
  ], { fetch: fetcher, storage: null });
  assert.equal(result.findings[0].kev.known, true);
  assert.equal(result.findings[0].epss.score, 0.42);
  assert.equal(result.findings[0].epss.percentile, 0.91);
  assert.equal(calls.length, 2);

  const empty = await CapybaraThreatIntel.enrichFindings([
    { id: "CVE-2024-12345", product: "nginx" }
  ], {
    fetch: async (url) => ({
      ok: true,
      json: async () => url.includes("cisa.gov")
        ? { vulnerabilities: [] }
        : { data: [] }
    }),
    storage: null
  });
  assert.deepEqual(JSON.parse(JSON.stringify(empty.findings[0].kev)), {
    known: false,
    source: "CISA KEV"
  });
});

test("does not fetch threat feeds if there are no CVE identifiers", async () => {
  const { CapybaraThreatIntel } = loadPlatform();
  let called = false;
  const result = await CapybaraThreatIntel.enrichFindings(
    [{ id: "GHSA-unknown" }],
    { fetch: async () => { called = true; }, storage: null }
  );
  assert.equal(called, false);
  assert.equal(result.errors.length, 0);
});

test("parses nested CycloneDX and SPDX package URLs without confirming deployment", () => {
  const { CapybaraSbom } = loadPlatform();
  const cyclone = CapybaraSbom.parse(JSON.stringify({
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    components: [{
      type: "library",
      name: "root",
      components: [{
        type: "library",
        name: "lodash",
        version: "4.17.20",
        purl: "pkg:npm/lodash@4.17.20"
      }]
    }]
  }));
  assert.equal(cyclone.components.length, 2);
  assert.equal(cyclone.components[1].osvPackage.name, "lodash");
  assert.equal(cyclone.components[1].versionStatus, "declared-unverified");

  const spdx = CapybaraSbom.parse(JSON.stringify({
    spdxVersion: "SPDX-2.3",
    packages: [{
      name: "requests",
      versionInfo: "2.31.0",
      externalRefs: [{
        referenceCategory: "PACKAGE-MANAGER",
        referenceType: "purl",
        referenceLocator: "pkg:pypi/requests@2.31.0"
      }]
    }]
  }));
  assert.equal(spdx.components[0].osvPackage.ecosystem, "PyPI");
});

test("SBOM parser rejects malformed, unsupported and conflicting inputs", () => {
  const { CapybaraSbom } = loadPlatform();
  assert.throws(() => CapybaraSbom.parse(""), /leer/);
  assert.throws(() => CapybaraSbom.parse("{"), /gültiges JSON/);
  assert.throws(() => CapybaraSbom.parse(JSON.stringify({ bomFormat: "Other", components: [] })), /Unbekanntes SBOM/);
  assert.throws(() => CapybaraSbom.parse("x".repeat(5 * 1024 * 1024 + 1)), /5 MiB/);

  const parsed = CapybaraSbom.parse(JSON.stringify({
    bomFormat: "CycloneDX",
    components: [{
      name: "lodash",
      version: "4.17.20",
      purl: "pkg:npm/lodash@4.17.21"
    }]
  }));
  assert.equal(parsed.components[0].version, null);
  assert.equal(parsed.components[0].versionStatus, "ambiguous");
  assert.equal(parsed.components[0].osvPackage, null);
});

test("NVD handles malformed response entries, duplicate CVEs, and invalid input", async () => {
  const { CapybaraNvd } = loadPlatform(async () => ({
    ok: true,
    json: async () => ({
      vulnerabilities: [
        null,
        { cve: null },
        { cve: { id: "CVE-2024-11111", vulnStatus: "Rejected" } },
        {
          cve: {
            id: "CVE-2024-22222",
            vulnStatus: "Analyzed",
            descriptions: [{ lang: "en", value: "Advisory text" }],
            metrics: {
              cvssMetricV31: [{
                type: "Primary",
                cvssData: { baseScore: 8.1, vectorString: "CVSS:3.1/AV:N/PR:N/UI:N" }
              }]
            }
          }
        },
        {
          cve: {
            id: "CVE-2024-33333",
            vulnStatus: "Analyzed",
            metrics: { cvssMetricV31: "bad-shape" }
          }
        },
        { cve: { id: "CVE-2024-22222", vulnStatus: "Analyzed" } }
      ]
    })
  }));
  await assert.rejects(CapybaraNvd.fetchProductCves("invalid"), /CPE-2\.3/);
  const result = await CapybaraNvd.fetchProductCves("cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*");
  assert.equal(result.findings.length, 2);
  assert.equal(result.findings[0].id, "CVE-2024-22222");
  assert.equal(result.findings[0].score, 8.1);
  assert.equal(result.findings[0].description, "Advisory text");
  assert.equal(result.findings[1].score, null);
  assert.equal(CapybaraNvd.versionIsAffected("1.2.3", { versionRanges: [["broken"]] }), null);
});

test("history recognizes version-only changes and supports clearing local state", async () => {
  const { CapybaraHistory } = loadPlatform();
  const change = CapybaraHistory.diff({
    findings: [{ id: "CVE-2025-1234", product: "nginx", productVersion: "1.24.0" }],
    components: [{ name: "nginx", version: "1.24.0" }],
    headers: { "content-security-policy": ["default-src 'self'"] }
  }, {
    findings: [{ id: "CVE-2025-1234", product: "nginx", productVersion: "1.26.0" }],
    components: [{ name: "nginx", version: "1.26.0" }],
    headers: { "content-security-policy": ["default-src 'none'"] }
  });
  assert.equal(change.newFindings.length, 0);
  assert.equal(change.resolvedFindings.length, 0);
  assert.equal(change.versionChanges.length, 2);
  assert.deepEqual(Array.from(change.headerChanges), ["content-security-policy"]);

  const data = {};
  const storage = {
    async get(key) { return { [key]: data[key] }; },
    async set(value) { Object.assign(data, value); },
    async remove(key) { delete data[key]; }
  };
  await CapybaraHistory.record("https://example.test", {
    findings: [null, {}, { id: "CVE-2025-1234", product: "nginx" }],
    components: [null, {}, { name: "nginx" }],
    headers: {}
  }, storage);
  const snapshots = await CapybaraHistory.read("https://example.test", storage);
  assert.equal(snapshots.length, 1);
  assert.equal(snapshots[0].findings.length, 1);
  assert.equal(snapshots[0].components.length, 1);
  await CapybaraHistory.clear("https://example.test", storage);
  assert.equal((await CapybaraHistory.read("https://example.test", storage)).length, 0);
  await assert.rejects(
    CapybaraHistory.record("https://example.test/path", { findings: [], components: [] }, storage),
    /nicht verfügbar/
  );
});

test("CSV report aligns headers, protects spreadsheet formulas and includes evidence", () => {
  const { CapybaraReports } = loadPlatform();
  const csv = CapybaraReports.csv([{
    id: "CVE-2025-1234",
    product: "=HYPERLINK(\"https://example.test\")",
    source: "NVD",
    confidence: "medium",
    detectionMethod: "CPE",
    observedAt: "2026-11-01T00:00:00.000Z",
    technicalEvidence: { versionStatus: "unverified" },
    remediation: { action: "Patch prüfen", priority: "hoch", slaDays: 7 },
    risk: { level: "hoch", reasons: ["KEV"] }
  }]);
  const [header, row] = csv.split("\r\n");
  assert.equal(header.split(",").length, row.split(",").length);
  assert.match(csv, /'=HYPERLINK/);
  assert.match(csv, /versionStatus/);
  assert.match(csv, /Patch prüfen/);
});
