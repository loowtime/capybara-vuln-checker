const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const context = { window: {} };
vm.runInNewContext(
  fs.readFileSync("src/popup/scripts/coverage.js", "utf8"),
  context
);
const coverage = context.window.CapybaraCoverage;

const byLabel = (report, label) =>
  report.checks.find((check) => check.label === label);

test("marks a complete website scan with all sources available", () => {
  const report = coverage.build({
    mode: "website",
    headers: { server: ["nginx"], "content-security-policy": ["default-src 'self'"] },
    pageAnalysis: true,
    tls: { available: true, metadata: { protocolVersion: "TLSv1.3" }, issues: [] },
    nvd: { queries: 2, failed: 0 },
    osv: { queries: 1, failed: 0 },
    threatIntel: { required: true, kev: true, epss: true },
    advisory: { matches: 1 },
    history: { state: "recorded" }
  });

  assert.equal(report.checks.length, 8);
  assert.equal(byLabel(report, "HTTP-Response-Header").state, "complete");
  assert.equal(byLabel(report, "Passive Seitenanalyse").state, "complete");
  assert.equal(byLabel(report, "TLS-Verbindungsmetadaten").state, "complete");
  assert.equal(byLabel(report, "NVD-CPE-Abgleich").state, "complete");
  assert.equal(byLabel(report, "OSV-Paketabgleich").state, "complete");
  assert.equal(byLabel(report, "CISA KEV & FIRST EPSS").state, "complete");
  assert.equal(byLabel(report, "Kuratierter Advisory-Katalog").state, "complete");
  assert.equal(byLabel(report, "Lokale Scan-Historie").state, "complete");
});

test("keeps partial, failed and unavailable sources visible", () => {
  const report = coverage.build({
    headers: {},
    pageAnalysis: false,
    tls: { available: false, reason: "TLS-Berechtigung fehlt." },
    nvd: { queries: 3, failed: 1 },
    osv: { queries: 2, failed: 2 },
    threatIntel: { required: true, kev: true, epss: false },
    advisory: { matches: 0 },
    history: { state: "failed", detail: "Speicher voll" }
  });

  assert.equal(byLabel(report, "HTTP-Response-Header").state, "unavailable");
  assert.equal(byLabel(report, "Passive Seitenanalyse").state, "unavailable");
  const tls = byLabel(report, "TLS-Verbindungsmetadaten");
  assert.equal(tls.state, "unavailable");
  assert.match(tls.detail, /TLS-Berechtigung fehlt/);
  assert.equal(byLabel(report, "NVD-CPE-Abgleich").state, "partial");
  assert.equal(byLabel(report, "OSV-Paketabgleich").state, "unavailable");
  const intel = byLabel(report, "CISA KEV & FIRST EPSS");
  assert.equal(intel.state, "partial");
  assert.match(intel.detail, /FIRST EPSS/);
  assert.doesNotMatch(intel.detail, /CISA KEV und FIRST EPSS konnten/);
  const history = byLabel(report, "Lokale Scan-Historie");
  assert.equal(history.state, "unavailable");
  assert.match(history.detail, /Speicher voll/);
});

test("marks missing queries and feeds as skipped instead of failed", () => {
  const report = coverage.build({
    headers: { server: ["nginx"] },
    pageAnalysis: true,
    tls: null,
    nvd: { queries: 0, failed: 0 },
    osv: { queries: 0, failed: 0 },
    threatIntel: { required: false },
    advisory: { matches: 0 },
    history: { state: "skipped" }
  });

  assert.equal(byLabel(report, "TLS-Verbindungsmetadaten").state, "skipped");
  assert.equal(byLabel(report, "NVD-CPE-Abgleich").state, "skipped");
  assert.equal(byLabel(report, "OSV-Paketabgleich").state, "skipped");
  assert.equal(byLabel(report, "CISA KEV & FIRST EPSS").state, "skipped");
  assert.equal(byLabel(report, "Lokale Scan-Historie").state, "skipped");
});

test("documents SBOM provenance and partial OSV coverage", () => {
  const report = coverage.build({
    mode: "sbom",
    sbom: { format: "CycloneDX 1.5", components: 4 },
    osv: { queries: 4, failed: 1 },
    threatIntel: { required: true, kev: true, epss: true }
  });

  assert.deepEqual(
    JSON.parse(JSON.stringify(report.checks.map((check) => check.label))),
    ["SBOM-Import", "SBOM-Versionsangaben", "OSV-Paketabgleich", "CISA KEV & FIRST EPSS"]
  );
  assert.equal(byLabel(report, "SBOM-Import").state, "complete");
  assert.equal(byLabel(report, "SBOM-Versionsangaben").state, "unverified");
  assert.equal(byLabel(report, "OSV-Paketabgleich").state, "partial");
});

test("defaults to a website report that makes missing data explicit", () => {
  const report = coverage.build();
  assert.equal(report.checks.length, 8);
  assert.equal(byLabel(report, "HTTP-Response-Header").state, "unavailable");
  assert.equal(byLabel(report, "TLS-Verbindungsmetadaten").state, "skipped");
  assert.equal(byLabel(report, "Lokale Scan-Historie").state, "skipped");
});
