const assert = require("node:assert/strict");
const fs = require("node:fs");
const test = require("node:test");
const vm = require("node:vm");

const context = { window: {} };
vm.runInNewContext(
  fs.readFileSync("src/popup/scripts/findings-view.js", "utf8"),
  context
);
const view = context.window.CapybaraFindingsView;

const findings = [
  {
    id: "CVE-2026-0001",
    product: "WordPress",
    productVersion: "6.8.1",
    description: "SQL-Injection in WP_Query",
    source: "NVD-CPE-Abgleich",
    risk: { level: "hoch" },
    kev: { known: true },
    relatedIds: ["GHSA-aaaa"]
  },
  {
    id: "CVE-2026-0002",
    product: "nginx",
    productVersion: "1.24.0",
    description: "HTTP/2 request handling issue",
    source: "NVD-CPE-Abgleich",
    risk: { level: "mittel" },
    kev: { known: false }
  },
  {
    id: "GHSA-bbbb",
    product: "JavaScript: Lodash",
    description: "Prototype pollution",
    source: "OSV/npm",
    risk: { level: "niedrig" },
    kev: null,
    relatedIds: ["CVE-2026-0003"]
  }
];

const ids = (items) => JSON.parse(JSON.stringify(items.map((item) => item.id)));

test("filters case-insensitively by ID, product, description and alias", () => {
  assert.deepEqual(ids(view.filter(findings, { query: "LODASH" })), ["GHSA-bbbb"]);
  assert.deepEqual(ids(view.filter(findings, { query: "cve-2026-0003" })), ["GHSA-bbbb"]);
  assert.deepEqual(ids(view.filter(findings, { query: "sql-injection" })), ["CVE-2026-0001"]);
  assert.deepEqual(ids(view.filter(findings, { query: "  nginx  " })), ["CVE-2026-0002"]);
});

test("combines priority and KEV filters with free-text search", () => {
  assert.deepEqual(ids(view.filter(findings, { priority: "hoch" })), ["CVE-2026-0001"]);
  assert.deepEqual(ids(view.filter(findings, { kevOnly: true })), ["CVE-2026-0001"]);
  assert.deepEqual(
    ids(view.filter(findings, { priority: "mittel", query: "nginx" })),
    ["CVE-2026-0002"]
  );
  assert.deepEqual(
    ids(view.filter(findings, { priority: "hoch", query: "nginx" })),
    []
  );
});

test("reports whether a filter is active and ignores invalid criteria", () => {
  assert.equal(view.isActive({}), false);
  assert.equal(view.isActive({ query: "   " }), false);
  assert.equal(view.isActive({ priority: "" }), false);
  assert.equal(view.isActive({ kevOnly: false }), false);
  assert.equal(view.isActive({ query: "nginx" }), true);
  assert.equal(view.isActive({ priority: "hoch" }), true);
  assert.equal(view.isActive({ kevOnly: true }), true);
  assert.equal(view.isActive(null), false);
});

test("returns an empty list for invalid input and keeps findings unchanged", () => {
  assert.deepEqual(ids(view.filter(null, { query: "x" })), []);
  assert.deepEqual(
    ids(view.filter([null, {}, ...findings], { query: "nginx" })),
    ["CVE-2026-0002"]
  );
  assert.equal(findings[0].filtered, undefined);
});
