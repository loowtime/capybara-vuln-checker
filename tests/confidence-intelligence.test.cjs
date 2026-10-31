const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const context = { window: {} };
vm.runInNewContext(
  fs.readFileSync("src/popup/scripts/confidence-intelligence.js", "utf8"),
  context
);
const confidence = context.window.CapybaraConfidence;

test("scores a verified, high-confidence version match highly", () => {
  const result = confidence.assess({
    confidence: "high",
    productVersion: "2.4.1",
    cpe: "cpe:2.3:a:vendor:product:2.4.1",
    technicalEvidence: { versionStatus: "verified" }
  });
  assert.equal(result.score, 100);
  assert.equal(result.level, "high");
});

test("reduces confidence when version and detection evidence are weak", () => {
  const result = confidence.assess({
    confidence: "low",
    technicalEvidence: { versionStatus: "unknown" }
  });
  assert.equal(result.level, "low");
  assert.ok(result.score < 40);
});

test("assesses all findings without mutating the originals", () => {
  const original = [{ id: "CVE-2025-0001", confidence: "medium" }];
  const assessed = confidence.assessAll(original);
  assert.ok(assessed[0].matchConfidence);
  assert.equal(original[0].matchConfidence, undefined);
});
