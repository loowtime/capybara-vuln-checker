const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");

const context = { window: {} };
vm.runInNewContext(fs.readFileSync("src/popup/scripts/cpe-matching.js", "utf8"), context);
const matcher = context.window.CapybaraCpeMatcher;

test("accepts a complete CPE with matching detected version", () => {
  const result = matcher.assess({
    version: "1.24.0",
    cpe: "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"
  });
  assert.equal(result.valid, true);
  assert.equal(result.level, "high");
});

test("rejects CPE when its version differs from the detected version", () => {
  const result = matcher.assess({
    version: "1.24.0",
    cpe: "cpe:2.3:a:f5:nginx:1.22.0:*:*:*:*:*:*:*"
  });
  assert.equal(result.valid, false);
  assert.match(result.reasons[0], /does not match/);
});

test("rejects incomplete CPE identifiers", () => {
  assert.equal(matcher.assess({ version: "1.0", cpe: "cpe:2.3:a:vendor:product" }).valid, false);
});

test("does not mutate component data when assessing a list", () => {
  const input = [{ version: "1.24.0", cpe: "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*" }];
  const output = matcher.assessAll(input);
  assert.equal(input[0].cpeAssessment, undefined);
  assert.equal(output[0].cpeAssessment.valid, true);
});
