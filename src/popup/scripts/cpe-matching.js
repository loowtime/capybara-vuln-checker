/* CPE 2.3 validation and match-quality assessment.
 * This validates the locally generated identifier before an NVD lookup.
 * It does not establish that a detected component is actually vulnerable.
 */
window.CapybaraCpeMatcher = (() => {
  function splitCpe(value) {
    if (typeof value !== "string" || !value.startsWith("cpe:2.3:")) return null;
    const fields = [];
    let current = "";
    let escaped = false;

    for (const char of value.slice(8)) {
      if (escaped) {
        current += `\\${char}`;
        escaped = false;
      } else if (char === "\\") {
        escaped = true;
      } else if (char === ":") {
        fields.push(current);
        current = "";
      } else {
        current += char;
      }
    }
    if (escaped) current += "\\\\";
    fields.push(current);
    return fields.length === 11 ? fields : null;
  }

  function assess(component) {
    const fields = splitCpe(component?.cpe);
    const reasons = [];
    if (!fields) {
      return {
        valid: false, score: 0, level: "invalid",
        vendor: null, product: null, version: null,
        reasons: ["CPE 2.3 format is invalid or incomplete."]
      };
    }

    const [part, vendor, product, version, update, edition, language,
      swEdition, targetSw, targetHw, other] = fields;
    let score = 40;

    if (!["a", "o", "h", "*", "-"].includes(part)) {
      return {
        valid: false, score: 0, level: "invalid",
        vendor, product, version,
        reasons: ["CPE part must be a, o, h, * or -."]
      };
    }
    if (!vendor || !product || vendor === "*" || product === "*") {
      return {
        valid: false, score: 0, level: "invalid",
        vendor, product, version,
        reasons: ["CPE must identify a specific vendor and product."]
      };
    }
    score += 20;
    reasons.push("Specific vendor and product are present.");

    if (!version || version === "*" || version === "-") {
      score -= 20;
      reasons.push("CPE does not contain a specific version.");
    } else if (String(component.version ?? "") !== version) {
      return {
        valid: false, score: 0, level: "invalid",
        vendor, product, version,
        reasons: [`CPE version (${version}) does not match detected version (${component.version ?? "missing"}).`]
      };
    } else {
      score += 30;
      reasons.push("CPE version matches the detected version.");
    }

    if (part === "a") {
      score += 10;
      reasons.push("CPE part identifies an application.");
    } else {
      reasons.push(`CPE part is "${part}".`);
    }

    const valid = score >= 60;
    return {
      valid,
      score: Math.max(0, Math.min(100, score)),
      level: score >= 85 ? "high" : score >= 60 ? "medium" : "low",
      vendor,
      product,
      version,
      reasons
    };
  }

  function assessAll(components) {
    return components.map((component) => ({
      ...component,
      cpeAssessment: assess(component)
    }));
  }

  return { assess, assessAll };
})();