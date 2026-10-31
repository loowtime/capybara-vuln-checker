/* Confidence scoring for CVE candidates.
 * This estimates match quality from available detection evidence.
 * It does NOT prove that the deployed component is vulnerable.
 */
window.CapybaraConfidence = {
  assess(finding) {
    let score = 50;
    const reasons = [];
    const detection = finding.confidence ?? "unknown";
    const versionStatus = finding.technicalEvidence?.versionStatus ?? "unknown";
    const version = finding.productVersion ?? finding.technicalEvidence?.detectedVersion;

    if (detection === "high") {
      score += 20;
      reasons.push("High-confidence component detection (+20).");
    } else if (detection === "medium") {
      score += 10;
      reasons.push("Medium-confidence component detection (+10).");
    } else if (detection === "low") {
      score -= 15;
      reasons.push("Low-confidence component detection (-15).");
    } else {
      score -= 10;
      reasons.push("Detection confidence is unknown (-10).");
    }

    if (versionStatus === "verified") {
      score += 20;
      reasons.push("Version is marked as verified (+20).");
    } else if (versionStatus === "observed-unverified") {
      score -= 5;
      reasons.push("Observed version is not independently verified (-5).");
    } else {
      score -= 15;
      reasons.push("No verified version status is available (-15).");
    }

    if (version) {
      score += 10;
      reasons.push("A product version was detected (+10).");
    } else {
      score -= 10;
      reasons.push("No product version was detected (-10).");
    }

    if (finding.cpe || finding.technicalEvidence?.cpe) {
      score += 5;
      reasons.push("A CPE product mapping is available (+5).");
    } else if (finding.osvPackage || finding.technicalEvidence?.package) {
      score += 5;
      reasons.push("A package coordinate is available (+5).");
    } else {
      score -= 5;
      reasons.push("No structured product/package identifier is available (-5).");
    }

    score = Math.max(0, Math.min(100, score));
    const level = score >= 80 ? "high" : score >= 55 ? "medium" : "low";
    return {
      score,
      level,
      reasons,
      label: level === "high" ? "High match confidence" :
        level === "medium" ? "Medium match confidence" : "Low match confidence"
    };
  },

  assessAll(findings) {
    return findings.map((finding) => ({
      ...finding,
      matchConfidence: this.assess(finding)
    }));
  }
};