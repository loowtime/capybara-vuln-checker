globalThis.CapybaraTls = (() => {
  const STATES = new Set(["secure", "weak", "insecure", "broken"]);

  function text(value, limit = 512) {
    return typeof value === "string" && value.trim()
      ? value.trim().slice(0, limit)
      : null;
  }

  function timestamp(value) {
    return Number.isFinite(value) && value >= 0 && value <= 8.64e15
      ? new Date(value).toISOString()
      : null;
  }

  function sanitizeSecurityInfo(info) {
    if (!info || typeof info !== "object" || Array.isArray(info)) return null;
    const certificate = Array.isArray(info.certificates)
      ? info.certificates[0]
      : null;
    const validity = certificate?.validity &&
      Number.isFinite(certificate.validity.start) &&
      Number.isFinite(certificate.validity.end)
      ? {
        start: timestamp(certificate.validity.start),
        end: timestamp(certificate.validity.end)
      }
      : null;
    const fingerprint = text(certificate?.fingerprint?.sha256, 256);
    return {
      state: STATES.has(info.state) ? info.state : "unknown",
      protocolVersion: text(info.protocolVersion, 32),
      cipherSuite: text(info.cipherSuite, 160),
      keaGroupName: text(info.keaGroupName, 80),
      signatureSchemeName: text(info.signatureSchemeName, 100),
      weaknessReasons: text(info.weaknessReasons, 256),
      certificateTransparencyStatus: text(info.certificateTransparencyStatus, 64),
      hsts: typeof info.hsts === "boolean" ? info.hsts : null,
      isDomainMismatch: typeof info.isDomainMismatch === "boolean"
        ? info.isDomainMismatch
        : null,
      isNotValidAtThisTime: typeof info.isNotValidAtThisTime === "boolean"
        ? info.isNotValidAtThisTime
        : null,
      isUntrusted: typeof info.isUntrusted === "boolean" ? info.isUntrusted : null,
      usedEch: typeof info.usedEch === "boolean" ? info.usedEch : null,
      certificate: certificate && typeof certificate === "object"
        ? {
          subject: text(certificate.subject),
          issuer: text(certificate.issuer),
          serialNumber: text(certificate.serialNumber, 256),
          fingerprintSha256: fingerprint,
          isBuiltInRoot: typeof certificate.isBuiltInRoot === "boolean"
            ? certificate.isBuiltInRoot
            : null,
          validity
        }
        : null
    };
  }

  function assess(info, error = null) {
    if (error) {
      return {
        available: false,
        label: "TLS-Daten nicht verfügbar",
        reason: String(error),
        issues: [],
        metadata: null
      };
    }
    if (!info || typeof info !== "object" || Array.isArray(info)) {
      return {
        available: false,
        label: "TLS-Prüfung nicht durchgeführt",
        reason: "Die TLS-Berechtigung wurde nicht erteilt oder die Seite verwendet kein HTTPS.",
        issues: [],
        metadata: null
      };
    }

    const metadata = sanitizeSecurityInfo(info);
    const issues = [];
    if (metadata.state === "insecure") {
      issues.push({
        level: "warning",
        title: "Verbindung ist nicht verschlüsselt",
        detail: "Der Hauptseitenaufruf wurde ohne TLS übertragen.",
        evidence: { state: metadata.state }
      });
    } else if (metadata.state === "weak") {
      issues.push({
        level: "warning",
        title: "Firefox bewertet die TLS-Verbindung als schwach",
        detail: metadata.weaknessReasons
          ? `Firefox meldet: ${metadata.weaknessReasons}.`
          : "Firefox kennzeichnet die ausgehandelte TLS-Verbindung als schwach.",
        evidence: {
          state: metadata.state,
          weaknessReasons: metadata.weaknessReasons,
          cipherSuite: metadata.cipherSuite
        }
      });
    }
    if (["TLSv1", "TLSv1.1"].includes(metadata.protocolVersion)) {
      issues.push({
        level: "warning",
        title: "Veraltete TLS-Protokollversion",
        detail: `${metadata.protocolVersion} ist veraltet; TLS 1.2 oder neuer sollte unterstützt werden.`,
        evidence: { protocolVersion: metadata.protocolVersion }
      });
    }
    if (metadata.isDomainMismatch === true) {
      issues.push({
        level: "warning",
        title: "Zertifikat passt nicht zum Hostnamen",
        detail: "Firefox meldet eine Abweichung zwischen Zertifikatsnamen und aufgerufenem Host.",
        evidence: { isDomainMismatch: true }
      });
    }
    if (metadata.isNotValidAtThisTime === true) {
      issues.push({
        level: "warning",
        title: "Zertifikat ist aktuell nicht gültig",
        detail: "Firefox meldet, dass das Zertifikat außerhalb seines Gültigkeitszeitraums liegt.",
        evidence: { isNotValidAtThisTime: true, validity: metadata.certificate?.validity ?? null }
      });
    }
    if (metadata.isUntrusted === true) {
      issues.push({
        level: "warning",
        title: "Zertifikatskette ist nicht vertrauenswürdig",
        detail: "Firefox konnte keine vertrauenswürdige Zertifikatskette bestätigen.",
        evidence: { isUntrusted: true }
      });
    }
    return {
      available: true,
      label: metadata.state === "secure"
        ? "TLS-Verbindung von Firefox als sicher bewertet"
        : metadata.state === "weak"
          ? "TLS-Verbindung von Firefox als schwach bewertet"
          : metadata.state === "insecure"
            ? "Keine TLS-Verschlüsselung"
            : "TLS-Status unbekannt",
      reason: null,
      issues,
      metadata
    };
  }

  return { sanitizeSecurityInfo, assess };
})();
