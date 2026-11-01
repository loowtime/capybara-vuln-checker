window.CapybaraPosture = {
  assessResponse(headers, cookieFlags, isHttps) {
    const findings = [];
    const header = (name) => headers[name]?.join(", ") ?? "";
    const csp = header("content-security-policy");
    const cspReportOnly = header("content-security-policy-report-only");

    if (!isHttps) {
      findings.push({
        level: "warning",
        title: "HSTS nicht sinnvoll über HTTP prüfbar",
        detail: "Rufe die Website über HTTPS auf. Strict-Transport-Security wird von Browsern nur über sichere Verbindungen berücksichtigt."
      });
    } else {
      const hsts = header("strict-transport-security");
      if (!hsts) {
        findings.push({
          level: "warning",
          title: "HSTS fehlt",
          detail: "Strict-Transport-Security kann Browser auf HTTPS festlegen. Prüfe eine passende max-age und ob includeSubDomains für deine Subdomains geeignet ist."
        });
      } else {
        const directives = hsts.split(";")
          .map((part) => part.trim())
          .filter(Boolean);
        const directiveNames = directives.map((part) => part.split("=")[0].trim().toLowerCase());
        const maxAgeDirective = directives.find((part) => /^max-age\b/i.test(part));
        const maxAgeMatch = maxAgeDirective?.match(/^max-age\s*=\s*(\d+)\s*$/i);
        const maxAge = maxAgeMatch ? Number(maxAgeMatch[1]) : null;
        const hasIncludeSubDomains = directiveNames.includes("includesubdomains");
        const hasPreload = directiveNames.includes("preload");
        const duplicateDirectives = [...new Set(
          directiveNames.filter((name, index) => directiveNames.indexOf(name) !== index)
        )];

        if (duplicateDirectives.length) {
          findings.push({
            level: "warning",
            title: "HSTS enthält doppelte Direktiven",
            detail: `Doppelte HSTS-Direktive(n): ${duplicateDirectives.join(", ")}. Entferne Mehrdeutigkeiten und prüfe den tatsächlich ausgelieferten Header.`,
            technicalEvidence: { duplicateDirectives }
          });
        }
        if (maxAge === null) {
          findings.push({
            level: "warning",
            title: "HSTS max-age fehlt oder ist ungültig",
            detail: "Der HSTS-Header enthält keine eindeutig gültige numerische max-age. Browser können die Richtlinie dadurch ignorieren.",
            technicalEvidence: { observedHeader: hsts }
          });
        } else if (maxAge === 0) {
          findings.push({
            level: "warning",
            title: "HSTS wird deaktiviert",
            detail: "max-age=0 löscht eine zuvor gespeicherte HSTS-Richtlinie für diesen Host. Prüfe, ob das beabsichtigt ist.",
            technicalEvidence: { maxAge }
          });
        } else if (maxAge < 15_552_000) {
          findings.push({
            level: "warning",
            title: "HSTS max-age ist kürzer als sechs Monate",
            detail: "Prüfe, ob eine längere max-age passend ist. HSTS-Preload nur nach Prüfung aller Subdomains erwägen.",
            technicalEvidence: { maxAge }
          });
        }

        if (hasPreload && (maxAge === null || maxAge < 31_536_000 || !hasIncludeSubDomains)) {
          findings.push({
            level: "warning",
            title: "HSTS-Preload-Deklaration erfüllt nicht die üblichen Voraussetzungen",
            detail: "Der Header enthält preload, aber max-age beträgt nicht mindestens ein Jahr oder includeSubDomains fehlt. Prüfe die Preload-Voraussetzungen und ob alle Subdomains dauerhaft HTTPS unterstützen.",
            technicalEvidence: { maxAge, includeSubDomains: hasIncludeSubDomains }
          });
        }
      }
    }

    if (!csp) {
      findings.push({
        level: cspReportOnly ? "info" : "warning",
        title: cspReportOnly ? "CSP ist nur im Report-Only-Modus aktiv" : "Content Security Policy fehlt",
        detail: cspReportOnly
          ? "Content-Security-Policy-Report-Only erzwingt die Richtlinie nicht. Nach Prüfung der Reports kann eine CSP schrittweise durchgesetzt werden."
          : "Eine passende CSP kann die Auswirkungen bestimmter Injection-Fehler begrenzen. Zunächst im Report-Only-Modus testen und an die Anwendung anpassen."
      });
    } else {
      const directives = new Map();
      for (const part of csp.split(";")) {
        const [name, ...values] = part.trim().split(/\s+/);
        const directive = name?.toLowerCase();
        if (directive && !directives.has(directive)) {
          directives.set(directive, values.join(" "));
        }
      }
      if (!directives.has("default-src")) {
        findings.push({
          level: "info",
          title: "CSP ohne default-src",
          detail: "Prüfe, ob eine restriktive default-src als Fallback für nicht explizit gesetzte Ressourcentypen sinnvoll ist."
        });
      }
      if (directives.get("object-src")?.trim() !== "'none'") {
        findings.push({
          level: "info",
          title: "CSP beschränkt object-src nicht auf none",
          detail: "Wenn die Website keine Legacy-Plugins benötigt, object-src 'none' prüfen, um eingebettete Plugin-Inhalte zu begrenzen."
        });
      }
      if (!directives.has("base-uri")) {
        findings.push({
          level: "info",
          title: "CSP ohne base-uri",
          detail: "Prüfe base-uri 'self' oder 'none', um unerwartete Änderungen des Basis-URLs einzuschränken."
        });
      }
    }

    const cspPolicies = headers["content-security-policy"] ?? [];
    const duplicateDirectives = new Set();
    const scriptPolicyIssues = new Set();
    for (const policy of cspPolicies) {
      const policyDirectives = new Map();
      for (const part of policy.split(";")) {
        const [rawName, ...values] = part.trim().split(/\s+/);
        const name = rawName?.toLowerCase();
        if (!name) continue;
        if (policyDirectives.has(name)) {
          duplicateDirectives.add(name);
        } else {
          policyDirectives.set(name, values);
        }
      }

      const sources = policyDirectives.get("script-src") ??
        policyDirectives.get("default-src") ??
        [];
      const normalizedSources = sources.map((source) => source.toLowerCase());
      const hasNonceOrHash = normalizedSources.some((source) =>
        /^'(?:nonce-|sha256-|sha384-|sha512-)/.test(source)
      );
      if (normalizedSources.includes("'unsafe-eval'")) {
        scriptPolicyIssues.add("unsafe-eval");
      }
      if (normalizedSources.includes("'unsafe-inline'") && !hasNonceOrHash) {
        scriptPolicyIssues.add("unsafe-inline");
      }
      if (normalizedSources.some((source) =>
        ["*", "http:", "https:", "data:", "blob:"].includes(source)
      )) {
        scriptPolicyIssues.add("broad-source");
      }
    }

    if (duplicateDirectives.size) {
      findings.push({
        level: "warning",
        title: "CSP enthält doppelte Direktiven",
        detail: `Doppelte CSP-Direktive(n): ${[...duplicateDirectives].join(", ")}. Browser ignorieren spätere Vorkommen derselben Direktive; prüfe die tatsächlich wirksame Richtlinie.`,
        technicalEvidence: { duplicateDirectives: [...duplicateDirectives] }
      });
    }
    if (scriptPolicyIssues.has("unsafe-eval") || scriptPolicyIssues.has("unsafe-inline")) {
      const issues = [...scriptPolicyIssues]
        .filter((issue) => issue === "unsafe-eval" || issue === "unsafe-inline");
      findings.push({
        level: "warning",
        title: "CSP erlaubt unsichere Skript-Ausnahmen",
        detail: `Die wirksame Skript-Quellliste enthält ${issues.join(" und ")}. Entferne die Ausnahme, sofern die Anwendung sie nicht benötigt; bei Inline-Skripten Nonces oder Hashes prüfen.`,
        technicalEvidence: { scriptPolicyIssues: issues }
      });
    }
    if (scriptPolicyIssues.has("broad-source")) {
      findings.push({
        level: "warning",
        title: "CSP-Skriptquellen sind weit gefasst",
        detail: "script-src (oder dessen default-src-Fallback) erlaubt eine breite Quelle wie *, http:, https:, data: oder blob:. Begrenze Skripte auf erforderliche Origins und prüfe mögliche Auswirkungen vor Änderungen.",
        technicalEvidence: { scriptPolicyIssue: "broad-source" }
      });
    }

    if (!header("x-content-type-options").split(",").some((value) => value.trim().toLowerCase() === "nosniff")) {
      findings.push({
        level: "warning",
        title: "X-Content-Type-Options: nosniff fehlt",
        detail: "nosniff reduziert MIME-Type-Sniffing durch Browser."
      });
    }
    if (!header("x-frame-options") && !/frame-ancestors\b/i.test(csp)) {
      findings.push({
        level: "warning",
        title: "Clickjacking-Schutz nicht erkannt",
        detail: "Setze eine passende CSP frame-ancestors-Richtlinie oder X-Frame-Options, falls Einbettung nicht benötigt wird."
      });
    }
    const referrerPolicy = header("referrer-policy");
    if (!referrerPolicy) {
      findings.push({
        level: "info",
        title: "Referrer-Policy fehlt",
        detail: "Eine explizite Referrer-Policy, zum Beispiel strict-origin-when-cross-origin, macht die Referrer-Freigabe vorhersehbarer."
      });
    } else {
      const supportedPolicies = new Set([
        "no-referrer",
        "no-referrer-when-downgrade",
        "same-origin",
        "origin",
        "strict-origin",
        "origin-when-cross-origin",
        "strict-origin-when-cross-origin",
        "unsafe-url"
      ]);
      const effectivePolicy = referrerPolicy.split(",")
        .map((policy) => policy.trim().toLowerCase())
        .filter((policy) => supportedPolicies.has(policy))
        .at(-1);
      if (!effectivePolicy) {
        findings.push({
          level: "warning",
          title: "Referrer-Policy ist ungültig oder unbekannt",
          detail: "Im Header wurde keine unterstützte Referrer-Policy erkannt. Prüfe Schreibweise und tatsächlich wirksame Richtlinie.",
          technicalEvidence: { observedHeader: referrerPolicy }
        });
      } else if (["unsafe-url", "no-referrer-when-downgrade"].includes(effectivePolicy)) {
        findings.push({
          level: "warning",
          title: "Referrer-Policy gibt umfangreiche URL-Informationen frei",
          detail: `Die wirksame Richtlinie "${effectivePolicy}" kann bei sicheren Cross-Origin-Navigationen mehr Referrer-Informationen als nötig übertragen. Prüfe strict-origin-when-cross-origin oder eine restriktivere Policy.`,
          technicalEvidence: { effectivePolicy }
        });
      }
    }
    const permissionsPolicy = header("permissions-policy");
    if (!permissionsPolicy) {
      findings.push({
        level: "info",
        title: "Permissions-Policy fehlt",
        detail: "Prüfe, ob nicht benötigte Browser-Funktionen wie Kamera oder Mikrofon für diese Website eingeschränkt werden sollten."
      });
    } else {
      const sensitiveFeatures = new Set([
        "camera", "microphone", "geolocation", "usb", "serial",
        "bluetooth", "hid", "payment"
      ]);
      const unrestrictedFeatures = [];
      for (const directive of permissionsPolicy.split(",")) {
        const match = directive.trim().match(/^([a-z-]+)\s*=\s*(?:\(\s*\*\s*\)|\*)$/i);
        const feature = match?.[1]?.toLowerCase();
        if (feature && sensitiveFeatures.has(feature)) unrestrictedFeatures.push(feature);
      }
      if (unrestrictedFeatures.length) {
        findings.push({
          level: "warning",
          title: "Permissions-Policy gibt sensible Funktionen global frei",
          detail: `Für ${[...new Set(unrestrictedFeatures)].join(", ")} ist eine Wildcard-Freigabe konfiguriert. Beschränke die Allowlist auf erforderliche Origins und prüfe eingebettete Inhalte.`,
          technicalEvidence: { unrestrictedFeatures: [...new Set(unrestrictedFeatures)] }
        });
      }
    }
    if (!header("cross-origin-opener-policy")) {
      findings.push({
        level: "info",
        title: "Cross-Origin-Opener-Policy fehlt",
        detail: "Für Anwendungen mit Bedarf an Browser-Isolation kann COOP sinnvoll sein; prüfe mögliche Auswirkungen auf Pop-ups und Anmeldungen."
      });
    }
    if (!header("cross-origin-embedder-policy")) {
      findings.push({
        level: "info",
        title: "Cross-Origin-Embedder-Policy fehlt",
        detail: "COEP kann zusammen mit COOP die Isolation für Anwendungen mit Bedarf an SharedArrayBuffer stärken; vor Aktivierung Kompatibilität prüfen."
      });
    }

    if (
      header("access-control-allow-origin").trim() === "*" &&
      /^true$/i.test(header("access-control-allow-credentials").trim())
    ) {
      findings.push({
        level: "info",
        title: "CORS-Header-Kombination prüfen",
        detail: "Access-Control-Allow-Origin: * und Access-Control-Allow-Credentials: true passen nicht zusammen; Browser erlauben bei Wildcard-Origin keine credentialed Cross-Origin-Antworten."
      });
    }

    if (cookieFlags.count) {
      if (cookieFlags.invalidHostPrefix) {
        findings.push({
          level: "warning",
          title: "Ungültige __Host-Cookie-Attribute",
          detail: `${cookieFlags.invalidHostPrefix} Cookie(s) mit __Host- Präfix erfüllen nicht alle Anforderungen (Secure, Path=/ und kein Domain-Attribut). Cookie-Werte werden nicht gespeichert.`
        });
      }
      if (cookieFlags.invalidSecurePrefix) {
        findings.push({
          level: "warning",
          title: "Ungültige __Secure-Cookie-Attribute",
          detail: `${cookieFlags.invalidSecurePrefix} Cookie(s) mit __Secure- Präfix haben kein Secure-Attribut. Cookie-Werte werden nicht gespeichert.`
        });
      }
      if (isHttps && cookieFlags.missingSecure) {
        findings.push({
          level: "warning",
          title: "Cookies ohne Secure-Attribut",
          detail: `${cookieFlags.missingSecure} von ${cookieFlags.count} gesetzten Cookies haben kein Secure-Attribut. Für Sitzungscookies über HTTPS sollte es aktiviert sein.`
        });
      }
      if (cookieFlags.missingHttpOnly) {
        findings.push({
          level: "info",
          title: "Cookies ohne HttpOnly-Attribut",
          detail: `${cookieFlags.missingHttpOnly} von ${cookieFlags.count} gesetzten Cookies sind für JavaScript zugänglich. Für Sitzungscookies HttpOnly prüfen.`
        });
      }
      if (cookieFlags.missingSameSite) {
        findings.push({
          level: "info",
          title: "Cookies ohne explizites SameSite",
          detail: `${cookieFlags.missingSameSite} von ${cookieFlags.count} gesetzten Cookies setzen SameSite nicht explizit. Für Sitzungscookies Lax oder Strict prüfen; Cross-Site-Flows benötigen ggf. None; Secure.`
        });
      }
    }

    if (/\b(?:nginx|apache|microsoft-iis|caddy|lighttpd)\/\d/i.test(header("server"))) {
      findings.push({
        level: "info",
        title: "Detaillierter Server-Banner offengelegt",
        detail: "Die Antwort verrät Produkt und Version. Banner-Reduktion erschwert passive Fingerprints, ersetzt aber keine Updates."
      });
    }
    if (header("x-powered-by")) {
      findings.push({
        level: "info",
        title: "X-Powered-By-Header offengelegt",
        detail: `Der Response-Header verrät "${header("x-powered-by")}". Prüfe, ob die Technologieangabe für den Betrieb erforderlich ist; das Entfernen ersetzt keine Updates.`
      });
    }

    return findings;
  }
};
