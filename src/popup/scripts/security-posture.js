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
      const maxAge = Number(hsts.match(/(?:^|;)\s*max-age=(\d+)/i)?.[1] ?? 0);
      if (!hsts) {
        findings.push({
          level: "warning",
          title: "HSTS fehlt",
          detail: "Strict-Transport-Security kann Browser auf HTTPS festlegen. Prüfe eine passende max-age und ob includeSubDomains für deine Subdomains geeignet ist."
        });
      } else if (maxAge < 15_552_000) {
        findings.push({
          level: "warning",
          title: "HSTS max-age ist kürzer als sechs Monate",
          detail: "Prüfe, ob eine längere max-age passend ist. HSTS-Preload nur nach Prüfung aller Subdomains erwägen."
        });
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
      const directives = new Map(csp.split(";").map((part) => {
        const [name, ...values] = part.trim().split(/\s+/);
        return [name?.toLowerCase(), values.join(" ")];
      }));
      if (!directives.has("default-src")) {
        findings.push({
          level: "info",
          title: "CSP ohne default-src",
          detail: "Prüfe, ob eine restriktive default-src als Fallback für nicht explizit gesetzte Ressourcentypen sinnvoll ist."
        });
      }
      if (/'unsafe-inline'|'unsafe-eval'/.test(directives.get("script-src") ?? "")) {
        findings.push({
          level: "warning",
          title: "CSP erlaubt unsichere Skript-Ausnahmen",
          detail: "script-src enthält unsafe-inline oder unsafe-eval. Nonces/Hashes und das Entfernen von Inline-Skripten können die Richtlinie stärken."
        });
      }
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
    if (!header("referrer-policy")) {
      findings.push({
        level: "info",
        title: "Referrer-Policy fehlt",
        detail: "Eine explizite Referrer-Policy, zum Beispiel strict-origin-when-cross-origin, macht die Referrer-Freigabe vorhersehbarer."
      });
    }
    if (!header("permissions-policy")) {
      findings.push({
        level: "info",
        title: "Permissions-Policy fehlt",
        detail: "Prüfe, ob nicht benötigte Browser-Funktionen wie Kamera oder Mikrofon für diese Website eingeschränkt werden sollten."
      });
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
