function captureServerHeader(tabId, origin) {
  return new Promise((resolve, reject) => {
    let timer;
    let listening = false;
    let watchingRequestErrors = false;
    let watchingTab = false;
    const target = new URL(origin);

    const cleanup = () => {
      clearTimeout(timer);
      if (listening) {
        browser.webRequest.onHeadersReceived.removeListener(onHeadersReceived);
        listening = false;
      }
      if (watchingRequestErrors) {
        browser.webRequest.onErrorOccurred.removeListener(onRequestError);
        watchingRequestErrors = false;
      }
      if (watchingTab) {
        browser.tabs.onUpdated.removeListener(onTabUpdated);
        watchingTab = false;
      }
    };

    const finish = (error, result) => {
      cleanup();
      if (error) reject(error);
      else resolve(result);
    };

    const onHeadersReceived = (details) => {
      const requestUrl = new URL(details.url);
      if (
        details.tabId !== tabId ||
        details.frameId !== 0 ||
        requestUrl.hostname !== target.hostname ||
        (details.statusCode >= 300 && details.statusCode < 400)
      ) {
        return;
      }
      const isSecureResponse = requestUrl.protocol === "https:";

      const observedHeaders = new Map([
        ["server", []],
        ["x-powered-by", []],
        ["x-aspnet-version", []],
        ["x-aspnetmvc-version", []],
        ["x-generator", []],
        ["strict-transport-security", []],
        ["content-security-policy", []],
        ["content-security-policy-report-only", []],
        ["x-content-type-options", []],
        ["x-frame-options", []],
        ["referrer-policy", []],
        ["permissions-policy", []],
        ["cross-origin-opener-policy", []],
        ["cross-origin-embedder-policy", []],
        ["cross-origin-resource-policy", []],
        ["access-control-allow-origin", []],
        ["access-control-allow-credentials", []],
        ["via", []],
        ["x-varnish", []],
        ["x-served-by", []],
        ["x-cache", []],
        ["cf-ray", []],
        ["x-amz-cf-id", []]
      ]);
      const cookieFlags = {
        count: 0,
        missingSecure: 0,
        missingHttpOnly: 0,
        missingSameSite: 0,
        invalidHostPrefix: 0,
        invalidSecurePrefix: 0
      };
      for (const header of details.responseHeaders ?? []) {
        if (header.name.toLowerCase() === "set-cookie" && header.value) {
          const parts = header.value.split(";");
          const cookieName = parts[0].split("=")[0].trim();
          const attributes = parts.slice(1);
          const attributeNames = new Set(
            attributes.map((attribute) => attribute.trim().split("=")[0].toLowerCase())
          );
          const pathIsRoot = attributes.some((attribute) => /^path=\/$/i.test(attribute.trim()));
          const hasDomain = attributeNames.has("domain");
          cookieFlags.count += 1;
          if (!attributeNames.has("secure")) cookieFlags.missingSecure += 1;
          if (!attributeNames.has("httponly")) cookieFlags.missingHttpOnly += 1;
          if (!attributes.some((attribute) => /^samesite=/i.test(attribute.trim()))) {
            cookieFlags.missingSameSite += 1;
          }
          if (
            cookieName.startsWith("__Secure-") &&
            (!isSecureResponse || !attributeNames.has("secure"))
          ) {
            cookieFlags.invalidSecurePrefix += 1;
          }
          if (
            cookieName.startsWith("__Host-") &&
            (!isSecureResponse || !attributeNames.has("secure") || hasDomain || !pathIsRoot)
          ) {
            cookieFlags.invalidHostPrefix += 1;
          }
          continue;
        }
        const values = observedHeaders.get(header.name.toLowerCase());
        if (values && header.value) values.push(header.value);
      }

      finish(null, {
        headers: Object.fromEntries(
          [...observedHeaders].filter(([, values]) => values.length)
        ),
        cookieFlags,
        statusCode: details.statusCode
      });
    };

    const onTabUpdated = (updatedTabId, changeInfo) => {
      if (updatedTabId !== tabId || !changeInfo.url) return;
      try {
        if (new URL(changeInfo.url).hostname !== target.hostname) {
          finish(
            new Error("Die Website hat auf einen anderen Host umgeleitet. Öffne das Ziel und starte die Prüfung erneut.")
          );
        }
      } catch {
        finish(new Error("Firefox konnte die Website nach dem Neuladen nicht öffnen."));
      }
    };

    const onRequestError = (details) => {
      if (details.tabId === tabId && details.frameId === 0) {
        finish(new Error(`Firefox konnte die Website nicht laden (${details.error}).`));
      }
    };

    try {
      browser.webRequest.onHeadersReceived.addListener(
        onHeadersReceived,
        {
          urls: [`http://${target.hostname}/*`, `https://${target.hostname}/*`],
          tabId,
          types: ["main_frame"]
        },
        ["responseHeaders"]
      );
      listening = true;
      browser.webRequest.onErrorOccurred.addListener(onRequestError, {
        urls: [`http://${target.hostname}/*`, `https://${target.hostname}/*`],
        tabId,
        types: ["main_frame"]
      });
      watchingRequestErrors = true;
      browser.tabs.onUpdated.addListener(onTabUpdated);
      watchingTab = true;
      timer = setTimeout(
        () => finish(new Error("Nach dem Neuladen wurde kein Server-Header empfangen.")),
        15000
      );
      browser.tabs.reload(tabId).catch((error) => finish(error));
    } catch (error) {
      finish(error);
    }
  });
}

browser.runtime.onMessage.addListener(async (message, sender) => {
  if (message?.type !== "scan-server-header") return undefined;
  if (sender.id !== browser.runtime.id || !Number.isInteger(message.tabId)) {
    throw new Error("Ungültige Anfrage für die Server-Prüfung.");
  }

  const tab = await browser.tabs.get(message.tabId);
  const currentUrl = new URL(tab.url);
  if (!["http:", "https:"].includes(currentUrl.protocol) || currentUrl.origin !== message.origin) {
    throw new Error("Die aktive Website hat sich geändert. Bitte starte die Prüfung erneut.");
  }

  return captureServerHeader(tab.id, currentUrl.origin);
});
