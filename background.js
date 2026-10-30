function captureServerHeader(tabId, origin) {
  return new Promise((resolve, reject) => {
    let timer;
    let listening = false;

    const cleanup = () => {
      clearTimeout(timer);
      if (listening) {
        browser.webRequest.onHeadersReceived.removeListener(onHeadersReceived);
        listening = false;
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
        requestUrl.origin !== origin ||
        (details.statusCode >= 300 && details.statusCode < 400)
      ) {
        return;
      }

      const serverHeader = details.responseHeaders?.find(
        (header) => header.name.toLowerCase() === "server"
      )?.value ?? null;
      finish(null, { serverHeader, statusCode: details.statusCode });
    };

    try {
      browser.webRequest.onHeadersReceived.addListener(
        onHeadersReceived,
        {
          urls: [`${new URL(origin).protocol}//${new URL(origin).hostname}/*`],
          tabId,
          types: ["main_frame"]
        },
        ["responseHeaders"]
      );
      listening = true;
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
