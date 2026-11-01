window.CapybaraHistory = (() => {
  const MAX_SNAPSHOTS = 30;
  const keyForOrigin = (origin) => `capybaraHistory:${encodeURIComponent(origin)}`;

  function findingMap(findings) {
    const map = new Map();
    for (const finding of findings ?? []) {
      if (typeof finding === "string") {
        const separator = finding.lastIndexOf(":");
        map.set(separator < 0 ? finding : finding.slice(0, separator),
          separator < 0 ? null : finding.slice(separator + 1));
      } else if (finding && typeof finding.id === "string") {
        map.set(`${finding.id}:${finding.product ?? "unknown"}`, finding.productVersion ?? null);
      }
    }
    return map;
  }

  function diff(previous, current) {
    if (!previous) return { baseline: true, newFindings: [], resolvedFindings: [], versionChanges: [], headerChanges: [] };
    const priorFindings = findingMap(previous.findings);
    const currentFindings = findingMap(current.findings);
    const previousComponents = Array.isArray(previous.components) ? previous.components : [];
    const currentComponents = Array.isArray(current.components) ? current.components : [];
    const priorComponents = new Map(previousComponents.map((item) =>
      [item?.name, item?.version ?? null]
    ));
    const versionChanges = currentComponents.flatMap((item) => {
      if (!item || typeof item.name !== "string") return [];
      const priorVersion = priorComponents.get(item.name);
      return priorVersion !== undefined && priorVersion !== (item.version ?? null)
        ? [{ component: item.name, from: priorVersion, to: item.version ?? null }]
        : [];
    });
    for (const [key, version] of currentFindings) {
      const priorVersion = priorFindings.get(key);
      if (priorVersion !== undefined && priorVersion !== version) {
        versionChanges.push({ component: key, from: priorVersion, to: version });
      }
    }
    const priorHeaders = previous.headers ?? {};
    const currentHeaders = current.headers ?? {};
    const headerNames = new Set([...Object.keys(priorHeaders), ...Object.keys(currentHeaders)]);
    const headerChanges = [...headerNames].filter((name) =>
      JSON.stringify(priorHeaders[name] ?? null) !== JSON.stringify(currentHeaders[name] ?? null)
    );
    return {
      baseline: false,
      newFindings: [...currentFindings.keys()].filter((item) => !priorFindings.has(item)),
      resolvedFindings: [...priorFindings.keys()].filter((item) => !currentFindings.has(item)),
      versionChanges,
      headerChanges
    };
  }

  function normalizeOrigin(origin) {
    try {
      const url = new URL(origin);
      if (!["http:", "https:"].includes(url.protocol) || url.origin !== origin) return false;
      return true;
    } catch {
      return false;
    }
  }

  async function record(origin, data, storage = globalThis.browser?.storage?.local) {
    if (!storage || !normalizeOrigin(origin)) {
      throw new Error("Lokale Scan-Historie ist nicht verfügbar.");
    }
    if (!Array.isArray(data?.findings) || !Array.isArray(data?.components)) {
      throw new Error("Scan-Daten für die lokale Historie sind ungültig.");
    }
    const key = keyForOrigin(origin);
    const stored = await storage.get(key);
    const snapshots = Array.isArray(stored?.[key])
      ? stored[key].filter((snapshot) =>
        snapshot && Array.isArray(snapshot.findings) && Array.isArray(snapshot.components)
      )
      : [];
    const findings = data.findings
      .filter((item) => item && typeof item === "object" && typeof item.id === "string")
      .map((item) => ({
        id: item.id,
        product: typeof item.product === "string" ? item.product : "unknown",
        productVersion: typeof item.productVersion === "string" ? item.productVersion : null
      }));
    const components = data.components
      .filter((item) => item && typeof item === "object" && typeof item.name === "string")
      .map((item) => ({
        name: item.name,
        version: typeof item.version === "string" ? item.version : null
      }));
    const current = {
      scannedAt: data.scannedAt ?? new Date().toISOString(),
      findings,
      components,
      headers: data.headers && typeof data.headers === "object" && !Array.isArray(data.headers)
        ? data.headers
        : {}
    };
    const change = diff(snapshots.at(-1), current);
    snapshots.push(current);
    const retained = snapshots.slice(-MAX_SNAPSHOTS);
    await storage.set({ [key]: retained });
    return { ...change, scannedAt: current.scannedAt, previousScanAt: snapshots.at(-2)?.scannedAt ?? null };
  }

  async function read(origin, storage = globalThis.browser?.storage?.local) {
    if (!storage || !normalizeOrigin(origin)) return [];
    const key = keyForOrigin(origin);
    const stored = await storage.get(key);
    return Array.isArray(stored?.[key])
      ? stored[key].filter((snapshot) =>
        snapshot && Array.isArray(snapshot.findings) && Array.isArray(snapshot.components)
      )
      : [];
  }

  async function clear(origin, storage = globalThis.browser?.storage?.local) {
    if (!storage || !normalizeOrigin(origin)) {
      throw new Error("Lokale Scan-Historie ist nicht verfügbar.");
    }
    await storage.remove(keyForOrigin(origin));
  }

  return { diff, record, read, clear };
})();
