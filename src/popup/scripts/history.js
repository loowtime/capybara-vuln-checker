window.CapybaraHistory = (() => {
  const MAX_SNAPSHOTS = 30;
  const keyForOrigin = (origin) => `capybaraHistory:${encodeURIComponent(origin)}`;

  function diff(previous, current) {
    if (!previous) return { baseline: true, newFindings: [], resolvedFindings: [], versionChanges: [], headerChanges: [] };
    const priorFindings = new Set(previous.findings);
    const currentFindings = new Set(current.findings);
    const priorComponents = new Map(previous.components.map((item) => [item.name, item.version]));
    const versionChanges = current.components.flatMap((item) => {
      const priorVersion = priorComponents.get(item.name);
      return priorVersion !== undefined && priorVersion !== item.version
        ? [{ component: item.name, from: priorVersion, to: item.version }]
        : [];
    });
    const priorHeaders = previous.headers ?? {};
    const headerNames = new Set([...Object.keys(priorHeaders), ...Object.keys(current.headers ?? {})]);
    const headerChanges = [...headerNames].filter((name) =>
      JSON.stringify(priorHeaders[name] ?? null) !== JSON.stringify(current.headers?.[name] ?? null)
    );
    return {
      baseline: false,
      newFindings: [...currentFindings].filter((item) => !priorFindings.has(item)),
      resolvedFindings: [...priorFindings].filter((item) => !currentFindings.has(item)),
      versionChanges,
      headerChanges
    };
  }

  async function record(origin, data, storage = globalThis.browser?.storage?.local) {
    if (!storage || !/^https?:\/\//.test(origin)) {
      throw new Error("Lokale Scan-Historie ist nicht verfügbar.");
    }
    const key = keyForOrigin(origin);
    const stored = await storage.get(key);
    const snapshots = Array.isArray(stored?.[key]) ? stored[key] : [];
    const current = {
      scannedAt: data.scannedAt ?? new Date().toISOString(),
      findings: data.findings.map((item) => `${item.id}:${item.product}:${item.productVersion}`),
      components: data.components.map((item) => ({ name: item.name, version: item.version ?? null })),
      headers: data.headers
    };
    const change = diff(snapshots.at(-1), current);
    snapshots.push(current);
    await storage.set({ [key]: snapshots.slice(-MAX_SNAPSHOTS) });
    return { ...change, scannedAt: current.scannedAt, previousScanAt: snapshots.at(-2)?.scannedAt ?? null };
  }

  async function read(origin, storage = globalThis.browser?.storage?.local) {
    if (!storage) return [];
    const key = keyForOrigin(origin);
    const stored = await storage.get(key);
    return Array.isArray(stored?.[key]) ? stored[key] : [];
  }

  return { diff, record, read };
})();
