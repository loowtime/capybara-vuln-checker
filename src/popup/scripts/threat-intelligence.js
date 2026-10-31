window.CapybaraThreatIntel = (() => {
  const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
  const EPSS_URL = "https://api.first.org/data/v1/epss";
  const CACHE_KEY = "capybaraKevCache";
  const CACHE_MAX_AGE = 24 * 60 * 60 * 1000;

  function parseKevFeed(payload) {
    if (!payload || !Array.isArray(payload.vulnerabilities)) {
      throw new Error("CISA-KEV-Feed hat ein unerwartetes Format.");
    }
    const entries = new Map();
    for (const record of payload.vulnerabilities) {
      if (!/^CVE-\d{4}-\d+$/i.test(record?.cveID ?? "")) continue;
      entries.set(record.cveID.toUpperCase(), {
        dateAdded: record.dateAdded ?? null,
        dueDate: record.dueDate ?? null,
        knownRansomwareCampaignUse: record.knownRansomwareCampaignUse ?? null,
        vendorProject: record.vendorProject ?? null,
        product: record.product ?? null
      });
    }
    return entries;
  }

  async function getKevEntries(fetcher = fetch, storage = globalThis.browser?.storage?.local ?? null) {
    if (storage) {
      const stored = await storage.get(CACHE_KEY);
      const cached = stored?.[CACHE_KEY];
      if (
        cached?.fetchedAt &&
        Date.now() - cached.fetchedAt < CACHE_MAX_AGE &&
        Array.isArray(cached.records)
      ) {
        return new Map(cached.records);
      }
    }

    const response = await fetcher(KEV_URL);
    if (!response.ok) throw new Error(`CISA KEV antwortet mit HTTP ${response.status}.`);
    const entries = parseKevFeed(await response.json());
    if (storage) {
      await storage.set({
        [CACHE_KEY]: {
          fetchedAt: Date.now(),
          records: [...entries.entries()]
        }
      });
    }
    return entries;
  }

  async function fetchEpss(cveIds, fetcher = fetch) {
    const ids = [...new Set(cveIds.filter((id) => /^CVE-\d{4}-\d+$/i.test(id ?? "")))];
    const results = new Map();
    for (let offset = 0; offset < ids.length; offset += 100) {
      const batch = ids.slice(offset, offset + 100);
      if (!batch.length) continue;
      const url = new URL(EPSS_URL);
      url.searchParams.set("cve", batch.join(","));
      const response = await fetcher(url.toString());
      if (!response.ok) throw new Error(`FIRST EPSS antwortet mit HTTP ${response.status}.`);
      const payload = await response.json();
      if (!Array.isArray(payload?.data)) {
        throw new Error("FIRST-EPSS-Antwort hat ein unerwartetes Format.");
      }
      for (const record of payload.data) {
        const score = Number(record.epss);
        if (
          /^CVE-\d{4}-\d+$/i.test(record?.cve ?? "") &&
          Number.isFinite(score) &&
          score >= 0 &&
          score <= 1
        ) {
          results.set(record.cve.toUpperCase(), {
            score,
            percentile: Number.isFinite(Number(record.percentile))
              ? Number(record.percentile)
              : null,
            date: record.date ?? null
          });
        }
      }
    }
    return results;
  }

  async function enrichFindings(findings, options = {}) {
    const fetcher = options.fetch ?? fetch;
    const storage = options.storage ?? globalThis.browser?.storage?.local ?? null;
    const errors = [];
    const ids = [...new Set(findings
      .map((finding) => finding.id)
      .filter((id) => /^CVE-\d{4}-\d+$/i.test(id ?? "")))];
    let kev = new Map();
    let epss = new Map();
    try {
      kev = await getKevEntries(fetcher, storage);
    } catch (error) {
      errors.push(error.message);
    }
    try {
      epss = await fetchEpss(ids, fetcher);
    } catch (error) {
      errors.push(error.message);
    }

    const enriched = findings.map((finding) => {
      const id = finding.id?.toUpperCase();
      const kevRecord = id ? kev.get(id) : null;
      const epssRecord = id ? epss.get(id) : null;
      return {
        ...finding,
        kev: kevRecord ? { ...kevRecord, known: true } :
          kev.size ? { known: false } : finding.kev ?? null,
        epss: epssRecord ?? finding.epss ?? null,
        relatedSources: [
          ...(finding.relatedSources ?? []),
          ...(kevRecord ? ["CISA KEV"] : []),
          ...(epssRecord ? ["FIRST EPSS"] : [])
        ]
      };
    });
    return { findings: enriched, errors };
  }

  return { parseKevFeed, fetchEpss, enrichFindings };
})();
