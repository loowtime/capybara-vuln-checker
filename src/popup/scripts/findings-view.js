/* Local, non-persistent filtering for the rendered CVE candidate list.
 * Filtering only changes which already loaded findings are displayed.
 * It does not alter evidence, priorities, reports or stored snapshots.
 */
window.CapybaraFindingsView = (() => {
  function normalizeCriteria(criteria) {
    const input = criteria && typeof criteria === "object" && !Array.isArray(criteria)
      ? criteria
      : {};
    return {
      query: typeof input.query === "string" ? input.query.trim().toLowerCase() : "",
      priority: typeof input.priority === "string" ? input.priority : "",
      kevOnly: input.kevOnly === true
    };
  }

  function searchableValues(finding) {
    if (!finding || typeof finding !== "object" || Array.isArray(finding)) return [];
    return [
      finding.id,
      finding.product,
      finding.productVersion,
      finding.source,
      finding.description,
      finding.risk?.level,
      ...(Array.isArray(finding.relatedIds) ? finding.relatedIds : [])
    ].filter((value) => typeof value === "string");
  }

  function filter(findings, criteria) {
    if (!Array.isArray(findings)) return [];
    const { query, priority, kevOnly } = normalizeCriteria(criteria);
    return findings.filter((finding) => {
      if (!finding || typeof finding !== "object" || Array.isArray(finding)) return false;
      if (priority && finding.risk?.level !== priority) return false;
      if (kevOnly && finding.kev?.known !== true) return false;
      if (!query) return true;
      return searchableValues(finding).some((value) => value.toLowerCase().includes(query));
    });
  }

  function isActive(criteria) {
    const normalized = normalizeCriteria(criteria);
    return Boolean(normalized.query || normalized.priority || normalized.kevOnly);
  }

  return { filter, isActive };
})();
