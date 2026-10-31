window.CapybaraSbom = (() => {
  const MAX_FILE_SIZE = 5 * 1024 * 1024;
  const ecosystems = new Map([
    ["npm", "npm"],
    ["pypi", "PyPI"],
    ["maven", "Maven"],
    ["cargo", "crates.io"],
    ["rubygems", "RubyGems"],
    ["golang", "Go"],
    ["nuget", "NuGet"],
    ["hex", "Hex"],
    ["composer", "Packagist"],
    ["pub", "Pub"]
  ]);

  function parsePurl(value) {
    if (typeof value !== "string" || !value.startsWith("pkg:")) return null;
    const body = value.slice(4).split(/[?#]/, 1)[0];
    const slash = body.indexOf("/");
    if (slash < 1) return null;
    const type = body.slice(0, slash).toLowerCase();
    const remainder = body.slice(slash + 1);
    const versionIndex = remainder.lastIndexOf("@");
    const path = versionIndex >= 0 ? remainder.slice(0, versionIndex) : remainder;
    let version = versionIndex >= 0 ? remainder.slice(versionIndex + 1) : null;
    try {
      const decodedPath = decodeURIComponent(path);
      version = version ? decodeURIComponent(version) : null;
      const ecosystem = ecosystems.get(type);
      if (!ecosystem || !decodedPath || decodedPath.split("/").some((part) => !part)) {
        return null;
      }
      return {
        name: type === "npm" && decodedPath.startsWith("@")
          ? decodedPath
          : decodedPath.split("/").pop(),
        ecosystem,
        version: version || null
      };
    } catch {
      return null;
    }
  }

  function normalizePackage(name, version, purl, source) {
    const coordinate = parsePurl(purl);
    const resolvedVersion = version || coordinate?.version || null;
    return {
      name: coordinate?.name || (typeof name === "string" ? name.trim() : ""),
      version: resolvedVersion,
      ecosystem: coordinate?.ecosystem ?? null,
      osvPackage: coordinate && resolvedVersion
        ? { name: coordinate.name, ecosystem: coordinate.ecosystem }
        : null,
      source,
      confidence: "medium",
      versionStatus: "declared-unverified",
      note: "Angabe aus importiertem SBOM; nicht gegen ein installiertes Deployment verifiziert."
    };
  }

  function parse(content) {
    if (typeof content !== "string" || !content.trim()) {
      throw new Error("SBOM-Datei ist leer oder kein Text.");
    }
    if (content.length > MAX_FILE_SIZE) {
      throw new Error("SBOM-Datei überschreitet die Grenze von 5 MiB.");
    }
    let document;
    try {
      document = JSON.parse(content);
    } catch {
      throw new Error("SBOM muss gültiges JSON enthalten (CycloneDX oder SPDX).");
    }

    let format;
    let rawPackages;
    if (document?.bomFormat === "CycloneDX" && Array.isArray(document.components)) {
      format = `CycloneDX ${document.specVersion ?? "unbekannt"}`;
      rawPackages = document.components
        .filter((component) => component?.type !== "file" && component?.type !== "operating-system")
        .map((component) => ({
          name: component.name,
          version: component.version,
          purl: component.purl
        }));
    } else if (
      typeof document?.spdxVersion === "string" &&
      Array.isArray(document.packages)
    ) {
      format = `SPDX ${document.spdxVersion}`;
      rawPackages = document.packages.map((pkg) => ({
        name: pkg.name,
        version: pkg.versionInfo,
        purl: pkg.externalRefs?.find((ref) =>
          ref?.referenceType === "purl" ||
          (ref?.referenceCategory === "PACKAGE-MANAGER" && ref?.referenceLocator?.startsWith("pkg:"))
        )?.referenceLocator
      }));
    } else {
      throw new Error("Unbekanntes SBOM-Format. Unterstützt werden CycloneDX JSON und SPDX JSON.");
    }

    const components = rawPackages
      .filter((pkg) => typeof pkg?.name === "string" && pkg.name.trim())
      .map((pkg) => normalizePackage(pkg.name, pkg.version, pkg.purl, format));
    const unique = new Map();
    for (const component of components) {
      const key = `${component.ecosystem ?? "unknown"}:${component.name}@${component.version ?? "unknown"}`;
      if (!unique.has(key)) unique.set(key, component);
    }
    return { format, components: [...unique.values()] };
  }

  return { parse, parsePurl };
})();
