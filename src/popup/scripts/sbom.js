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
    const declaredVersion = typeof version === "string" && version.trim()
      ? version.trim()
      : null;
    const versionConflict = Boolean(
      declaredVersion && coordinate?.version && declaredVersion !== coordinate.version
    );
    const resolvedVersion = versionConflict
      ? null
      : declaredVersion || coordinate?.version || null;
    return {
      name: coordinate?.name || (typeof name === "string" ? name.trim() : ""),
      version: resolvedVersion,
      ecosystem: coordinate?.ecosystem ?? null,
      osvPackage: coordinate && resolvedVersion
        ? { name: coordinate.name, ecosystem: coordinate.ecosystem }
        : null,
      source,
      confidence: versionConflict ? "low" : "medium",
      versionStatus: versionConflict ? "ambiguous" : "declared-unverified",
      note: versionConflict
        ? "Versionsangaben im SBOM und Package URL widersprechen sich; kein OSV-Abgleich bis zur manuellen Klärung."
        : "Angabe aus importiertem SBOM; nicht gegen ein installiertes Deployment verifiziert."
    };
  }

  function collectCycloneComponents(components, output = [], depth = 0) {
    if (!Array.isArray(components) || depth > 20) return output;
    for (const component of components) {
      if (!component || typeof component !== "object" || Array.isArray(component)) continue;
      if (
        typeof component.name === "string" &&
        component.type !== "file" &&
        component.type !== "operating-system"
      ) {
        output.push({
          name: component.name,
          version: component.version,
          purl: component.purl
        });
      }
      collectCycloneComponents(component.components, output, depth + 1);
    }
    return output;
  }

  function parse(content) {
    if (typeof content !== "string" || !content.trim()) {
      throw new Error("SBOM-Datei ist leer oder kein Text.");
    }
    if (new TextEncoder().encode(content).byteLength > MAX_FILE_SIZE) {
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
      rawPackages = collectCycloneComponents(document.components);
    } else if (
      typeof document?.spdxVersion === "string" &&
      Array.isArray(document.packages)
    ) {
      format = `SPDX ${document.spdxVersion}`;
      rawPackages = document.packages
        .filter((pkg) => pkg && typeof pkg === "object" && !Array.isArray(pkg))
        .map((pkg) => ({
          name: pkg.name,
          version: pkg.versionInfo,
          purl: (Array.isArray(pkg.externalRefs) ? pkg.externalRefs : []).find((ref) =>
          ref?.referenceType === "purl" ||
          (
            ref?.referenceCategory === "PACKAGE-MANAGER" &&
            typeof ref?.referenceLocator === "string" &&
            ref.referenceLocator.startsWith("pkg:")
          )
        )?.referenceLocator
        }));
    } else {
      throw new Error("Unbekanntes SBOM-Format. Unterstützt werden CycloneDX JSON und SPDX JSON.");
    }

    if (rawPackages.length > 20_000) {
      throw new Error("SBOM enthält mehr als 20.000 Komponenten.");
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

  return { parse, parsePurl, normalizePackage };
})();
