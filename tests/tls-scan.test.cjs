const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

const root = path.join(__dirname, "..");
const tlsSource = fs.readFileSync(
  path.join(root, "src/popup/scripts/tls-analysis.js"),
  "utf8"
);

function loadTls() {
  const context = vm.createContext({ URL });
  vm.runInContext(tlsSource, context, { filename: "tls-analysis.js" });
  return context.CapybaraTls;
}

function event() {
  return {
    listener: null,
    addListener(listener, filter, extraInfoSpec) {
      this.listener = listener;
      this.filter = filter;
      this.extraInfoSpec = extraInfoSpec;
    },
    removeListener(listener) {
      if (this.listener === listener) this.listener = null;
    }
  };
}

function loadBackground({ securityInfo, tlsPermission = true } = {}) {
  const onMessage = event();
  const onHeadersReceived = event();
  const onErrorOccurred = event();
  const onUpdated = event();
  let insideHeadersListener = false;
  let securityInfoCalls = 0;
  const details = {
    requestId: "request-1",
    tabId: 7,
    frameId: 0,
    url: "https://example.test/",
    statusCode: 200,
    responseHeaders: [
      { name: "Server", value: "nginx/1.26.0" },
      { name: "Strict-Transport-Security", value: "max-age=31536000" },
      { name: "Set-Cookie", value: "session=secret; Secure; HttpOnly; SameSite=Lax" }
    ]
  };
  const browser = {
    runtime: { id: "test-extension", onMessage },
    permissions: {
      async contains({ permissions }) {
        return permissions.includes("webRequestBlocking") && tlsPermission;
      }
    },
    webRequest: {
      onHeadersReceived,
      onErrorOccurred,
      async getSecurityInfo(requestId) {
        assert.equal(insideHeadersListener, true);
        assert.equal(requestId, "request-1");
        securityInfoCalls += 1;
        return securityInfo;
      }
    },
    tabs: {
      onUpdated,
      async get(tabId) {
        assert.equal(tabId, 7);
        return { id: tabId, url: "https://example.test/" };
      },
      async reload(tabId) {
        assert.equal(tabId, 7);
        queueMicrotask(() => {
          insideHeadersListener = true;
          onHeadersReceived.listener(details);
          insideHeadersListener = false;
        });
      }
    }
  };
  const context = vm.createContext({ browser, URL, setTimeout, clearTimeout });
  context.globalThis = context;
  vm.runInContext(tlsSource, context, { filename: "tls-analysis.js" });
  vm.runInContext(
    fs.readFileSync(path.join(root, "src/background.js"), "utf8"),
    context,
    { filename: "background.js" }
  );
  return {
    handler: onMessage.listener,
    onHeadersReceived,
    securityInfoCalls: () => securityInfoCalls
  };
}

test("sanitizes Firefox TLS metadata and excludes raw certificate material", () => {
  const tls = loadTls();
  const sanitized = tls.sanitizeSecurityInfo({
    state: "secure",
    protocolVersion: "TLSv1.3",
    cipherSuite: "TLS_AES_128_GCM_SHA256",
    keaGroupName: "X25519",
    signatureSchemeName: "ecdsa_secp256r1_sha256",
    hsts: true,
    isDomainMismatch: false,
    isNotValidAtThisTime: false,
    isUntrusted: false,
    certificates: [{
      subject: "CN=example.test",
      issuer: "CN=Example CA",
      serialNumber: "123",
      fingerprint: { sha256: "cert-fingerprint" },
      validity: { start: 1793520000000, end: 1825056000000 },
      rawDER: [1, 2, 3]
    }]
  });

  assert.equal(sanitized.state, "secure");
  assert.equal(sanitized.protocolVersion, "TLSv1.3");
  assert.equal(sanitized.certificate.subject, "CN=example.test");
  assert.equal(sanitized.certificate.fingerprintSha256, "cert-fingerprint");
  assert.equal("rawDER" in sanitized.certificate, false);
  assert.equal("certificates" in sanitized, false);
});

test("identifies old protocols and Firefox-reported certificate problems", () => {
  const report = loadTls().assess({
    state: "weak",
    protocolVersion: "TLSv1.1",
    cipherSuite: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    weaknessReasons: "cipher",
    isDomainMismatch: true,
    isNotValidAtThisTime: true,
    isUntrusted: true,
    certificates: []
  });

  assert.equal(report.available, true);
  assert.equal(report.issues.length, 5);
  assert.deepEqual(
    JSON.parse(JSON.stringify(report.issues.map((issue) => issue.title))),
    [
      "Firefox bewertet die TLS-Verbindung als schwach",
      "Veraltete TLS-Protokollversion",
      "Zertifikat passt nicht zum Hostnamen",
      "Zertifikat ist aktuell nicht gültig",
      "Zertifikatskette ist nicht vertrauenswürdig"
    ]
  );
});

test("reports insecure HTTP and unavailable or malformed TLS data explicitly", () => {
  const tls = loadTls();
  assert.equal(tls.assess({ state: "insecure" }).issues[0].title, "Verbindung ist nicht verschlüsselt");
  assert.equal(tls.assess(null).available, false);
  assert.equal(tls.assess(null).reason.includes("Berechtigung"), true);
  assert.equal(tls.assess(null, "permission denied").reason, "permission denied");
  assert.equal(tls.assess({ state: "unexpected" }).metadata.state, "unknown");
  assert.equal(tls.sanitizeSecurityInfo(null), null);
  assert.equal(
    tls.sanitizeSecurityInfo({ certificates: [{ validity: { start: 1e300, end: 1 } }] })
      .certificate.validity.start,
    null
  );
});

test("background captures TLS only when requested and only for the main frame", async () => {
  const data = loadBackground({
    securityInfo: {
      state: "secure",
      protocolVersion: "TLSv1.3",
      cipherSuite: "TLS_AES_128_GCM_SHA256",
      hsts: true,
      certificates: [{
        subject: "CN=example.test",
        issuer: "CN=Example CA",
        fingerprint: { sha256: "fingerprint" }
      }]
    }
  });
  const responsePromise = data.handler(
    {
      type: "scan-server-header",
      tabId: 7,
      origin: "https://example.test",
      captureTls: true
    },
    { id: "test-extension" }
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(
    JSON.parse(JSON.stringify(data.onHeadersReceived.extraInfoSpec)),
    ["responseHeaders", "blocking"]
  );
  const response = await responsePromise;

  assert.equal(data.securityInfoCalls(), 1);
  assert.equal(response.tls.state, "secure");
  assert.equal(response.tls.certificate.fingerprintSha256, "fingerprint");
  assert.equal(response.headers.server[0], "nginx/1.26.0");
  assert.equal("session" in response, false);

  const withoutTls = loadBackground({ tlsPermission: false });
  const passivePromise = withoutTls.handler(
    {
      type: "scan-server-header",
      tabId: 7,
      origin: "https://example.test",
      captureTls: true
    },
    { id: "test-extension" }
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(
    JSON.parse(JSON.stringify(withoutTls.onHeadersReceived.extraInfoSpec)),
    ["responseHeaders"]
  );
  const passiveResponse = await passivePromise;
  assert.equal(withoutTls.securityInfoCalls(), 0);
  assert.equal(passiveResponse.tls, null);
  assert.match(passiveResponse.tlsError, /Berechtigung fehlt/);
});

test("scan history tracks TLS protocol and certificate changes", () => {
  const context = vm.createContext({ URL });
  context.window = {};
  vm.runInContext(
    fs.readFileSync(path.join(root, "src/popup/scripts/history.js"), "utf8"),
    context
  );
  const changes = context.window.CapybaraHistory.diff(
    {
      findings: [],
      components: [],
      tls: {
        state: "secure",
        protocolVersion: "TLSv1.2",
        cipherSuite: "old-suite",
        certificate: { fingerprintSha256: "old-fingerprint" }
      }
    },
    {
      findings: [],
      components: [],
      tls: {
        state: "secure",
        protocolVersion: "TLSv1.3",
        cipherSuite: "new-suite",
        certificate: { fingerprintSha256: "new-fingerprint" }
      }
    }
  );

  assert.deepEqual(
    JSON.parse(JSON.stringify(changes.tlsChanges.map((item) => item.field))),
    ["Protokoll", "Cipher-Suite", "Zertifikat-Fingerprint"]
  );
});
