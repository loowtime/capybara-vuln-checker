# Capybara Vuln Check

Eine Firefox-Erweiterung für passive Update- und Sicherheits-Hinweise auf
eigenen oder ausdrücklich autorisiert geprüften Websites. Nach Bestätigung
liest sie ausgewählte HTTP-Antwort-Header und bereits geladene Ressourcen.
Erkannte Produkt-/Versions-Kombinationen werden über CPE mit der NVD
abgeglichen. Ergänzend gibt es eine kleine, lokal gepflegte Advisory-Liste für
WordPress-Core, sichtbare WordPress-Plugins, Joomla JCE und PHP, weil NVD-
Einträge für manche Plugins keine maschinenlesbaren CPE-Konfigurationen haben.

Angezeigt werden CVE-Kandidaten samt Status, CVSS und einer nachvollziehbaren
Einordnung. Werte über 8,0 werden hervorgehoben. Die Erweiterung bewertet
passiv CSP, HSTS, Clickjacking-/MIME-Schutz, Browser-Policies, Cookie-
Attribute, Mixed Content, Passwortformulare und externe Skripte ohne SRI.

## Projektstruktur

```text
manifest.json             Firefox-Einstiegspunkt
assets/icons/             Erweiterungssymbole
src/
  background.js             Header-Erfassung beim Seitenreload
  popup.html                Popup-Einstiegspunkt
  popup/scripts/            Erkennung, NVD, Posture, UI und Orchestrierung
  styles/                   Popup-Styles
tests/                      Offline-Tests ohne Netzwerkzugriff
```

Die Erweiterung hat absichtlich keinen Build-Schritt: Firefox lädt die Dateien
direkt über `manifest.json` und `src/popup.html`.

## Installation zum Testen

1. Öffne `about:debugging` in Firefox.
2. Wähle **Dieser Firefox** und **Temporäres Add-on laden**.
3. Wähle die Datei `manifest.json` aus diesem Verzeichnis.
4. Öffne eine eigene oder ausdrücklich autorisierte Website und klicke auf das
   Capybara-Symbol.
5. Bestätige im Popup, dass du zur Prüfung berechtigt bist, und starte den Scan.
   Beim ersten Scan bittet Firefox zusätzlich um Zugriff auf den Host der
   geöffneten Seite. Die Seite wird zur Erfassung des Headers einmal neu geladen.

Nach Änderungen an `manifest.json` muss das Add-on unter `about:debugging`
entfernt und mit **Temporäres Add-on laden** erneut geladen werden.

## Grenzen und Datenschutz

- Es werden nur ausgewählte Antwort-Header der Hauptseite und URLs bereits
  geladener Seitenressourcen ausgewertet. Das Add-on crawlt keine Seiten und
  führt keine aktiven Schwachstellenprüfungen durch.
- Neben Server-/Runtime- und CMS-Hinweisen werden Namen und Versionshinweise
  ausgewählter JavaScript-Bibliotheken (jQuery, Bootstrap, Lodash, AngularJS)
  nur aus bereits geladenen Asset-URLs erkannt. Dafür werden keine weiteren
  Seitenressourcen abgerufen. Ein CPE-Abgleich erfolgt nur für Komponenten mit
  konfiguriertem Produktprofil; Dateinamen und `ver`-Parameter sind schwache
  Hinweise und kein Beweis der installierten Version.
- Cookie-Werte werden nicht gespeichert oder angezeigt; ausgewertet werden
  nur Anzahl und Secure-/HttpOnly-/SameSite-Attribute der Cookies im
  Hauptseiten-Response. Header-Befunde sind Hinweise und müssen zur Anwendung
  passen; insbesondere CSP- und Browser-Policies können Funktionen brechen.
- WordPress-Plugin-Namen stammen aus öffentlichen Asset-Pfaden. Ein `ver`-
  Parameter ist nur ein schwacher Versionshinweis und kann eine Asset-Version
  statt der installierten Plugin-Version bezeichnen. Treffer aus diesem Wert
  sind deshalb nur Update-Hinweise; die Installation im CMS oder Deployment
  muss vor einer Entscheidung geprüft werden.
- Der ergänzende Advisory-Katalog umfasst derzeit:
  - WordPress-Plugins: [CVE-2020-36847](https://nvd.nist.gov/vuln/detail/CVE-2020-36847),
    [CVE-2025-12057](https://nvd.nist.gov/vuln/detail/CVE-2025-12057),
    [CVE-2025-13486](https://nvd.nist.gov/vuln/detail/CVE-2025-13486) und
    [CVE-2025-6389](https://nvd.nist.gov/vuln/detail/CVE-2025-6389).
  - WordPress-Core: [CVE-2026-60137](https://nvd.nist.gov/vuln/detail/CVE-2026-60137)
    und [CVE-2026-63030](https://nvd.nist.gov/vuln/detail/CVE-2026-63030).
  - Joomla JCE: [CVE-2026-48907](https://nvd.nist.gov/vuln/detail/CVE-2026-48907).
  - PHP: [CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618)
    und [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619).

  Versionen werden nur dann als im erfassten Bereich markiert, wenn sie zu den
  dokumentierten Versionsbereichen passen; unbekannte Plugin-Versionen
  verlangen eine manuelle Prüfung. Der Katalog ersetzt keine regelmäßige
  Aktualisierung und ist keine vollständige CVE-Datenbank.
- CVE-2025-34085 ist von der CNA zurückgezogen/abgelehnt und als Duplikat von
  CVE-2020-36847 gekennzeichnet; die zurückgezogene ID wird nicht als aktive
  Schwachstelle ausgegeben.
- Die NVD-Abfrage verwendet das erkannte Produkt und die Version als CPE.
  Ergebnisse sind Hinweise, kein Beweis, dass das konkrete System verwundbar
  ist; ebenso beweist ein leerer Befund keine Sicherheit. CVSS bewertet die
  Schwachstelle allgemein, nicht die tatsächliche Konfiguration der Website.
  NVD-CPE-Datensätze können bei Herstellernamen und Produktzuordnung variieren.
- Die Dienstübersicht zeigt die Zahl der zugeordneten NVD-CVEs und wie viele
  davon CVSS > 8,0 haben. CVE-Kandidaten werden nicht mehr allein wegen eines
  niedrigeren Scores ausgeblendet. Hinweise und Beschreibungen sind aufklappbar.
- Pro Produkt werden höchstens die ersten 100 NVD-Ergebnisse ausgewertet.
- NVD-Anfragen laufen nacheinander mit Abstand, um die öffentliche API nicht
  durch parallele Abfragen zu überlasten; mehrere erkannte Produkte können
  deshalb etwas länger brauchen.
- Bei Distributionsversionen wie Debian können Fixes zurückportiert sein.
  Ein Upstream-Versionsvergleich kann dann einen falschen Alarm auslösen;
  Distribution-Advisories bleiben maßgeblich.
- An die NVD wird nur das CPE gesendet, nicht die Seiten-URL oder der Hostname.
- Es werden keine Ports gescannt, keine weiteren Endpunkte abgefragt und keine
  Exploits ausgeführt.
- NVD kann Anfragen begrenzen oder vorübergehend nicht erreichbar sein.

## Entwicklung und Tests

Die Tests laufen offline mit Node.js und greifen nicht auf Websites oder die
NVD zu:

```sh
npm test
```
