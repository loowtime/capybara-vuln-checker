# Capybara Vuln Check

Eine Firefox-Erweiterung für passive CVE-Hinweise zu gemeldeten Webserver-Versionen.
Nach ausdrücklicher Berechtigungsbestätigung liest sie den `Server`-HTTP-Header
der aktiven Website. Für erkannte nginx- und Apache-HTTP-Server-Versionen fragt
sie die NVD anhand des exakten CPE-Produkts und der Version ab und zeigt
zugehörige Treffer mit einem CVSS-Score **über 8,0**.

## Installation zum Testen

1. Öffne `about:debugging` in Firefox.
2. Wähle **Dieser Firefox** und **Temporäres Add-on laden**.
3. Wähle die Datei `manifest.json` aus diesem Verzeichnis.
4. Öffne eine eigene oder ausdrücklich autorisierte Website und klicke auf das
   Capybara-Symbol.
5. Bestätige im Popup die Berechtigung und starte die Prüfung. Firefox fragt
   einmalig nach der Berechtigung zum Lesen von Antwort-Headern; die Seite wird
   zur Erfassung des Headers einmal neu geladen.

## Grenzen und Datenschutz

- Nur der vom Server gesendete `Server`-Header wird gelesen. Unterstützt sind
  aktuell nginx und Apache HTTP Server mit sichtbarer Versionsnummer. Ein
  fehlender oder veränderter Header kann nicht erkannt werden; Reverse-Proxies
  können statt des Anwendungsservers erscheinen.
- Die NVD-Abfrage verwendet das erkannte Produkt und die Version als CPE.
  Ergebnisse sind Hinweise, kein Beweis, dass das konkrete System verwundbar
  ist; ebenso beweist ein leerer Befund keine Sicherheit.
- An die NVD wird nur das CPE gesendet, nicht die Seiten-URL oder der Hostname.
- Es werden keine Ports gescannt, keine weiteren Endpunkte abgefragt und keine
  Exploits ausgeführt.
- NVD kann Anfragen begrenzen oder vorübergehend nicht erreichbar sein.
