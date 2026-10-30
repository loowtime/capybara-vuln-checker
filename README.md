# Capybara Vuln Check

Eine Firefox-Erweiterung für passive Update-Hinweise. Nach ausdrücklicher
Berechtigungsbestätigung liest sie ausgewählte HTTP-Antwort-Header und bereits
geladene Seitenressourcen. Sie erkennt offengelegte Versionen von nginx,
Apache HTTP Server, IIS, Tomcat, PHP, OpenSSL und weiteren Diensten sowie
WordPress-/Joomla-Metadaten und sichtbare Plugin-Ressourcen. Für unterstützte
Produkt-/Versions-Kombinationen fragt sie die NVD über CPE ab und zeigt CVEs
mit CVSS **über 8,0** samt Schweregrad an.

Zusätzlich bewertet sie passiv wichtige Response-Header (CSP, HSTS,
Clickjacking-/MIME-Schutz, Referrer- und Browser-Policies), Cookie-Attribute,
Mixed Content, Passwortformulare und externe Skripte ohne SRI.

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
- Cookie-Werte werden nicht gespeichert oder angezeigt; ausgewertet werden
  nur Anzahl und Secure-/HttpOnly-/SameSite-Attribute der Cookies im
  Hauptseiten-Response. Header-Befunde sind Hinweise und müssen zur Anwendung
  passen; insbesondere CSP- und Browser-Policies können Funktionen brechen.
- WordPress-Plugin-Namen stammen aus öffentlichen Asset-Pfaden. Ein `ver`-
  Parameter ist nur ein schwacher Versionshinweis und kann eine Asset-Version
  statt der installierten Plugin-Version bezeichnen. Die Installation im CMS
  oder Deployment muss für Update-Entscheidungen geprüft werden.
- Die NVD-Abfrage verwendet das erkannte Produkt und die Version als CPE.
  Ergebnisse sind Hinweise, kein Beweis, dass das konkrete System verwundbar
  ist; ebenso beweist ein leerer Befund keine Sicherheit. CVSS bewertet die
  Schwachstelle allgemein, nicht die tatsächliche Konfiguration der Website.
- Pro Produkt werden höchstens die 100 neuesten NVD-Einträge ausgewertet.
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
