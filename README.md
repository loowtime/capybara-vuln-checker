# Capybara Vuln Check

Eine Firefox-Erweiterung für passive, unverifizierte Hinweise auf aktuelle CVEs.
Beim Öffnen des Capybara-Buttons untersucht sie die aktive Seite auf sichtbare
Technologie-Metadaten und typische Ressourcenpfade. Für bis zu drei erkannte
Technologien fragt sie die NVD nach in den letzten 120 Tagen veröffentlichten
CVEs ab und zeigt Treffer mit einem CVSS-Score **über 8,0**.

## Installation zum Testen

1. Öffne `about:debugging` in Firefox.
2. Wähle **Dieser Firefox** und **Temporäres Add-on laden**.
3. Wähle die Datei `manifest.json` aus diesem Verzeichnis.
4. Öffne eine Website und klicke auf das Capybara-Symbol.

## Grenzen und Datenschutz

- Die Erkennung nutzt nur sichtbare Generator-Metadaten, Seitenpfade und
  Ressourcen-URLs. Servertechnologien wie PHP sind oft nicht erkennbar.
- Die NVD-Abfrage sucht nach Technologiestichwörtern, nicht nach verifizierten
  Produkt-/Versions-Kombinationen. Ein Treffer ist **kein Nachweis**, dass die
  besuchte Website betroffen ist; fehlende Treffer sind ebenso kein Nachweis
  der Sicherheit.
- Nur erkannte Technologiestichwörter werden an die NVD gesendet. Seiten-URL,
  Hostname und Seiteninhalte werden nicht übertragen.
- Es werden keine Ports, Server oder Schwachstellen aktiv getestet und keine
  Exploits ausgeführt.
- NVD kann Anfragen begrenzen oder vorübergehend nicht erreichbar sein.
