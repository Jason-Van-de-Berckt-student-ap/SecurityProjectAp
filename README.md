# EASM Scanner - External Attack Surface Management

## Overzicht

Deze applicatie is een modulaire Flask-webapplicatie voor het scannen en analyseren van domeinen. Het doel is om het externe aanvalsoppervlak van een organisatie in kaart te brengen door middel van DNS-, SSL-, subdomein- en kwetsbaarheidsscans. Resultaten worden overzichtelijk gepresenteerd en zijn te exporteren.

## Functionaliteiten
- Scan één domein of meerdere domeinen (batch)
- Analyse van DNS-records, SSL-certificaten, subdomeinen, gerelateerde domeinen, kwetsbaarheden en darkweb/onion links
- Resultaten worden opgeslagen in een SQLite-database en als CSV-bestand
- Scan-geschiedenis en downloadbare rapporten
- Moderne frontend met TailwindCSS

## Installatie

1. **Vereisten**
   - Python 3.9+
   - pip
   - (Optioneel) Docker

2. **Repository klonen**
   ```bash
   git clone <repository-url>
   cd SecurityProjectAp/project
   ```

3. **Dependencies installeren**
   ```bash
   pip install -r requirements.txt
   ```

4. **.env instellen**
   Maak een `.env` bestand aan in de `project/` map met daarin:
   ```env
   BRAVE_API_KEY=...   # Vul je Brave Search API key in
   NVD_API_KEY=...     # Vul je NVD API key in
   SECRET_KEY=...      # Random string voor Flask sessions
   ```

5. **Applicatie starten**
   ```bash
   python app.py
   ```
   Of met Docker:
   ```bash
   docker build -t easm-scanner .
   docker run -p 5000:5000 easm-scanner
   ```

6. **Open de webapp**
   Ga naar [http://localhost:5000](http://localhost:5000) in je browser.

## Gebruik
- Vul een domein in op de hoofdpagina en kies de gewenste scanopties.
- Voor batchscans: upload een tekstbestand met domeinen (één per regel).
- Bekijk resultaten direct in de webinterface of download als CSV.
- Scan-geschiedenis is te vinden via de knop "View Scan History".

## Mappenstructuur
- `project/` - Hoofdapplicatie (Flask, services, routes, templates)
- `results/` - CSV-rapporten van uitgevoerde scans
- `uploads/` - Batch-uploadbestanden
- `easm.db` - SQLite database met scanresultaten

## Veelgestelde vragen
- **API keys nodig?** Ja, voor sommige functionaliteiten zijn externe API keys vereist (zie `.env`).
- **Batchscan limiet?** Voor optimale prestaties: max. 20-30 domeinen per batch. Het systeem kan meer aan, maar dan duurt het langer.
- **Problemen met dependencies?** Gebruik bij voorkeur een virtuele omgeving (`python -m venv venv`).

## Ontwikkelaars
- Zie `ARCHITECTUUR.md` voor een technisch overzicht en Mermaid-diagram van de architectuur.

## Disclaimer
Dit project is bedoeld voor educatieve doeleinden. En is gemaakt voor de New Wave group als security project.

## Creators
Jason Van de Berckt
Stanley Okomhen
