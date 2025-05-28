# EASM Project Architectuur

## Architectuur Overzicht (Tekst)

**1. Webapplicatie (Flask)**
- Hoofdbestand: `app.py`
  - Initialiseert de Flask-applicatie.
  - Zet de database op (`easm.db`).
  - Registreert blueprints voor routes.
- Configuratie: `config.py`
  - Bevat API-sleutels, databasepad, en beveiligingsinstellingen.

**2. Routes (Blueprints)**
- `routes/single_scan.py`: Routes voor het scannen van één domein.
- `routes/batch_scan.py`: Routes voor batchscans van meerdere domeinen.

**3. Services**
- `services/`: Bevat logica voor:
  - DNS-scans
  - SSL-informatie
  - Vulnerability scanning
  - Subdomein- en gerelateerde domein-detectie
  - Darkweb/onion link-detectie
  - Technologie-detectie

**4. Templates (Frontend)**
- `templates/index.html`: Hoofdpagina met scanformulier (single/batch).
- `templates/results.html`: Resultaten van een scan.
- `templates/batch_results.html`: Resultaten van batchscans.
- `templates/history.html`: Overzicht van uitgevoerde scans.
- `templates/technology_detection_depreciated.html`: Visualisatie van technologieën.

**5. Database**
- SQLite (`easm.db`)
  - Tabel `scans`: Resultaten van individuele scans.
  - Tabel `batch_scans`: Informatie over batchscans.

**6. Bestanden & Opslag**
- `uploads/`: Geüploade batchbestanden (Batch Scan).
- `results/`: CSV-resultaten van scans.

**7. Overige**
- `Dockerfile` en `compose.yml`: Voor containerisatie.
- `requirements.txt`: Python dependencies.

---

## Mermaid Diagram

```mermaid
flowchart TB
    %% Richting is TB (top-bottom) voor een hogere, minder brede diagram
    %% Webapplicatie
    A1[app.py] --> C1[config.py]
    A1 --> B1a[routes/single_scan.py]
    A1 --> B1b[routes/batch_scan.py]
    A1 --> B1c[routes/tech_detection_depreciated.py]

    %% Blueprints naar services
    B1a --> S1[services/dns_service.py]
    B1a --> S2[services/ssl_service.py]
    B1a --> S3[services/vuln_service.py]
    B1a --> S4[services/subdomain_service.py]
    B1a --> S5[services/domain_service.py]
    B1a --> S6[services/Darkweb.py]
    B1a --> S7[services/tech_detection_service.py]

    B1b --> S1
    B1b --> S2
    B1b --> S3
    B1b --> S4
    B1b --> S5
    B1b --> S6
    B1b --> S7

    B1c --> S7

    %% Blueprints naar database
    B1a --> D1[easm.db]
    B1b --> D1
    D1 --> D1a[scans]
    D1 --> D1b[batch_scans]

    %% Blueprints naar opslag
    B1a --> O2[CVE]
```

---

**Samenvatting:**  
Het project is een modulaire Flask-applicatie voor domeinscans, met een duidelijke scheiding tussen routes, services, templates en opslag. Scans kunnen individueel of in batch worden uitgevoerd, resultaten worden opgeslagen in een SQLite-database en zijn te downloaden als CSV. De frontend gebruikt TailwindCSS en biedt een overzichtelijke gebruikersinterface.
