"""
Single domain scan routes for the EASM application.
These routes handle individual domain scanning.
"""
from flask import Blueprint, render_template, request, jsonify, send_from_directory, send_file
import json
from datetime import datetime
import sqlite3,os
from pathlib import Path
import csv
import io

# Import services
from services.dns_service import get_dns_records
from services.ssl_service import get_ssl_info
from services.vuln_service import check_vulnerabilities_alternative
from services.subdomain_service import find_subdomains
from services.domain_service import find_related_domains
from services.Darkweb import check_ahmia
from config import BRAVE_API_KEY

# Create blueprint
single_scan_bp = Blueprint('single_scan', __name__)

# Routes
@single_scan_bp.route('/')
def index():
    """Render the main index page with the scan form."""
    return render_template('index.html')

@single_scan_bp.route('/critical_high_cves')
def critical_high_cves():
    """Toon alle domeinen met minstens één unieke Critical of High CVE (ook uit batch scans)."""
    conn = sqlite3.connect('easm.db')
    c = conn.cursor()
    c.execute('''SELECT domain, scan_date, vulnerabilities
                 FROM scans
                 ORDER BY scan_date DESC''')
    # ...existing code...
    domains_with_cves = []
    for row in c.fetchall():
        domain = row[0]
        scan_date = row[1]
        try:
            vulns = json.loads(row[2])
        except Exception:
            continue
        seen_cves = set()
        unique_cve_vulns = []
        for v in vulns:
            if v.get('type') == 'tech_vulnerability' and v.get('severity', '').lower() in ('critical', 'high'):
                # Gebruik cve_id + description als unieke key
                cve_id = v.get('cve_id', 'Unknown')
                description = v.get('description', '')
                unique_key = (cve_id, description)
                if unique_key not in seen_cves:
                    seen_cves.add(unique_key)
                    unique_cve_vulns.append(v)
        if unique_cve_vulns:
            domains_with_cves.append({
                'domain': domain,
                'scan_date': scan_date,
                'vulnerabilities': unique_cve_vulns
            })
    conn.close()
# ...existing code...
    return render_template('critical_high_cves.html', domains=domains_with_cves)

@single_scan_bp.route('/history')
def scan_history():
    """Display the scan history page."""
    try:
        conn = sqlite3.connect('easm.db')
        c = conn.cursor()
        
        # Get single scans
        c.execute('''SELECT domain, scan_date, dns_records, ssl_info, 
                            vulnerabilities, subdomains, related_domains, onion_links
                     FROM scans 
                     WHERE is_batch_scan = 0
                     ORDER BY scan_date DESC''')
        single_scans = []
        for row in c.fetchall():
            single_scans.append({
                'domain': row[0],
                'scan_date': row[1],
                'dns_records': row[2],
                'ssl_info': row[3],
                'vulnerabilities': row[4],
                'subdomains': row[5],
                'related_domains': row[6],
                'onion_links': row[7]
            })
        
        # Get batch scans
        c.execute('''SELECT batch_id, created_at, total_domains, completed_domains, status
                     FROM batch_scans
                     ORDER BY created_at DESC''')
        batch_scans = []
        for row in c.fetchall():
            batch_scans.append({
                'batch_id': row[0],
                'created_at': row[1],
                'total_domains': row[2],
                'completed_domains': row[3],
                'status': row[4]
            })
        
        conn.close()
        return render_template('history.html', 
                             single_scans=single_scans,
                             batch_scans=batch_scans)
    except Exception as e:
        print(f"Error retrieving scan history: {str(e)}")
        return render_template('history.html', 
                             single_scans=[],
                             batch_scans=[],
                             error=str(e))

@single_scan_bp.route('/scan', methods=['POST'])
def scan_domain():
    """Process a single domain scan."""
    domain = request.form['domain']
    scan_options = {
        'dns_scan': 'dns_scan' in request.form,
        'ssl_scan': 'ssl_scan' in request.form,
        'subdomain_scan': 'subdomain_scan' in request.form,
        'related_domains': 'related_domains' in request.form,
        'vuln_scan': 'vuln_scan' in request.form,
        'darkweb':'darkweb' in request.form
    }
    
    # Initialize results dictionary
    results = {
        'dns_info': {},
        'ssl_info': {},
        'vulnerabilities': [],
        'subdomains': [],
        'related_domains': [],
        'onion_links': {'interested_links': [], 'other_links': []}
    }
    
    try:
        # Perform scans based on selected options
        if scan_options['dns_scan']:
            print(f"Starting DNS scan for {domain}")
            results['dns_info'] = get_dns_records(domain)
        
        if scan_options['ssl_scan']:
            print(f"Starting SSL scan for {domain}")
            results['ssl_info'] = get_ssl_info(domain)
        
        if scan_options['vuln_scan']:
            print(f"Starting vulnerability scan for {domain}")
            results['vulnerabilities'] = check_vulnerabilities_alternative(domain)
        
        if scan_options['subdomain_scan']:
            print(f"Starting subdomain discovery for {domain}")
            results['subdomains'] = find_subdomains(domain)
        
        if scan_options['related_domains']:
            print(f"Starting related domain discovery for {domain}")
            results['related_domains'] = find_related_domains(domain, BRAVE_API_KEY)
            
        if scan_options['darkweb']:
            print(f"Darkweb scan uitvoeren op {domain}")
            darkweb_results = check_ahmia(domain)
            results['onion_links'] = darkweb_results
        
        # Store results in database
        conn = sqlite3.connect('easm.db')
        c = conn.cursor()
        c.execute('''INSERT INTO scans 
                     (domain, scan_date, dns_records, ssl_info, vulnerabilities, 
                      subdomains, related_domains, onion_links)
                     VALUES (?, ?, ?, ?, ?, ?, ?,?)''',
                  (domain, 
                   datetime.now(),
                   json.dumps(results['dns_info']),
                   json.dumps(results['ssl_info']),
                   json.dumps(results['vulnerabilities']),
                   json.dumps(results['subdomains']),
                   json.dumps(results['related_domains']),
                   json.dumps(results['onion_links'])))
        conn.commit()
        conn.close()
        
        # Export results to CSV
        from routes.utils import export_to_csv
        csv_file = export_to_csv(results, domain)
        
        # Render template with results
        return render_template('results.html',
                             domain=domain,
                             dns_info=results['dns_info'],
                             ssl_info=results['ssl_info'],
                             vulnerabilities=results['vulnerabilities'],
                             subdomains=results['subdomains'],
                             related_domains=results['related_domains'],
                             onionlinks=results['onion_links'],
                             csv_file=csv_file)
                             
    except Exception as e:
        # Log the error
        print(f"Error during scan: {str(e)}")
        
        # Return error page or error message
        return render_template('results.html',
                             domain=domain,
                             error=str(e),
                             dns_info={},
                             ssl_info={'error': 'Scan failed'},
                             vulnerabilities=[],
                             subdomains=[],
                             related_domains=[],
                             onionlinks={'interested_links': [], 'other_links': []})

@single_scan_bp.route('/download/<filename>')
def download_batch_file(filename):
    """Download a file from a specific batch directory."""
    try:
        # Ensure results directory exists
        os.makedirs('results', exist_ok=True)
        
        # Get the absolute path to the results directory
        file_path = os.path.abspath('results')
        
        if not os.path.exists(os.path.join(file_path, filename)):
            return jsonify({'error': f'File {filename} not found in {file_path}'}), 404
            
        return send_from_directory(file_path, filename, as_attachment=True)
    except Exception as e:
        return jsonify({'error': f'Error downloading file: {str(e)}'}), 500
    
@single_scan_bp.route('/darkweb', methods=['GET', 'POST'])
def darkweb_scan():
    """Render the darkweb scan page."""
    try:
        if request.method == 'POST':
            domain = request.form.get('domain', '')
            # Haal de links op uit de database
            conn = sqlite3.connect('easm.db')
            c = conn.cursor()
            c.execute('''SELECT onion_links
                         FROM scans
                         WHERE domain = ?
                         ORDER BY scan_date DESC
                         LIMIT 1''', (domain,))
            row = c.fetchone()
            conn.close()

            if row:
                links = json.loads(row[0])
                print(f"Darkweb links voor {domain} uit database: {links}")  # Debug print
                # Als de links al in het nieuwe formaat zijn, gebruik ze direct
                if isinstance(links, dict) and 'interested_links' in links and 'other_links' in links:
                    return render_template('darkweb.html', result=links, domain=domain)
                # Anders, converteer de oude lijst naar het nieuwe formaat
                else:
                    # Voer de check_ahmia functie opnieuw uit om de links te categoriseren
                    categorized_links = check_ahmia(domain)
                    return render_template('darkweb.html', result=categorized_links, domain=domain)
            else:
                # Als er geen links in de database zijn, voer een nieuwe scan uit
                categorized_links = check_ahmia(domain)
                return render_template('darkweb.html', result=categorized_links, domain=domain)
        else:
            domain = request.args.get('domain', '')
            return render_template('darkweb.html', domain=domain)
    except Exception as e:
        print(f"Error during darkweb scan: {str(e)}")
        return render_template('darkweb.html', error=str(e), domain='')

@single_scan_bp.route('/scan/<path:domain>')
def view_scan_results(domain):
    """View the scan results for a specific domain."""
    try:
        # Get the most recent scan from the database
        conn = sqlite3.connect('easm.db')
        c = conn.cursor()
        c.execute('''SELECT scan_date, dns_records, ssl_info, vulnerabilities, 
                            subdomains, related_domains, onion_links
                     FROM scans
                     WHERE domain = ?
                     ORDER BY scan_date DESC
                     LIMIT 1''', (domain,))
        row = c.fetchone()
        conn.close()

        if not row:
            return render_template('results.html',
                                domain=domain,
                                error="No scan results found for this domain.",
                                dns_info={},
                                ssl_info={'error': 'No data'},
                                vulnerabilities=[],
                                subdomains=[],
                                related_domains=[],
                                onionlinks={'interested_links': [], 'other_links': []})

        scan_date = row[0]
        dns_info = json.loads(row[1])
        ssl_info = json.loads(row[2])
        vulnerabilities = json.loads(row[3])
        subdomains = json.loads(row[4])
        related_domains = json.loads(row[5])
        onionlinks = json.loads(row[6])

        # Check if onionlinks is in the correct format
        if not isinstance(onionlinks, dict) or 'interested_links' not in onionlinks or 'other_links' not in onionlinks:
            if isinstance(onionlinks, list):
                categorized_links = check_ahmia(domain)
                onionlinks = categorized_links
            else:
                onionlinks = {'interested_links': [], 'other_links': []}

        return render_template('results.html',
                            domain=domain,
                            scan_date=scan_date,
                            dns_info=dns_info,
                            ssl_info=ssl_info,
                            vulnerabilities=vulnerabilities,
                            subdomains=subdomains,
                            related_domains=related_domains,
                            onionlinks=onionlinks)
    except Exception as e:
        print(f"Error in view_scan_results: {str(e)}")
        return render_template('results.html',
                            domain=domain,
                            error=str(e),
                            dns_info={},
                            ssl_info={'error': 'Scan failed'},
                            vulnerabilities=[],
                            subdomains=[],
                            related_domains=[],
                            onionlinks={'interested_links': [], 'other_links': []})

@single_scan_bp.route('/scan/<path:domain>/download')
def download_scan_results(domain):
    """Download the scan results for a specific domain as a CSV file."""
    try:
        # Get the most recent scan from the database
        conn = sqlite3.connect('easm.db')
        c = conn.cursor()
        c.execute('''SELECT scan_date, dns_records, ssl_info, vulnerabilities, 
                            subdomains, related_domains, onion_links
                     FROM scans
                     WHERE domain = ?
                     ORDER BY scan_date DESC
                     LIMIT 1''', (domain,))
        row = c.fetchone()
        conn.close()

        if not row:
            return jsonify({'error': 'No scan results found for this domain'}), 404

        scan_date = row[0]
        dns_info = json.loads(row[1])
        ssl_info = json.loads(row[2])
        vulnerabilities = json.loads(row[3])
        subdomains = json.loads(row[4])
        related_domains = json.loads(row[5])
        onionlinks = json.loads(row[6])

        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Category', 'Finding', 'Details'])
        
        # Write DNS records
        for record_type, records in dns_info.items():
            for record in records:
                writer.writerow(['DNS Record', record_type, record])
        
        # Write SSL info
        for key, value in ssl_info.items():
            writer.writerow(['SSL Certificate', key, str(value)])
        
        # Write vulnerabilities
        for vuln in vulnerabilities:
            writer.writerow(['Vulnerability', 
                           f"{vuln['title']} ({vuln['severity']})", 
                           vuln['description']])
        
        # Write subdomains
        for sub in subdomains:
            writer.writerow(['Subdomain', 
                           sub['subdomain'], 
                           f"IP: {sub['ip']}, Status: {sub['status']}"])
        
        # Write related domains
        for related in related_domains:
            writer.writerow(['Related Domain',
                           f"{related['domain']} ({related['confidence']})",
                           f"Type: {related['relation_type']}, Evidence: {related['evidence']}"])
        
        # Write darkweb links
        if isinstance(onionlinks, dict):
            for link in onionlinks.get('interested_links', []):
                writer.writerow(['Darkweb Link (Interesting)', link, ''])
            for link in onionlinks.get('other_links', []):
                writer.writerow(['Darkweb Link', link, ''])

        # Prepare the response
        output.seek(0)
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'scan_results_{domain}_{scan_date}.csv'
        )

    except Exception as e:
        print(f"Error in download_scan_results: {str(e)}")
        return jsonify({'error': str(e)}), 500
