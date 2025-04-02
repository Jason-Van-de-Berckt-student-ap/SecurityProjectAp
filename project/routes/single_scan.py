"""
Single domain scan routes for the EASM application.
These routes handle individual domain scanning.
"""
from flask import Blueprint, render_template, request, jsonify, send_from_directory
import json
from datetime import datetime
import sqlite3,os
from pathlib import Path

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
        'onlion_links': []
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
            print(f"Darweb scan uitvoeren op {domain}")
            results['onlion_links'] = check_ahmia(domain)
        
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
                   json.dumps(results['onlion_links'])))
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
                             onionlinks=results['onlion_links'],
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
                             onionlinks=results['onlion_links'])

@single_scan_bp.route('/download/<filename>')
def download_batch_file(filename):
    """Download a file from a specific batch directory."""
    try:
        file_path = os.path.join('results')
        if not os.path.exists(file_path):
            return jsonify({'error': f'File {filename} not found in {file_path}'}), 404
            
        return send_from_directory(file_path,filename, as_attachment=True)
    except Exception as e:
        return jsonify({'error': f'Error downloading file: {str(e)} {file_path}'}), 500
    
@single_scan_bp.route('/darkweb', methods=['GET', 'POST'])
def darkweb_scan():
    """Render the darkweb scan page."""
    try:
        if request.method == 'POST':
            links = request.form.get('onionlinks')
            links=links[11:-2].split(',')
            print(f"Darkweb scan uitvoeren op {links}")
            # Perform darkweb scan using the provided links
            # Render template with results
            return render_template('darkweb.html', result=links)
        else:
            # Handle GET request
            return render_template('darkweb.html')
            
    except Exception as e:
        # Log the error
        print(f"Error during darkweb scan: {str(e)}")
        
        # Return error page or error message
        return render_template('darkweb.html', error=str(e))
