"""
Batch domain scan routes for the EASM application.
These routes handle batch processing of multiple domains.
"""
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, send_from_directory
import json
import os
import time
import csv
import sqlite3
from datetime import datetime
from werkzeug.utils import secure_filename

# Import services
from services.dns_service import get_dns_records
from services.ssl_service import get_ssl_info
from services.vuln_service import check_vulnerabilities_alternative
from services.subdomain_service import find_subdomains
from services.domain_service import find_related_domains
from config import BRAVE_API_KEY

# Import utilities
from routes.utils import allowed_file, export_to_csv
from services.domain_utils import validate_domains_file

# Create blueprint
batch_scan_bp = Blueprint('batch_scan', __name__)

# Ensure necessary directories exist
def ensure_directories():
    """Ensure required directories exist."""
    os.makedirs('uploads', exist_ok=True)
    os.makedirs('results', exist_ok=True)

# Routes
@batch_scan_bp.route('/batch_scan', methods=['POST'])
def batch_scan():
    """Process a batch domain scan from an uploaded file."""
    ensure_directories()
    
    if 'domains_file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['domains_file']
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join('uploads', filename)
        file.save(file_path)
        
        # Read file content
        with open(file_path, 'r') as f:
            file_content = f.read()
        
        # Get file extension
        file_extension = filename.rsplit('.', 1)[1].lower()
        
        # Validate domains in the file
        valid_domains, invalid_domains, error_message = validate_domains_file(file_content, file_extension)
        
        # Return validation results
        return render_template('validate_domains.html',
                             filename=filename,
                             valid_domains=valid_domains,
                             invalid_domains=invalid_domains,
                             error_message=error_message)
    
    return jsonify({'error': 'File type not allowed'}), 400

@batch_scan_bp.route('/process_batch_validation', methods=['POST'])
def process_batch_validation():
    """Process validated domains from the batch upload."""
    # Get domains from form
    domains_json = request.form.get('domains_json', '[]')
    domains = json.loads(domains_json)
    
    if not domains:
        return redirect(url_for('single_scan.index'))
    
    # Get scan options
    scan_options = {
        'dns_scan': 'dns_scan' in request.form,
        'ssl_scan': 'ssl_scan' in request.form,
        'subdomain_scan': 'subdomain_scan' in request.form,
        'related_domains': 'related_domains' in request.form,
        'vuln_scan': 'vuln_scan' in request.form
    }
    
    # Create batch ID and directory
    batch_id = str(int(time.time()))
    batch_dir = os.path.join('results', batch_id)
    os.makedirs(batch_dir, exist_ok=True)
    
    # Save domains for processing
    with open(os.path.join(batch_dir, 'domains.txt'), 'w') as f:
        for domain in domains:
            f.write(f"{domain}\n")
    
    # Save scan options
    with open(os.path.join(batch_dir, 'options.json'), 'w') as f:
        json.dump(scan_options, f)
    
    # Return batch results page
    return render_template('batch_results.html',
                         batch_id=batch_id,
                         domains=domains,
                         total=len(domains),
                         scan_options=scan_options)

@batch_scan_bp.route('/process_batch/<batch_id>', methods=['POST'])
def process_batch(batch_id):
    """Process the batch of domains and generate results."""
    batch_dir = os.path.join('results', batch_id)
    
    # Read domains from the stored file
    with open(os.path.join(batch_dir, 'domains.txt'), 'r') as f:
        domains = [line.strip() for line in f if line.strip()]
    
    # Get scan options from the stored file
    with open(os.path.join(batch_dir, 'options.json'), 'r') as f:
        scan_options = json.load(f)
    
    # Process each domain
    all_results = {}
    for i, domain in enumerate(domains):
        try:
            print(f"Processing domain {i+1}/{len(domains)}: {domain}")
            
            # Initialize results dictionary
            results = {
                'dns_info': {},
                'ssl_info': {},
                'vulnerabilities': [],
                'subdomains': [],
                'related_domains': []
            }
            
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
            
            # Store results in database
            conn = sqlite3.connect('easm.db')
            c = conn.cursor()
            c.execute('''INSERT INTO scans 
                         (domain, scan_date, dns_records, ssl_info, vulnerabilities, 
                          subdomains, related_domains)
                         VALUES (?, ?, ?, ?, ?, ?, ?)''',
                      (domain, 
                       datetime.now(),
                       json.dumps(results['dns_info']),
                       json.dumps(results['ssl_info']),
                       json.dumps(results['vulnerabilities']),
                       json.dumps(results['subdomains']),
                       json.dumps(results['related_domains'])))
            conn.commit()
            conn.close()
            
            # Export results to CSV
            csv_file = export_to_csv(results, domain)
            
            # Store results for this domain
            all_results[domain] = {
                'status': 'completed',
                'results': results,
                'csv_file': csv_file
            }
            
        except Exception as e:
            print(f"Error scanning domain {domain}: {str(e)}")
            all_results[domain] = {
                'status': 'error',
                'error': str(e)
            }
    
    # Save all results to a JSON file
    with open(os.path.join(batch_dir, 'all_results.json'), 'w') as f:
        json.dump(all_results, f)
    
    # Create a combined CSV report
    combined_csv = os.path.join(batch_dir, f'combined_results_{batch_id}.csv')
    with open(combined_csv, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Domain', 'Category', 'Finding', 'Details'])
        
        for domain, domain_results in all_results.items():
            if domain_results['status'] == 'completed':
                results = domain_results['results']
                
                # Write DNS records
                for record_type, records in results['dns_info'].items():
                    for record in records:
                        writer.writerow([domain, 'DNS Record', record_type, record])
                
                # Write vulnerabilities
                for vuln in results['vulnerabilities']:
                    writer.writerow([domain, 'Vulnerability', 
                                   f"{vuln['title']} ({vuln['severity']})", 
                                   vuln['description']])
                
                # Write subdomains
                for sub in results['subdomains']:
                    writer.writerow([domain, 'Subdomain', 
                                   sub['subdomain'], 
                                   f"IP: {sub['ip']}, Status: {sub['status']}"])
                
                # Write related domains
                for related in results['related_domains']:
                    writer.writerow([domain, 'Related Domain',
                                   f"{related['domain']} ({related['confidence']})",
                                   f"Type: {related['relation_type']}, Evidence: {related['evidence']}"])
            else:
                writer.writerow([domain, 'Error', domain_results['error'], ''])
    
    return render_template('batch_complete.html', 
                         batch_id=batch_id, 
                         results=all_results,
                         total=len(domains),
                         completed=len(all_results),
                         combined_csv=os.path.basename(combined_csv))

@batch_scan_bp.route('/download/<path:filename>')
def download_file(filename):
    """Download a file from the results directory."""
    return send_from_directory('results', filename, as_attachment=True)