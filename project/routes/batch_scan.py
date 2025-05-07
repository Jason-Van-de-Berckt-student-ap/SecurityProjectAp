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
from pathlib import Path



# Import services
from services.dns_service import get_dns_records
from services.ssl_service import get_ssl_info
from services.vuln_service import check_vulnerabilities_alternative
from services.subdomain_service import find_subdomains
from services.domain_service import find_related_domains
from services.Darkweb import check_ahmia
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
    # Get domains from form with better error handling
    domains_list = request.form.get('domains_list', '')
    domains = [d.strip() for d in domains_list.split(',') if d.strip()]
    
    if not domains:
        return redirect(url_for('single_scan.index'))
    
    # Get scan options
    scan_options = {
        'dns_scan': 'dns_scan' in request.form,
        'ssl_scan': 'ssl_scan' in request.form,
        'subdomain_scan': 'subdomain_scan' in request.form,
        'related_domains': 'related_domains' in request.form,
        'vuln_scan': 'vuln_scan' in request.form,
        'darkweb': 'darkweb' in request.form
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
    
    # Create batch record in database
    conn = sqlite3.connect('easm.db')
    c = conn.cursor()
    c.execute('''INSERT INTO batch_scans 
                 (batch_id, created_at, total_domains, status)
                 VALUES (?, ?, ?, ?)''',
              (batch_id, datetime.now(), len(domains), 'pending'))
    conn.commit()
    conn.close()
    
    # Redirect to the batch results page
    return redirect(url_for('batch_scan.batch_results_view', batch_id=batch_id))

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
    completed_domains = 0
    
    for i, domain in enumerate(domains):
        try:
            print(f"Processing domain {i+1}/{len(domains)}: {domain}")
            
            # Initialize results dictionary
            results = {
                'dns_info': {},
                'ssl_info': {},
                'vulnerabilities': [],
                'subdomains': [],
                'related_domains': [],
                'onion_links': {'interested_links': [], 'other_links': []}
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
                
            if scan_options['darkweb']:
                print(f"Starting darkweb scan for {domain}")
                results['onion_links'] = check_ahmia(domain)
            
            # Store results in database
            conn = sqlite3.connect('easm.db')
            c = conn.cursor()
            c.execute('''INSERT INTO scans 
                         (domain, scan_date, dns_records, ssl_info, vulnerabilities, 
                          subdomains, related_domains, onion_links, batch_id, is_batch_scan)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (domain, 
                       datetime.now(),
                       json.dumps(results['dns_info']),
                       json.dumps(results['ssl_info']),
                       json.dumps(results['vulnerabilities']),
                       json.dumps(results['subdomains']),
                       json.dumps(results['related_domains']),
                       json.dumps(results['onion_links']),
                       batch_id,
                       1))
            conn.commit()
            
            # Update batch progress
            completed_domains += 1
            c.execute('''UPDATE batch_scans 
                         SET completed_domains = ?, 
                             status = CASE 
                                WHEN ? = total_domains THEN 'completed'
                                ELSE 'in_progress'
                             END
                         WHERE batch_id = ?''',
                      (completed_domains, completed_domains, batch_id))
            conn.commit()
            conn.close()
            
            # Export results to individual CSV
            csv_file = f"{domain}.csv"
            csv_path = os.path.join(batch_dir, csv_file)
            
            # Create individual domain CSV file
            with open(csv_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Category', 'Finding', 'Details'])
                
                # Write DNS records
                for record_type, records in results['dns_info'].items():
                    for record in records:
                        writer.writerow(['DNS Record', record_type, record])
                
                # Write vulnerabilities
                for vuln in results['vulnerabilities']:
                    writer.writerow(['Vulnerability', 
                                   f"{vuln['title']} ({vuln['severity']})", 
                                   vuln['description']])
                
                # Write subdomains
                for sub in results['subdomains']:
                    writer.writerow(['Subdomain', 
                                   sub['subdomain'], 
                                   f"IP: {sub['ip']}, Status: {sub['status']}"])
                
                # Write related domains
                for related in results['related_domains']:
                    writer.writerow(['Related Domain',
                                   f"{related['domain']} ({related['confidence']})",
                                   f"Type: {related['relation_type']}, Evidence: {related['evidence']}"])
                
                # Write darkweb links
                if scan_options['darkweb']:
                    for link in results['onion_links'].get('interested_links', []):
                        writer.writerow(['Darkweb Link (Interesting)', link, ''])
                    for link in results['onion_links'].get('other_links', []):
                        writer.writerow(['Darkweb Link', link, ''])
            
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
            
            # Update batch progress even for failed scans
            conn = sqlite3.connect('easm.db')
            c = conn.cursor()
            completed_domains += 1
            c.execute('''UPDATE batch_scans 
                         SET completed_domains = ?, 
                             status = CASE 
                                WHEN ? = total_domains THEN 'completed'
                                ELSE 'in_progress'
                             END
                         WHERE batch_id = ?''',
                      (completed_domains, completed_domains, batch_id))
            conn.commit()
            conn.close()
    
    # Save all results to a JSON file
    with open(os.path.join(batch_dir, 'all_results.json'), 'w') as f:
        json.dump(all_results, f)
    
    # Return the complete results page instead of just a status
    return render_template('batch_complete.html',
                         batch_id=batch_id,
                         results=all_results,
                         total=len(domains),
                         completed=completed_domains,
                         combined_csv=f'combined_results_{batch_id}.csv')

@batch_scan_bp.route('/batch_results/<batch_id>')
def batch_results_view(batch_id):
    """Display the batch results page for tracking scan progress."""
    batch_dir = os.path.join('results', batch_id)
    
    # Read domains from the stored file
    try:
        with open(os.path.join(batch_dir, 'domains.txt'), 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return jsonify({'error': 'Batch not found'}), 404
    
    # Get scan options from the stored file
    with open(os.path.join(batch_dir, 'options.json'), 'r') as f:
        scan_options = json.load(f)
    
    # Check if results exist
    results_file = os.path.join(batch_dir, 'all_results.json')
    completed = 0
    results = {}
    
    if os.path.exists(results_file):
        with open(results_file, 'r') as f:
            results = json.load(f)
        completed = sum(1 for r in results.values() if r.get('status') == 'completed')
        
        # If all domains are processed, redirect to completion page
        if completed == len(domains):
            combined_csv = f'combined_results_{batch_id}.csv'
            return render_template('batch_complete.html', 
                                batch_id=batch_id, 
                                results=results,
                                total=len(domains),
                                completed=completed,
                                combined_csv=combined_csv)
    
    # Render the batch results tracking page
    return render_template('batch_results.html',
                         batch_id=batch_id,
                         domains=domains,
                         total=len(domains),
                         completed=completed,
                         scan_options=scan_options) 
@batch_scan_bp.route('/results/<domain>', methods=['GET', 'POST']) 
def view_batch_results(domain):
    """View the results for a specific domain in a batch scan."""
    try:
        # Get the batch_id from the request
        batch_id = request.args.get('batch_id')
        if not batch_id:
            return jsonify({'error': 'Missing batch ID'}), 400
            
        # Load the results for this batch
        batch_dir = os.path.join('results', batch_id)
        with open(os.path.join(batch_dir, 'all_results.json'), 'r') as f:
            all_results = json.load(f)
        
        # Get this domain's results
        if domain not in all_results:
            return jsonify({'error': 'Domain not found in batch'}), 404
            
        domain_results = all_results[domain]
        
        # Render the results template
        if domain_results['status'] == 'completed':
            results = domain_results['results']
            return render_template('results.html',
                                domain=domain,
                                dns_info=results['dns_info'],
                                ssl_info=results['ssl_info'],
                                vulnerabilities=results['vulnerabilities'],
                                subdomains=results['subdomains'],
                                related_domains=results['related_domains'],
                                onionlinks=results['onion_links'],
                                csv_file=domain_results.get('csv_file', ''),
                                batch_id=batch_id)
        else:
            return render_template('results.html',
                                domain=domain,
                                error=domain_results['error'],
                                dns_info={},
                                ssl_info={'error': 'Scan failed'},
                                vulnerabilities=[],
                                subdomains=[],
                                related_domains=[],
                                onionlinks={'interested_links': [], 'other_links': []})
    except Exception as e:
        return render_template('results.html',
                            domain=domain,
                            error=str(e),
                            dns_info={},
                            ssl_info={'error': 'Scan failed'},
                            vulnerabilities=[],
                            subdomains=[],
                            related_domains=[],
                            onionlinks={'interested_links': [], 'other_links': []})

@batch_scan_bp.route('/download/<batch_id>/<filename>')
def download_batch_file(batch_id, filename):
    """Download a file from a specific batch directory."""
    try:
        batch_dir = os.path.join('results', batch_id)
        if not os.path.exists(batch_dir):
            print(f"Batch directory not found: {batch_dir}")
            return jsonify({'error': f'Batch {batch_id} not found'}), 404
            
        file_path = os.path.join(batch_dir, filename)
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            return jsonify({'error': f'File {filename} not found in batch {batch_id}'}), 404
            
        # Ensure the filename is secure
        secure_filename(filename)
        
        # Use absolute path for send_from_directory
        abs_batch_dir = os.path.abspath(batch_dir)
        return send_from_directory(abs_batch_dir, filename, as_attachment=True)
    except Exception as e:
        print(f"Error downloading file: {str(e)}")
        return jsonify({'error': f'Error downloading file: {str(e)}'}), 500
