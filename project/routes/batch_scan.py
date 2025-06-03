"""
Batch domain scan routes for the EASM application.
These routes handle batch processing of multiple domains.
"""
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, send_from_directory, g
import json
import os
import time
import csv
import sqlite3
import zipfile
import io
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

# Import optimized services
from services.optimized_scanner import optimized_scanner, validate_domain
from services.background_tasks import submit_background_task, get_task_manager, background_batch_scan
from services.streaming_export import get_db_streaming_exporter

# Import authentication and logging
from services.auth_service import login_required, require_permission
from services.logging_service import log_user_action, get_logging_service

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

# Domain cleanup function
def cleanup_old_scans(domain, db_path='easm.db'):
    """Verwijder oudste scans als er meer dan 5 voor dit domein zijn."""
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        SELECT rowid FROM scans
        WHERE domain = ?
        ORDER BY scan_date ASC
    ''', (domain,))
    rows = c.fetchall()
    if len(rows) > 5:
        to_delete = rows[:len(rows) - 5]
        c.executemany('DELETE FROM scans WHERE rowid = ?', to_delete)
        conn.commit()
    conn.close()

def create_batch_zip(batch_id, batch_dir):
    """Create a ZIP file containing all CSV files and results from a batch scan."""
    try:
        zip_filename = f'batch_results_{batch_id}.zip'
        zip_path = os.path.join(batch_dir, zip_filename)
        
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            # Add all CSV files
            for file in os.listdir(batch_dir):
                if file.endswith('.csv'):
                    file_path = os.path.join(batch_dir, file)
                    zipf.write(file_path, file)
            
            # Add the JSON results file
            json_file = os.path.join(batch_dir, 'all_results.json')
            if os.path.exists(json_file):
                zipf.write(json_file, 'all_results.json')
            
            # Add the domains list
            domains_file = os.path.join(batch_dir, 'domains.txt')
            if os.path.exists(domains_file):
                zipf.write(domains_file, 'domains.txt')
            
            # Add scan options
            options_file = os.path.join(batch_dir, 'options.json')
            if os.path.exists(options_file):
                zipf.write(options_file, 'scan_options.json')
        
        return zip_filename
    except Exception as e:
        print(f"Error creating ZIP file: {str(e)}")
        return None

# Routes
@batch_scan_bp.route('/batch_scan', methods=['POST'])
@login_required
@require_permission('batch_scan')
@log_user_action('batch_scan_upload')
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
        
        # Return validation results without scan options (will be selected on validation page)
        return render_template('validate_domains.html',
                             filename=filename,
                             valid_domains=valid_domains,
                             invalid_domains=invalid_domains,
                             error_message=error_message)
    
    return jsonify({'error': 'File type not allowed'}), 400

@batch_scan_bp.route('/process_batch_validation', methods=['POST'])
@login_required
@require_permission('batch_scan')
@log_user_action('batch_scan_validation')
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
@login_required
@require_permission('batch_scan')
@log_user_action('batch_scan_execute')
def process_batch(batch_id):
    """Process the batch of domains using optimized scanner."""
    batch_dir = os.path.join('results', batch_id)
    
    # Read domains from the stored file
    with open(os.path.join(batch_dir, 'domains.txt'), 'r') as f:
        domains = [line.strip() for line in f if line.strip()]
    
    # Get scan options from the stored file
    with open(os.path.join(batch_dir, 'options.json'), 'r') as f:
        scan_options = json.load(f)
    
    # Check if background processing is requested
    background_process = request.form.get('background', False)
    
    if background_process:
        # Submit as background task
        task_id = submit_background_task(
            f"Batch Scan: {len(domains)} domains",
            optimized_scanner.scan_domains_batch_parallel,
            domains, scan_options, BRAVE_API_KEY
        )
        
        return jsonify({
            'status': 'submitted',
            'task_id': task_id,
            'batch_id': batch_id,
            'message': f'Batch scan for {len(domains)} domains submitted as background task'
        })
    
    # Process immediately with optimized scanner
    print(f"Starting optimized batch scan for {len(domains)} domains")
    all_results = optimized_scanner.scan_domains_batch_parallel(domains, scan_options, BRAVE_API_KEY)
    
    # Export individual CSV files for each domain
    completed_domains = 0
    for domain, domain_result in all_results.items():
        if domain_result['status'] == 'completed':
            results = domain_result['results']
            csv_file = f"{domain}.csv"
            csv_path = os.path.join(batch_dir, csv_file)
            
            # Create individual domain CSV file
            with open(csv_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Category', 'Finding', 'Details'])
                
                # Write scan results to CSV
                for record_type, records in results.get('dns_info', {}).items():
                    for record in records:
                        writer.writerow(['DNS Record', record_type, record])
                
                for vuln in results.get('vulnerabilities', []):
                    writer.writerow(['Vulnerability', 
                                   f"{vuln['title']} ({vuln['severity']})", 
                                   vuln['description']])
                
                for sub in results.get('subdomains', []):
                    writer.writerow(['Subdomain', 
                                   sub['subdomain'], 
                                   f"IP: {sub['ip']}, Status: {sub['status']}"])
                
                for related in results.get('related_domains', []):
                    writer.writerow(['Related Domain',
                                   f"{related['domain']} ({related['confidence']})",
                                   f"Type: {related['relation_type']}, Evidence: {related['evidence']}"])
                
                # Write darkweb links
                onion_links = results.get('onion_links', {})
                for link in onion_links.get('interested_links', []):
                    writer.writerow(['Darkweb Link (Interesting)', link, ''])
                for link in onion_links.get('other_links', []):
                    writer.writerow(['Darkweb Link', link, ''])
            
            # Add CSV file reference to result
            all_results[domain]['csv_file'] = csv_file
            completed_domains += 1
    
    # Update batch status in database
    conn = sqlite3.connect('easm.db')
    c = conn.cursor()
    c.execute('''UPDATE batch_scans 
                 SET completed_domains = ?, status = 'completed'
                 WHERE batch_id = ?''',
              (completed_domains, batch_id))
    conn.commit()
    conn.close()
    
    # Save all results to a JSON file
    with open(os.path.join(batch_dir, 'all_results.json'), 'w') as f:
        json.dump(all_results, f)
    
    # Create ZIP file containing all results
    zip_filename = create_batch_zip(batch_id, batch_dir)
    if not zip_filename:
        zip_filename = f'batch_results_{batch_id}.zip'  # fallback name
    
    print(f"Completed optimized batch scan for {len(domains)} domains")
    
    return render_template('batch_complete.html',
                         batch_id=batch_id,
                         results=all_results,
                         total=len(domains),
                         completed=completed_domains,
                         zip_file=zip_filename)

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
            # Create ZIP file containing all results
            zip_filename = create_batch_zip(batch_id, batch_dir)
            if not zip_filename:
                zip_filename = f'batch_results_{batch_id}.zip'  # fallback name
            
            return render_template('batch_complete.html', 
                                batch_id=batch_id, 
                                results=results,
                                total=len(domains),
                                completed=completed,
                                zip_file=zip_filename)
    
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

@batch_scan_bp.route('/batch_progress/<batch_id>')
def batch_progress(batch_id):
    """Return the current progress (completed/total) for a batch scan as JSON."""
    try:
        conn = sqlite3.connect('easm.db')
        c = conn.cursor()
        c.execute('''SELECT completed_domains, total_domains FROM batch_scans WHERE batch_id = ?''', (batch_id,))
        row = c.fetchone()
        conn.close()
        if row:
            completed, total = row
            return jsonify({'completed': completed, 'total': total})
        else:
            return jsonify({'error': 'Batch not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@batch_scan_bp.route('/batch_results/<batch_id>/download')
def download_batch_zip(batch_id):
    """Download the ZIP file for a completed batch scan from the history page."""
    try:
        batch_dir = os.path.join('results', batch_id)
        if not os.path.exists(batch_dir):
            return jsonify({'error': f'Batch {batch_id} not found'}), 404
        
        # Look for the ZIP file in the batch directory
        zip_filename = f'batch_results_{batch_id}.zip'
        zip_path = os.path.join(batch_dir, zip_filename)
        
        if not os.path.exists(zip_path):
            # Try to create the ZIP file if it doesn't exist
            zip_filename = create_batch_zip(batch_id, batch_dir)
            if not zip_filename:
                return jsonify({'error': 'Unable to create or find ZIP file for this batch'}), 404
            zip_path = os.path.join(batch_dir, zip_filename)
        
        # Use absolute path for send_from_directory
        abs_batch_dir = os.path.abspath(batch_dir)
        return send_from_directory(abs_batch_dir, zip_filename, as_attachment=True)
    except Exception as e:
        print(f"Error downloading batch ZIP: {str(e)}")
        return jsonify({'error': f'Error downloading batch ZIP: {str(e)}'}), 500
