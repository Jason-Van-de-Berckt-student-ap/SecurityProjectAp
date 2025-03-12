"""
Technology detection routes for the EASM application.
"""
from flask import Blueprint, render_template, request, jsonify
from services.tech_detection_service import scan_website_technologies, get_technology_vulnerabilities

# Create blueprint
tech_detection_bp = Blueprint('tech_detection', __name__)

@tech_detection_bp.route('/tech_detection', methods=['GET'])
def tech_detection():
    """Scan a domain for technologies and display results."""
    domain = request.args.get('domain', '')
    
    if not domain:
        return jsonify({'error': 'Domain parameter is required'}), 400
    
    try:
        # Get technology data
        tech_data = scan_website_technologies(domain)
        
        # Get vulnerability data specific to technologies
        vulnerabilities = get_technology_vulnerabilities(domain)
        
        # Render template with results
        return render_template('technology_detection.html',
                             domain=domain,
                             tech_data=tech_data,
                             vulnerabilities=vulnerabilities)
    except Exception as e:
        return render_template('technology_detection.html',
                             domain=domain,
                             error=str(e))

@tech_detection_bp.route('/api/tech_detection', methods=['GET'])
def tech_detection_api():
    """API endpoint to get technology data for a domain."""
    domain = request.args.get('domain', '')
    
    if not domain:
        return jsonify({'error': 'Domain parameter is required'}), 400
    
    try:
        # Get technology data
        tech_data = scan_website_technologies(domain)
        
        # Get vulnerability data specific to technologies
        vulnerabilities = get_technology_vulnerabilities(domain)
        
        # Return JSON response
        return jsonify({
            'domain': domain,
            'technology_data': tech_data,
            'vulnerabilities': vulnerabilities
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500