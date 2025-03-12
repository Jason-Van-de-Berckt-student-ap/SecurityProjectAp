"""
Enhanced technology detection service for the EASM application.
This module provides WhatRuns-like functionality to detect web technologies.
"""
import requests
from bs4 import BeautifulSoup
import re
import urllib3
from urllib.parse import urlparse

# Suppress only the single InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Expanded vulnerability database
VULNERABILITY_DB = {
    "jQuery": {
        "min_version": "3.6.0",
        "severity": "High",
        "description": "Outdated jQuery version found. Vulnerable to XSS attacks.",
        "cve": ["CVE-2020-11023", "CVE-2020-11022"]
    },
    "WordPress": {
        "min_version": "6.4.3", 
        "severity": "High",
        "description": "Outdated WordPress version. Security updates required.",
        "cve": ["CVE-2023-45132", "CVE-2023-45133"]
    },
    "React": {
        "min_version": "18.2.0",
        "severity": "Medium",
        "description": "Older React version. Potential security and performance issues.",
        "cve": []
    },
    "Bootstrap": {
        "min_version": "5.3.0",
        "severity": "Medium",
        "description": "Outdated Bootstrap version. Security vulnerabilities present.",
        "cve": ["CVE-2023-38286"]
    },
    "Angular": {
        "min_version": "17.0.0",
        "severity": "Medium",
        "description": "Older Angular version detected. Update recommended.",
        "cve": []
    },
    "PHP": {
        "min_version": "8.2.0",
        "severity": "High",
        "description": "Outdated PHP version. Critical security updates missing.",
        "cve": ["CVE-2023-3823", "CVE-2023-0567"]
    },
    "Apache": {
        "min_version": "2.4.58",
        "severity": "High",
        "description": "Outdated Apache server with known vulnerabilities.",
        "cve": ["CVE-2023-45802", "CVE-2023-31122"]
    },
    "Nginx": {
        "min_version": "1.25.3",
        "severity": "Medium",
        "description": "Older Nginx version detected. Security updates recommended.",
        "cve": ["CVE-2023-44487"]
    },
    "Drupal": {
        "min_version": "10.1.2",
        "severity": "High",
        "description": "Outdated Drupal version. Critical security updates missing.",
        "cve": ["CVE-2023-39922"]
    },
    "Laravel": {
        "min_version": "10.0.0",
        "severity": "Medium",
        "description": "Older Laravel framework. Security updates recommended.",
        "cve": []
    },
    "Django": {
        "min_version": "4.2.0",
        "severity": "Medium",
        "description": "Older Django version. Security updates recommended.",
        "cve": ["CVE-2023-41164"]
    },
    "Express.js": {
        "min_version": "4.18.0",
        "severity": "Medium",
        "description": "Outdated Express.js version. Security updates missing.",
        "cve": []
    },
    "ASP.NET": {
        "min_version": "7.0",
        "severity": "Medium",
        "description": "Older ASP.NET version. Security updates recommended.",
        "cve": []
    },
    "Ruby on Rails": {
        "min_version": "7.0.0",
        "severity": "Medium",
        "description": "Older Rails version. Security updates recommended.",
        "cve": []
    },
    "Joomla": {
        "min_version": "4.3.4",
        "severity": "High",
        "description": "Outdated Joomla version. Critical security updates missing.",
        "cve": ["CVE-2023-35168"]
    },
    "Magento": {
        "min_version": "2.4.6",
        "severity": "High",
        "description": "Outdated Magento version. Critical security updates missing.",
        "cve": ["CVE-2022-24124"]
    },
    "OpenSSL": {
        "min_version": "3.0.12",
        "severity": "Critical",
        "description": "Outdated OpenSSL version. Critical vulnerabilities present.",
        "cve": ["CVE-2023-3446", "CVE-2023-0464"]
    }
}

# Technology fingerprints
TECH_FINGERPRINTS = {
    # JavaScript frameworks and libraries
    "react": {
        "patterns": [
            r"react\.production\.min\.js",
            r"react-dom\.production\.min\.js",
            r"__REACT_DEVTOOLS_GLOBAL_HOOK__",
            r"_reactRootContainer",
        ],
        "type": "JavaScript Framework"
    },
    "vue": {
        "patterns": [
            r"vue(@[\d\.]+)?\.js",
            r"vue\.min\.js",
            r"__vue__",
            r"\[\[\"__vue_",
        ],
        "type": "JavaScript Framework"
    },
    "angular": {
        "patterns": [
            r"angular\.js",
            r"angular\.min\.js",
            r"ng-app",
            r"ng-controller",
            r"ng-bind",
            r"angular\.module",
        ],
        "type": "JavaScript Framework"
    },
    "jquery": {
        "patterns": [
            r"jquery-(\d+\.\d+\.\d+)\.js",
            r"jquery\.min\.js",
            r"jquery\.js",
            r"jQuery v",
        ],
        "type": "JavaScript Library"
    },
    "bootstrap": {
        "patterns": [
            r"bootstrap\.min\.css",
            r"bootstrap\.min\.js",
            r"bootstrap\/(\d+\.\d+\.\d+)\/js\/bootstrap",
            r"class=\"navbar navbar-",
            r"class=\"btn btn-",
        ],
        "type": "CSS Framework"
    },
    "tailwind": {
        "patterns": [
            r"tailwind\.css",
            r"tailwindcss",
            r"tailwind\.min\.css",
            r"class=\"(sm:|md:|lg:|xl:|2xl:)?(flex|grid|block|table|hidden)",
        ],
        "type": "CSS Framework"
    },
    # Content Management Systems
    "wordpress": {
        "patterns": [
            r"\/wp-content\/",
            r"\/wp-includes\/",
            r"wp-embed\.min\.js",
            r"\"generator\" content=\"WordPress",
            r"\/plugins\/elementor\/",
        ],
        "type": "CMS"
    },
    "drupal": {
        "patterns": [
            r"drupal\.js",
            r"\/sites\/default\/files\/",
            r"\"generator\" content=\"Drupal",
            r"jQuery\.extend\(Drupal\.settings",
        ],
        "type": "CMS"
    },
    "joomla": {
        "patterns": [
            r"\/media\/jui\/",
            r"\"generator\" content=\"Joomla",
            r"\/media\/system\/js\/core\.js",
        ],
        "type": "CMS"
    },
    # E-commerce platforms
    "shopify": {
        "patterns": [
            r"cdn\.shopify\.com",
            r"shopify\.com\/s\/files\/",
            r"Shopify\.theme",
            r"ShopifyBuy",
        ],
        "type": "E-commerce"
    },
    "magento": {
        "patterns": [
            r"\/skin\/frontend\/",
            r"\/js\/mage\/",
            r"Mage\.Cookies",
            r"\"generator\" content=\"Magento",
        ],
        "type": "E-commerce"
    },
    "woocommerce": {
        "patterns": [
            r"woocommerce",
            r"wc-api",
            r"wc_add_to_cart",
            r"woocommerce-product",
        ],
        "type": "E-commerce"
    },
    # Web servers
    "apache": {
        "patterns": [
            r"Server: Apache\/(\d+\.\d+\.\d+)",
            r"x-powered-by: PHP\/",
        ],
        "header": True,
        "type": "Web Server"
    },
    "nginx": {
        "patterns": [
            r"Server: nginx\/(\d+\.\d+\.\d+)",
        ],
        "header": True,
        "type": "Web Server"
    },
    "iis": {
        "patterns": [
            r"Server: Microsoft-IIS\/(\d+\.\d+)",
        ],
        "header": True,
        "type": "Web Server"
    },
    # Programming languages and frameworks
    "php": {
        "patterns": [
            r"X-Powered-By: PHP\/(\d+\.\d+\.\d+)",
            r"\.php",
        ],
        "header": True,
        "type": "Programming Language"
    },
    "aspnet": {
        "patterns": [
            r"__VIEWSTATE",
            r"__EVENTTARGET",
            r"\.aspx",
            r"ASP\.NET",
            r"X-AspNet-Version",
        ],
        "type": "Web Framework"
    },
    "laravel": {
        "patterns": [
            r"X-XSRF-TOKEN",
            r"laravel_session",
            r"laravel-token",
        ],
        "type": "Web Framework"
    },
    "django": {
        "patterns": [
            r"csrfmiddlewaretoken",
            r"__admin_media_prefix__",
            r"django",
        ],
        "type": "Web Framework"
    },
    "ruby-on-rails": {
        "patterns": [
            r"X-Csrf-Token",
            r"authenticity_token",
            r"ruby",
            r"rails",
        ],
        "type": "Web Framework"
    },
    # Analytics and marketing
    "google-analytics": {
        "patterns": [
            r"google-analytics\.com\/analytics\.js",
            r"gtag\('config'",
            r"GoogleAnalyticsObject",
            r"UA-\d{4,10}-\d{1,4}",
            r"G-[A-Z0-9]{10}",
        ],
        "type": "Analytics"
    },
    "google-tag-manager": {
        "patterns": [
            r"googletagmanager\.com\/gtm\.js",
            r"GTM-[A-Z0-9]{5,7}",
        ],
        "type": "Analytics"
    },
    "hotjar": {
        "patterns": [
            r"static\.hotjar\.com",
            r"hotjar",
            r"_hjSettings",
        ],
        "type": "Analytics"
    },
    # Payment systems
    "stripe": {
        "patterns": [
            r"js\.stripe\.com",
            r"Stripe\(",
            r"stripe-button",
        ],
        "type": "Payment"
    },
    "paypal": {
        "patterns": [
            r"paypal\.com\/sdk",
            r"paypalobjects",
        ],
        "type": "Payment"
    },
    # CDNs and hosting
    "cloudflare": {
        "patterns": [
            r"cf-ray",
            r"cloudflare",
            r"__cfduid",
        ],
        "header": True,
        "type": "CDN"
    },
    "aws": {
        "patterns": [
            r"amazonaws\.com",
            r"aws-region",
        ],
        "type": "Hosting"
    },
    "netlify": {
        "patterns": [
            r"netlify",
            r"x-nf-request-id",
        ],
        "header": True,
        "type": "Hosting"
    },
    "vercel": {
        "patterns": [
            r"vercel\.com",
            r"x-vercel-",
        ],
        "header": True,
        "type": "Hosting"
    },
    # Security
    "recaptcha": {
        "patterns": [
            r"www\.google\.com\/recaptcha\/",
            r"grecaptcha",
        ],
        "type": "Security"
    },
    "hcaptcha": {
        "patterns": [
            r"hcaptcha\.com\/",
            r"hcaptcha",
        ],
        "type": "Security"
    },
    "cloudflare-bot-management": {
        "patterns": [
            r"turnstile\.cloudflare\.com",
            r"cf_chl_",
        ],
        "type": "Security"
    },
    # Font services
    "google-fonts": {
        "patterns": [
            r"fonts\.googleapis\.com",
            r"fonts\.gstatic\.com",
        ],
        "type": "Fonts"
    },
    "fontawesome": {
        "patterns": [
            r"fontawesome",
            r"fa-",
            r"fa\s",
            r"\.fa\{",
        ],
        "type": "Fonts"
    },
    # JavaScript utilities
    "lodash": {
        "patterns": [
            r"lodash\.min\.js",
            r"lodash\.js",
            r"lodash@",
        ],
        "type": "JavaScript Library"
    },
    "moment-js": {
        "patterns": [
            r"moment\.min\.js",
            r"moment\.js",
            r"moment@",
        ],
        "type": "JavaScript Library"
    },
    "gsap": {
        "patterns": [
            r"gsap",
            r"TweenMax",
            r"ScrollTrigger",
        ],
        "type": "Animation Library"
    },
    # Mobile frameworks
    "react-native": {
        "patterns": [
            r"react-native",
            r"ReactNative",
        ],
        "type": "Mobile Framework"
    },
    # State management
    "redux": {
        "patterns": [
            r"redux",
            r"createStore",
        ],
        "type": "State Management"
    },
}

def normalize_version(version):
    """
    Normalize version strings for comparison.
    
    Args:
        version (str): Raw version string
        
    Returns:
        str: Normalized version string
    """
    # Strip 'v' prefix if present
    if version.startswith('v'):
        version = version[1:]
    
    # Replace any non-numeric/non-dot characters with dots
    version = re.sub(r'[^\d.]', '.', version)
    
    # Split by dots and take up to 3 parts
    parts = version.split('.')[:3]
    
    # Ensure we have at least 3 parts (adding zeros if necessary)
    while len(parts) < 3:
        parts.append('0')
    
    # Join with dots
    return '.'.join(parts)

def compare_versions(version1, version2):
    """
    Compare two version strings.
    
    Args:
        version1 (str): First version string
        version2 (str): Second version string
        
    Returns:
        int: -1 if version1 < version2, 0 if equal, 1 if version1 > version2
    """
    # Handle empty strings or None values
    if not version1 or version1 == "unknown":
        version1 = "0.0.0"
    if not version2 or version2 == "unknown":
        version2 = "0.0.0"
    
    v1 = normalize_version(version1)
    v2 = normalize_version(version2)
    
    try:
        v1_parts = [int(x) for x in v1.split('.')]
        v2_parts = [int(x) for x in v2.split('.')]
    except ValueError:
        # If conversion to int fails, treat as 0.0.0
        v1_parts = [0, 0, 0]
        v2_parts = [0, 0, 0]
    
    for i in range(max(len(v1_parts), len(v2_parts))):
        v1_part = v1_parts[i] if i < len(v1_parts) else 0
        v2_part = v2_parts[i] if i < len(v2_parts) else 0
        
        if v1_part < v2_part:
            return -1
        elif v1_part > v2_part:
            return 1
    
    return 0

def extract_version(text, technology_name=None):
    """
    Extract version numbers from text with technology-specific patterns.
    
    Args:
        text (str): Text to extract version from
        technology_name (str, optional): Name of technology to use specific patterns
        
    Returns:
        str: Extracted version or "unknown"
    """
    # Technology-specific patterns
    tech_patterns = {
        "WordPress": r'WordPress (\d+\.\d+\.\d+)',
        "jQuery": r'jQuery v?(\d+\.\d+\.\d+)',
        "Bootstrap": r'bootstrap[/-](\d+\.\d+\.\d+)',
        "React": r'react@?(\d+\.\d+\.\d+)',
        "Angular": r'angular[/-](\d+\.\d+\.\d+)',
        "Vue": r'vue@?(\d+\.\d+\.\d+)',
    }
    
    # Try technology-specific pattern first
    if technology_name and technology_name in tech_patterns:
        match = re.search(tech_patterns[technology_name], text)
        if match:
            return match.group(1)
    
    # General patterns
    patterns = [
        r'v?(\d+\.\d+\.\d+(-\w+)?)',  # Matches v1.2.3 or 1.2.3-beta
        r'(\d{4}-\d{2}-\d{2})',       # Matches dates like 2023-01-01
        r'(\d+\.\d+\.\d+)',           # Matches 1.2.3
        r'(\d+\.\d+)',                # Matches 1.2
    ]
    
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    
    return "unknown"

def get_headers_fingerprint(headers):
    """
    Extract technology information from HTTP headers.
    
    Args:
        headers (dict): HTTP response headers
        
    Returns:
        dict: Detected technologies from headers
    """
    technologies = {}
    
    # Check for server header
    server = headers.get('Server', '')
    if server:
        # Apache
        apache_match = re.search(r'Apache/(\d+\.\d+\.\d+)', server)
        if apache_match:
            technologies['Apache'] = apache_match.group(1)
        
        # Nginx
        nginx_match = re.search(r'nginx/(\d+\.\d+\.\d+)', server)
        if nginx_match:
            technologies['Nginx'] = nginx_match.group(1)
        
        # Microsoft IIS
        iis_match = re.search(r'Microsoft-IIS/(\d+\.\d+)', server)
        if iis_match:
            technologies['Microsoft IIS'] = iis_match.group(1)
    
    # Check for X-Powered-By header
    powered_by = headers.get('X-Powered-By', '')
    if powered_by:
        # PHP
        php_match = re.search(r'PHP/(\d+\.\d+\.\d+)', powered_by)
        if php_match:
            technologies['PHP'] = php_match.group(1)
        
        # ASP.NET
        aspnet_match = re.search(r'ASP\.NET', powered_by)
        if aspnet_match:
            technologies['ASP.NET'] = extract_version(powered_by)
    
    # Check for CloudFlare
    if 'CF-Ray' in headers:
        technologies['CloudFlare'] = "Detected"
    
    # Check for security headers
    security_headers = {
        'Strict-Transport-Security': 'HSTS',
        'Content-Security-Policy': 'CSP',
        'X-Content-Type-Options': 'X-Content-Type-Options',
        'X-XSS-Protection': 'XSS Protection',
        'X-Frame-Options': 'X-Frame-Options'
    }
    
    for header, tech in security_headers.items():
        if header in headers:
            technologies[tech] = "Enabled"
    
    return technologies

def get_cookie_fingerprint(cookies):
    print("Namijken van cookies")
    """
    Extract technology information from cookies.
    
    Args:
        cookies (dict or RequestsCookieJar): HTTP response cookies
        
    Returns:
        dict: Detected technologies from cookies
    """
    technologies = {}
    
    cookie_patterns = {
        r'PHPSESSID': 'PHP',
        r'_shopify': 'Shopify',
        r'PrestaShop': 'PrestaShop',
        r'wp-': 'WordPress',
        r'laravel_session': 'Laravel',
        r'JSESSIONID': 'Java',
        r'ASP.NET_SessionId': 'ASP.NET',
        r'_ga': 'Google Analytics',
        r'_fbp': 'Facebook Pixel',
        r'_hjSession': 'Hotjar',
    }
    
    # Convert RequestsCookieJar to a dictionary if needed
    if not isinstance(cookies, dict):
        # Try to access as dictionary
        try:
            cookie_dict = dict(cookies)
        except:
            # Handle the case where cookies cannot be converted to dict
            try:
                cookie_dict = {k: v for k, v in cookies.items()}
            except:
                # If all conversions fail, return empty dict
                print("Could not process cookies")
                return technologies
    else:
        cookie_dict = cookies
    
    # Now process the cookies dictionary
    for cookie_name in cookie_dict:
        for pattern, tech in cookie_patterns.items():
            if re.search(pattern, cookie_name, re.IGNORECASE):
                technologies[tech] = "Detected (via cookie)"
    
    return technologies

def extract_technologies_from_html(html_content, url):
    print("extract technologies from html")
    """
    Extract technologies from HTML content.
    
    Args:
        html_content (str): HTML content
        url (str): URL of the page
        
    Returns:
        dict: Detected technologies
    """
    technologies = {}
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Extract from meta tags
    for meta in soup.find_all('meta'):
        name = meta.get('name', '').lower()
        content = meta.get('content', '')
        
        if name == 'generator':
            if 'WordPress' in content:
                version = re.search(r'WordPress (\d+\.\d+\.\d+)', content)
                technologies["WordPress"] = version.group(1) if version else "Detected"
            
            if 'Drupal' in content:
                version = re.search(r'Drupal (\d+\.\d+\.\d+)', content)
                technologies["Drupal"] = version.group(1) if version else "Detected"
            
            if 'Joomla' in content:
                version = re.search(r'Joomla! (\d+\.\d+\.\d+)', content)
                technologies["Joomla"] = version.group(1) if version else "Detected"
            
            if 'Shopify' in content:
                technologies["Shopify"] = "Detected"
    
    # Extract from script tags
    for script in soup.find_all('script'):
        src = script.get('src', '')
        script_content = script.string if script.string else ''
        
        # Check for jQuery
        if 'jquery' in src.lower():
            jquery_version = extract_version(src, "jQuery")
            if jquery_version != "unknown":
                technologies["jQuery"] = jquery_version
        
        # Check for React
        if 'react' in src.lower():
            react_version = extract_version(src, "React")
            if react_version != "unknown":
                technologies["React"] = react_version
        
        # Check for Vue.js
        if 'vue' in src.lower():
            vue_version = extract_version(src, "Vue")
            if vue_version != "unknown":
                technologies["Vue.js"] = vue_version
        
        # Check for Angular
        if 'angular' in src.lower():
            angular_version = extract_version(src, "Angular")
            if angular_version != "unknown":
                technologies["Angular"] = angular_version
        
        # Check for Bootstrap
        if 'bootstrap' in src.lower():
            bootstrap_version = extract_version(src, "Bootstrap")
            if bootstrap_version != "unknown":
                technologies["Bootstrap"] = bootstrap_version
        
        # Check script content for fingerprints
        if script_content:
            if 'wp-content' in script_content or 'wp-includes' in script_content:
                if "WordPress" not in technologies:
                    technologies["WordPress"] = "Detected"
            
            if 'Shopify' in script_content:
                if "Shopify" not in technologies:
                    technologies["Shopify"] = "Detected"
    
    # Check for CSS frameworks in stylesheets
    for link in soup.find_all('link', rel='stylesheet'):
        href = link.get('href', '')
        
        if 'bootstrap' in href.lower():
            bootstrap_version = extract_version(href, "Bootstrap")
            if bootstrap_version != "unknown" and "Bootstrap" not in technologies:
                technologies["Bootstrap"] = bootstrap_version
        
        if 'tailwind' in href.lower():
            if "Tailwind CSS" not in technologies:
                technologies["Tailwind CSS"] = "Detected"
    
    # Check for common patterns in the entire HTML
    for tech_name, tech_info in TECH_FINGERPRINTS.items():
        if "header" in tech_info and tech_info["header"]:
            continue  # Skip header-based technologies
        
        tech_found = False
        for pattern in tech_info["patterns"]:
            if re.search(pattern, html_content, re.IGNORECASE):
                tech_found = True
                break
        
        if tech_found:
            # Try to extract a version if not already found
            if tech_name.title() not in technologies:
                version = "Detected"
                # Look for version in scripts, especially for JS frameworks
                for script in soup.find_all('script'):
                    src = script.get('src', '')
                    if tech_name.lower() in src.lower():
                        extracted_version = extract_version(src, tech_name.title())
                        if extracted_version != "unknown":
                            version = extracted_version
                            break
                
                technologies[tech_name.title().replace('-', ' ')] = version
    
    return technologies

def analyze_vulnerabilities(tech_data):
    print("Analyseren van zwakheden.")
    """
    Analyze vulnerabilities based on detected technologies.
    
    Args:
        tech_data (dict): Dictionary of detected technologies
        
    Returns:
        list: List of vulnerability dictionaries
    """
    vulnerabilities = []
    
    for tech, version in tech_data.items():
        if tech in VULNERABILITY_DB:
            db_entry = VULNERABILITY_DB[tech]
            
            # Skip if version is not detected or is just "Detected"
            if version == "unknown" or version == "Detected" or not version:
                vulnerabilities.append({
                    "title": f"{tech} Detected",
                    "description": f"Version information unavailable. Latest recommended: {db_entry['min_version']}+",
                    "severity": "Info" 
                })
                continue
            
            try:
                if compare_versions(version, db_entry["min_version"]) < 0:
                    cve_list = ""
                    if "cve" in db_entry and db_entry["cve"]:
                        cve_list = " Associated CVEs: " + ", ".join(db_entry["cve"])
                        
                    vulnerabilities.append({
                        "title": f"Outdated {tech} Version",
                        "description": f"{db_entry['description']} Detected: {version}, Required: {db_entry['min_version']}+.{cve_list}",
                        "severity": db_entry["severity"]
                    })
                else:
                    vulnerabilities.append({
                        "title": f"{tech} {version}",
                        "description": f"Current version is up to date (minimum recommended: {db_entry['min_version']})",
                        "severity": "Info"
                    })
            except Exception as e:
                print(f"Error comparing versions for {tech}: {str(e)}")
                vulnerabilities.append({
                    "title": f"{tech} {version}",
                    "description": f"Error analyzing version. Latest recommended: {db_entry['min_version']}+",
                    "severity": "Info"
                })
        else:
            # For technologies not in our vulnerability database
            vulnerabilities.append({
                "title": f"{tech} {version}",
                "description": "Technology detected but not in vulnerability database",
                "severity": "Info"
            })
    
    # Check for missing security headers
    if "HSTS" not in tech_data:
        vulnerabilities.append({
            "title": "Missing HSTS Header",
            "description": "Strict-Transport-Security header not set. This site may be vulnerable to protocol downgrade attacks.",
            "severity": "Medium"
        })
    
    if "CSP" not in tech_data:
        vulnerabilities.append({
            "title": "Missing Content Security Policy",
            "description": "No Content-Security-Policy header found. This can increase risk of XSS attacks.",
            "severity": "Medium"
        })
    
    if "X-Content-Type-Options" not in tech_data:
        vulnerabilities.append({
            "title": "Missing X-Content-Type-Options Header",
            "description": "X-Content-Type-Options header not set. This can lead to MIME-type sniffing vulnerabilities.",
            "severity": "Low"
        })
    
    return vulnerabilities

def categorize_technologies(tech_data):
    print("Sorteren van technologieën")
    """
    Categorize detected technologies by type.
    
    Args:
        tech_data (dict): Dictionary of detected technologies
        
    Returns:
        dict: Technologies categorized by type
    """
    categorized = {
        "Web Frameworks": {},
        "JavaScript Libraries": {},
        "CMS": {},
        "E-commerce": {},
        "Web Servers": {},
        "Programming Languages": {},
        "Analytics": {},
        "Security": {},
        "Hosting/CDN": {},
        "Other": {}
    }
    
    # Map technologies to categories based on TECH_FINGERPRINTS
    category_map = {}
    for tech_name, tech_info in TECH_FINGERPRINTS.items():
        category = tech_info.get("type", "Other")
        category_map[tech_name.title().replace('-', ' ')] = category
    
    # Manually add common technologies not covered by fingerprints
    additional_mapping = {
        "PHP": "Programming Languages",
        "ASP.NET": "Web Frameworks",
        "HSTS": "Security",
        "CSP": "Security",
        "X-Content-Type-Options": "Security",
        "XSS Protection": "Security",
        "X-Frame-Options": "Security",
        "React": "JavaScript Libraries",
        "Vue.js": "JavaScript Libraries",
        "Angular": "JavaScript Libraries",
        "jQuery": "JavaScript Libraries",
        "Bootstrap": "Web Frameworks",
        "Tailwind CSS": "Web Frameworks",
        "WordPress": "CMS",
        "Drupal": "CMS",
        "Joomla": "CMS",
        "Magento": "E-commerce",
        "Shopify": "E-commerce",
        "WooCommerce": "E-commerce",
        "Google Analytics": "Analytics",
        "Hotjar": "Analytics",
        "Cloudflare": "Hosting/CDN",
        "Nginx": "Web Servers",
        "Apache": "Web Servers",
        "Microsoft IIS": "Web Servers",
    }

# Add these main functions at the end of your tech_detection_enhanced.py file

def get_website_technologies(domain):
    print("Web pagina technologieën ophalen")
    """
    Main function to detect technologies used on a website.
    
    Args:
        domain (str): Domain name to scan
        
    Returns:
        dict: Dictionary containing detected technologies and categorized results
    """
    # Normalize domain
    domain = domain.strip().lower()
    if domain.startswith(('http://', 'https://')):
        parsed = urlparse(domain)
        domain = parsed.netloc
    elif domain.startswith('www.'):
        domain = domain[4:]
    
    technologies = {}
    headers_detected = {}
    cookies_detected = {}
    html_detected = {}
    
    try:
        # Try HTTPS first
        try:
            response = requests.get(f'https://{domain}', 
                                   headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
                                   timeout=10, 
                                   verify=False,
                                   allow_redirects=True)
        except requests.exceptions.RequestException:
            # Fall back to HTTP if HTTPS fails
            response = requests.get(f'http://{domain}', 
                                   headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'},
                                   timeout=10,
                                   allow_redirects=True)
        
        # Extract technologies from headers
        headers_detected = get_headers_fingerprint(response.headers)
        
        # Extract technologies from cookies
        cookies_detected = get_cookie_fingerprint(response.cookies)
        
        # Extract technologies from HTML content
        html_detected = extract_technologies_from_html(response.text, domain)
        
        # Combine all detected technologies, prioritizing more specific version information
        for tech_dict in [html_detected, cookies_detected, headers_detected]:
            for tech, version in tech_dict.items():
                if tech not in technologies or technologies[tech] == "Detected" or technologies[tech] == "unknown":
                    technologies[tech] = version
        
        # Categorize detected technologies
        categorized = categorize_technologies(technologies)
        
        return {
            "raw_technologies": technologies,
            "categorized": categorized
        }
        
    except Exception as e:
        print(f"Error scanning technologies for {domain}: {str(e)}")
        return {
            "raw_technologies": {},
            "categorized": {},
            "error": str(e)
        }

def check_tech_vulnerabilities(domain):
    print("Nakijken van zwakheden.")
    """
    Check for vulnerabilities based on detected technologies.
    
    Args:
        domain (str): Domain name to scan
        
    Returns:
        list: List of vulnerability dictionaries
    """
    try:
        # Get technologies used on the website
        tech_data = get_website_technologies(domain)
        
        # If there was an error in technology detection
        if "error" in tech_data:
            return [{
                "title": "Technology Detection Error",
                "description": f"Error scanning technologies: {tech_data['error']}",
                "severity": "Unknown"
            }]
        
        # Analyze vulnerabilities based on detected technologies
        vulnerabilities = analyze_vulnerabilities(tech_data["raw_technologies"])
        
        # If no specific vulnerabilities were found
        if not vulnerabilities:
            vulnerabilities.append({
                "title": "No Technology Vulnerabilities Detected",
                "description": "No known vulnerable technologies were detected. This doesn't guarantee the absence of vulnerabilities.",
                "severity": "Info"
            })
        
        # Return results
        return vulnerabilities
        
    except Exception as e:
        print(f"Error checking technology vulnerabilities for {domain}: {str(e)}")
        return [{
            "title": "Scan Error",
            "description": f"Error during vulnerability scan: {str(e)}",
            "severity": "Unknown"
        }]