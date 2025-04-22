"""
Technology detection service for the EASM application.
This integrates the enhanced technology detection capabilities.
"""
import ast
import datetime
import time
import json
import sys
import requests
import urllib.parse
from tabulate import tabulate

def scan_website_technologies(domain):
    """Scan a domain for technologies using WhatRuns API."""
    url = "https://www.whatruns.com/api/v1/get_site_apps"
    data = {"data": {"hostname": domain, "url": domain, "rawhostname": domain}}
    data = urllib.parse.urlencode({k: json.dumps(v) for k, v in data.items()})
    data = data.replace('+', '')
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    try:
        response = requests.post(url, data=data, headers=headers)
        loaded = json.loads(response.content)
        
        # Debug output
        print("API Response:", loaded)
        
        # Check if 'apps' key exists and has content
        if 'apps' not in loaded or not loaded['apps']:
            print(f"Error: No 'apps' data found for {domain}")
            return []
            
        # Parse apps data - it's a JSON string that needs to be parsed
        try:
            apps = json.loads(loaded['apps'])
        except json.JSONDecodeError as e:
            print(f"Error parsing apps JSON: {e}")
            return []
        
        # Check if apps dictionary is empty
        if not apps:
            print(f"No technology data found for {domain}")
            return []
        
        # Get the first key from apps
        try:
            app_keys = list(apps.keys())
            if not app_keys:  # Check if the list is empty
                print(f"No app keys found for {domain}")
                return []
            nuance = app_keys[0]  # Get the first key without removing it
        except Exception as e:
            print(f"Error accessing app keys: {e}")
            return []

        entries = []
        try:
            for app_type, values in apps[nuance].items():
                if not values:  # Skip empty lists
                    continue
                    
                for item in values:
                    # Safe conversion of timestamps with error handling
                    try:
                        dt = datetime.datetime.fromtimestamp((item['detectedTime']/1000))
                        ldt = datetime.datetime.fromtimestamp((item['latestDetectedTime']/1000))
                    except (KeyError, TypeError) as e:
                        print(f"Error processing timestamps: {e}")
                        dt = ldt = datetime.datetime.now()
                        
                    version = item.get('version', 'N/A')
                    name = item.get('name', 'Unknown')
                    
                    entries.append({
                        'Type': app_type, 
                        'Name': name,
                        'Detected': dt, 
                        'Last_Detected': ldt, 
                        'Version': version
                    })
                    print(f"Detected {app_type}: {name} (version: {version})")
        except Exception as e:
            print(f"Error processing app data: {e}")
        
        # Final verification
        if not entries:
            print("No technologies detected after processing")
        else:
            print(f"Successfully detected {len(entries)} technologies")
            
        return entries
    except Exception as e:
        print(f"Error in scan_website_technologies: {e}")
        return []

def search_nvd_by_technology(api_key, technology, version=None, max_results=100):
    """Search NVD database for vulnerabilities related to a specific technology."""
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Check for missing version information
    if not version or version == 'N/A':
        warning_vuln = {
            "cve": {
                "id": "VERSION_UNKNOWN",
                "descriptions": [{
                    "lang": "en",
                    "value": f"WARNING: No version information available for {technology}. "
                            f"This technology may have known vulnerabilities, but without version information, "
                            f"specific vulnerabilities cannot be determined. Please identify the version for a complete security assessment."
                }],
                "published": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                "lastModified": datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
            },
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": "UNKNOWN",
                        "baseSeverity": "UNKNOWN"
                    }
                }]
            }
        }
        print(f"\nWARNING: No version information available for {technology}")
        return [warning_vuln]
    
    all_vulnerabilities = []
    start_index = 0
    results_per_page = 20  # NVD API default
    
    # Refine search to include version if available
    search_term = f"{technology} {version}"
    
    print(f"\nSearching NVD for: {search_term}")
    
    while len(all_vulnerabilities) < max_results:
        print(f"\n=== Making request (start_index: {start_index}) ===")
        
        # Set up request parameters
        params = {
            "keywordSearch": search_term,
            "resultsPerPage": min(results_per_page, max_results - len(all_vulnerabilities)),
            "startIndex": start_index
        }

        # Set up headers with API key
        headers = {
            'Accept': 'application/json',
            'apiKey': api_key
        }

        try:
            print("Making API request...")
            response = requests.get(base_url, params=params, headers=headers)
            
            print(f"API Response Status Code: {response.status_code}")
            print(f"API Response Headers: {dict(response.headers)}")
            
            # Check for rate limiting (403) or other errors
            if response.status_code == 403:
                print("Rate limit reached. Waiting 30 seconds...")
                print(f"Response Text: {response.text}")
                time.sleep(30)
                continue
            elif response.status_code == 404:
                print(f"No vulnerabilities found for {search_term}")
                break
            elif response.status_code != 200:
                print(f"Error: {response.status_code}")
                print(f"Response Text: {response.text}")
                break
                
            # Parse the response
            print("\nParsing API response...")
            data = response.json()
            
            # Print full API response for debugging
            print("\nFull API Response:")
            print(json.dumps(data, indent=2))
            
            vulnerabilities = data.get("vulnerabilities", [])
            total_results = data.get("totalResults", 0)
            
            print(f"Found {total_results} total results, retrieved {len(vulnerabilities)} vulnerabilities")
            
            # If no more results, break the loop
            if not vulnerabilities:
                break

            # Add vulnerabilities to list
            all_vulnerabilities.extend(vulnerabilities)
            
            # Update start_index for the next page
            start_index += len(vulnerabilities)
            
            # If we've fetched all available results, break
            if start_index >= total_results:
                break
                
            # Polite delay to avoid hitting rate limits
            time.sleep(0.6)  # ~50 requests per 30 seconds
            
        except Exception as e:
            print(f"An error occurred: {e}")
            print(f"Exception type: {type(e).__name__}")
            break
    
    print(f"\n=== Search Complete ===")
    print(f"Total vulnerabilities found: {len(all_vulnerabilities)}")
    return all_vulnerabilities

def extract_vulnerability_info(vuln):
    """Extract relevant information from a vulnerability entry."""
    cve = vuln.get("cve", {})
    
    # Extract CVE ID
    cve_id = cve.get("id", "Unknown")
    
    # Extract description
    descriptions = cve.get("descriptions", [])
    description = "No description available"
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value", "No description available")
            break
    
    # Extract published and modified dates
    published = cve.get("published", "Unknown")
    lastModified = cve.get("lastModified", "Unknown")
    
    # Extract CVSS scores
    metrics = cve.get("metrics", {})
    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0] if "cvssMetricV31" in metrics and metrics["cvssMetricV31"] else \
              metrics.get("cvssMetricV30", [{}])[0] if "cvssMetricV30" in metrics and metrics["cvssMetricV30"] else {}
    
    base_score = cvss_v3.get("cvssData", {}).get("baseScore", "N/A") if cvss_v3 else "N/A"
    severity = cvss_v3.get("cvssData", {}).get("baseSeverity", "N/A") if cvss_v3 else "N/A"
    
    return {
        "cve_id": cve_id,
        "description": description,
        "published": published,
        "lastModified": lastModified,
        "base_score": base_score,
        "severity": severity
    }

def integrate_tech_vulnerabilities(domain, api_key, max_results=100):
    """Scan a domain for technologies and check them against NVD for vulnerabilities."""
    print(f"Scanning {domain} for technologies...")
    entries = scan_website_technologies(domain)
    
    if not entries:
        return {"status": "error", "message": f"No technologies detected for {domain}"}
    
    all_vulnerabilities = {}
    
    # Process each technology
    for entry in entries:
        tech_name = entry['Name']
        tech_version = entry['Version']
        
        print(f"Scanning {tech_name} (version: {tech_version}) for vulnerabilities...")
        
        # Search NVD for vulnerabilities
        vulnerabilities = search_nvd_by_technology(api_key, tech_name, tech_version, max_results)
        
        if vulnerabilities:
            # Process and extract relevant vulnerability information
            vuln_info = [extract_vulnerability_info(vuln) for vuln in vulnerabilities]
            all_vulnerabilities[f"{tech_name} {tech_version}"] = vuln_info
            print(f"Found {len(vuln_info)} vulnerabilities for {tech_name} {tech_version}")
        else:
            all_vulnerabilities[f"{tech_name} {tech_version}"] = []
            print(f"No vulnerabilities found for {tech_name} {tech_version}")
            
        # Be nice to the NVD API
        time.sleep(1)
    
    return {
        "status": "success",
        "domain": domain,
        "technologies_count": len(entries),
        "technologies": entries,
        "vulnerabilities": all_vulnerabilities
    }

def format_results(results):
    """Format the scan results for display."""
    if results.get("status") == "error":
        return results.get("message")
    
    output = [f"Domain: {results.get('domain')}"]
    output.append(f"Detected {results.get('technologies_count')} technologies")
    output.append("\nTECHNOLOGIES DETECTED:")
    
    # Format technologies table
    tech_data = []
    for tech in results.get("technologies", []):
        try:
            tech_data.append([
                tech.get("Type", "Unknown"), 
                tech.get("Name", "Unknown"), 
                tech.get("Version", "N/A"),
                tech.get("Last_Detected").strftime("%Y-%m-%d") if tech.get("Last_Detected") else "Unknown"
            ])
        except Exception as e:
            print(f"Error formatting tech data: {e}")
            tech_data.append(["Error", "Error", "Error", "Error"])
    
    headers = ["Type", "Technology", "Version", "Last Detected"]
    output.append(tabulate(tech_data, headers=headers, tablefmt="grid"))
    
    # Format vulnerabilities
    output.append("\nVULNERABILITIES:")
    for tech, vulns in results.get("vulnerabilities", {}).items():
        output.append(f"\n{tech} - {len(vulns)} vulnerabilities found")
        
        if not vulns:
            output.append("  No vulnerabilities found")
            continue
            
        # Sort vulnerabilities by severity/score
        try:
            vulns.sort(key=lambda x: float(x.get("base_score")) if x.get("base_score") != "N/A" else 0, reverse=True)
        except Exception as e:
            print(f"Error sorting vulnerabilities: {e}")
        
        vuln_data = []
        for vuln in vulns:
            try:
                vuln_data.append([
                    vuln.get("cve_id", "Unknown"),
                    vuln.get("severity", "N/A"),
                    vuln.get("base_score", "N/A"),
                    vuln.get("published", "Unknown")[:10] if vuln.get("published") and vuln.get("published") != "Unknown" else "Unknown",
                    (vuln.get("description", "")[:100] + "...") if vuln.get("description") and len(vuln.get("description", "")) > 100 else vuln.get("description", "")
                ])
            except Exception as e:
                print(f"Error formatting vulnerability data: {e}")
                vuln_data.append(["Error", "Error", "Error", "Error", "Error"])
        
        vuln_headers = ["CVE ID", "Severity", "Score", "Published", "Description"]
        output.append(tabulate(vuln_data, headers=vuln_headers, tablefmt="grid"))
    
    return "\n".join(output)