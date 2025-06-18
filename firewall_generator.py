import json
import os
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(filename=os.path.join("logs", "analysis_log.db"),
                    level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

def generate_firewall_rules(static_data, dynamic_data, output_path):
    """Generate Windows firewall rules from static and dynamic analysis data."""
    try:
        # Extract static IOCs
        static_iocs = static_data.get("iocs", {})
        static_ips = list(set(static_iocs.get("ips", [])))
        static_urls = static_iocs.get("urls", [])

        # Extract dynamic IOCs
        dynamic_network = dynamic_data.get("network", {})
        dynamic_ips = list(set(dynamic_network.get("ips", [])))
        dynamic_urls = dynamic_network.get("dns_requests", [])

        # Combine and deduplicate
        all_ips = list(set(static_ips + dynamic_ips))
        all_urls = list(set(static_urls + dynamic_urls))

        if not all_ips and not all_urls:
            return {"success": False, "error": "No IPs or URLs found to generate firewall rules"}

        # Prepare firewall rules in Windows format
        rules = [
            f"# Windows Firewall Rules for {static_data.get('filename', 'Unknown')} - Generated on {datetime.now().strftime('%Y-%m-%d')}",
            "# Block outbound traffic to known malicious IPs using netsh advfirewall"
        ]

        for i, ip in enumerate(all_ips, 1):
            rules.append(f'netsh advfirewall firewall add rule name="Block Malicious IP{i} ({ip})" dir=out action=block remoteip={ip}')

        if all_urls:
            rules.append("\n# Suggested DNS Sinkholing (manual configuration or enterprise DNS filtering):")
            for url in all_urls:
                rules.append(f'# Block domain: {url}')
                rules.append(f'# Suggestion: Redirect {url} to 127.0.0.1 using your DNS configuration')

        # Write to file
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            f.write("\n".join(rules))
        os.chmod(output_path, 0o777)
        logging.info(f"Windows firewall rules generated: {output_path}")
        return {"success": True, "output_file": output_path}
    except Exception as e:
        logging.error(f"Firewall rule generation failed: {str(e)}")
        return {"success": False, "error": str(e)}

def generate_firewall(static_analysis_file, dynamic_analysis_file):
    """Generate Windows firewall rules from static and dynamic analysis JSON."""
    try:
        with open(static_analysis_file, "r") as f:
            static_data = json.load(f)
        with open(dynamic_analysis_file, "r") as f:
            dynamic_data = json.load(f)
        output_path = os.path.join("firewall_rules", "firewall_rules.txt")
        return generate_firewall_rules(static_data, dynamic_data, output_path)
    except Exception as e:
        logging.error(f"Firewall generation failed: {str(e)}")
        return {"success": False, "error": str(e)}

if __name__ == "__main__":
    static_analysis_file = os.path.join("output", "sample_analysis.json")
    dynamic_analysis_file = os.path.join("output", "sample_dynamic.json")
    result = generate_firewall(static_analysis_file, dynamic_analysis_file)
    if result["success"]:
        print(f"Firewall rules generated: {result['output_file']}")
    else:
        print(f"Error: {result['error']}")