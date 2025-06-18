import json
import os
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(filename=os.path.join("logs", "analysis_log.db"),
                    level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

def generate_firewall_rules(static_data, dynamic_data, output_path):
    """Generate concise firewall rules from static and dynamic analysis data."""
    try:
        # Extract static IOCs
        static_iocs = static_data.get("iocs", {})
        static_ips = list(set(static_iocs.get("ips", [])))
        static_urls = static_iocs.get("urls", [])

        # Extract dynamic IOCs
        dynamic_network = dynamic_data.get("network", {})
        dynamic_ips = list(set(dynamic_network.get("ips", [])))
        dynamic_urls = dynamic_network.get("dns_requests", [])

        # Combine and deduplicate IPs and URLs
        all_ips = list(set(static_ips + dynamic_ips))
        all_urls = list(set(static_urls + dynamic_urls))
        if not all_ips and not all_urls:
            return {"success": False, "error": "No IPs or URLs found to generate firewall rules"}

        # Prepare firewall rules
        rules = [
            f"# Firewall Rules for {static_data.get('filename', 'Unknown')} - Generated on {datetime.now().strftime('%Y-%m-%d')}",
            "# Block and log outbound traffic to malicious IPs"
        ]

        # Add rules for IPs with logging (one rule per IP)
        for i, ip in enumerate(all_ips, 1):
            rules.append(f'iptables -A OUTPUT -d {ip} -j LOG --log-prefix "Malware Blocked IP{i}: "')
            rules.append(f'iptables -A OUTPUT -d {ip} -j DROP')

        # Add DNS sinkholing suggestions for URLs
        if all_urls:
            rules.append("\n# Suggested DNS Sinkholing (use dnsmasq or unbound to implement):")
            for url in all_urls:
                rules.append(f'# Block domain: {url}')
                rules.append(f'# e.g., dnsmasq: address=/{url}/127.0.0.1')

        # Write to file
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            f.write("\n".join(rules))
        logging.info(f"Firewall rules generated: {output_path}")
        return {"success": True, "output_file": output_path}
    except Exception as e:
        logging.error(f"Firewall rule generation failed: {str(e)}")
        return {"success": False, "error": str(e)}

def generate_firewall(static_analysis_file, dynamic_analysis_file):
    """Generate firewall rules from static and dynamic analysis JSON."""
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
