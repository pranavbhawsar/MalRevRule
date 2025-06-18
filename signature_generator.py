import json
import os
from datetime import datetime
import logging
import re

# Setup logging
logging.basicConfig(filename=os.path.join("logs", "analysis_log.db"),
                    level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

def escape_yara_string(s):
    """Escape special characters in a string for YARA rules."""
    s = s.replace('"', '\\"').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    return f'"{s}"'

def string_to_hex(s):
    """Convert a string to a YARA hex pattern."""
    return "{" + " ".join([f"{ord(c):02X}" for c in s]) + "}"

def generate_yara_rule(static_data, dynamic_data, output_path):
    """Generate a robust YARA rule from static and dynamic analysis data."""
    try:
        # Extract static data
        filename = static_data.get("filename", "Unknown")
        suspicious_strings = static_data.get("suspicious_strings", [])
        strings = static_data.get("strings", [])
        static_iocs = static_data.get("iocs", {})
        static_ips = static_iocs.get("ips", [])
        suspicious_imports = static_data.get("suspicious_imports", [])
        sections = static_data.get("sections", [])
        entry_bytes = static_data.get("entry_bytes", "")

        # Extract dynamic data
        dynamic_network = dynamic_data.get("network", {})
        dynamic_ips = dynamic_network.get("ips", [])
        domains = dynamic_network.get("dns_requests", [])

        # Prepare YARA rule
        rule_name = f"{filename.replace('.', '_')}_{datetime.now().strftime('%Y%m%d')}"
        yara_rule = [
            f"rule {rule_name} {{",
            "    meta:",
            '        author = "Malware Analysis Tool"',
            f'        date = "{datetime.now().strftime("%Y-%m-%d")}"',
            f'        description = "Detects {filename} and potential variants, including Gh0st RAT"',
            "    strings:"
        ]

        # Add suspicious strings with regex and hex patterns
        string_index = 1
        gh0st_strings = []
        for s in suspicious_strings[:5]:
            yara_rule.append(f'        $s{string_index} = {escape_yara_string(s)} nocase')
            if "password" in s.lower():
                yara_rule.append(f'        $s{string_index}_re = /p[a@]ssw[0o]rd/ nocase')
            if "gh0st" in s.lower():
                yara_rule.append(f'        $s{string_index}_gh0st_re = /Gh[0o]st/ nocase')
                gh0st_strings.append(f'$s{string_index}')
            yara_rule.append(f'        $s{string_index}_hex = {string_to_hex(s)}')
            string_index += 1

        # Add additional strings
        for s in strings[:5]:
            if s not in suspicious_strings:
                yara_rule.append(f'        $s{string_index} = {escape_yara_string(s)} nocase')
                string_index += 1

        # Add static IPs
        for i, ip in enumerate(static_ips[:5], 1):
            yara_rule.append(f'        $ip{i} = "{ip}"')

        # Add dynamic IPs and domains
        for i, ip in enumerate(dynamic_ips[:5], len(static_ips) + 1):
            if ip not in static_ips:
                yara_rule.append(f'        $ip{i} = "{ip}"')
        for i, domain in enumerate(domains[:5], 1):
            yara_rule.append(f'        $domain{i} = "{domain}"')

        # Add suspicious imports
        for i, imp in enumerate(suspicious_imports[:5], 1):
            yara_rule.append(f'        $imp{i} = "{imp}"')

        # Add section names
        for i, section in enumerate(sections[:5], 1):
            if section.get("name"):
                yara_rule.append(f'        $section{i} = "{section["name"]}"')

        # Add entry point bytes
        if entry_bytes:
            yara_rule.append(f'        $entry = {{ {entry_bytes} }}')

        # Condition
        condition = [
            "    condition:",
            "        uint16(0) == 0x5A4D and ("
        ]
        sub_conditions = []
        if suspicious_strings:
            sub_conditions.append("2 of ($s*)")
        if gh0st_strings:
            sub_conditions.append("1 of (" + ", ".join(gh0st_strings) + ")")  # Prioritize Gh0st strings
        if static_ips or dynamic_ips:
            sub_conditions.append("1 of ($ip*)")
        if domains:
            sub_conditions.append("1 of ($domain*)")
        if suspicious_imports:
            sub_conditions.append("2 of ($imp*) or #imp > 3")
        if any("upx" in s.get("name", "").lower() for s in sections):
            sub_conditions.append('1 of ($section*) and any of them in ("upx")')
        if entry_bytes:
            sub_conditions.append("$entry at entrypoint")
        if sub_conditions:
            condition.append(" or ".join(sub_conditions))
        else:
            condition.append("false")
        condition.append("        )")
        
        yara_rule.extend(condition)

        # Write to file
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            f.write("\n".join(yara_rule))
        logging.info(f"YARA rule generated: {output_path}")
        return {"success": True, "output_file": output_path}
    except Exception as e:
        logging.error(f"YARA rule generation failed: {str(e)}")
        return {"success": False, "error": str(e)}

def generate_signatures(static_analysis_file, dynamic_analysis_file):
    """Generate YARA signatures from static and dynamic analysis JSON."""
    try:
        with open(static_analysis_file, "r") as f:
            static_data = json.load(f)
        with open(dynamic_analysis_file, "r") as f:
            dynamic_data = json.load(f)
        output_path = os.path.join("signatures", "malware_signature.yara")
        return generate_yara_rule(static_data, dynamic_data, output_path)
    except Exception as e:
        logging.error(f"Signature generation failed: {str(e)}")
        return {"success": False, "error": str(e)}

if __name__ == "__main__":
    static_analysis_file = os.path.join("output", "sample_analysis.json")
    dynamic_analysis_file = os.path.join("output", "sample_dynamic.json")
    result = generate_signatures(static_analysis_file, dynamic_analysis_file)
    if result["success"]:
        print(f"Signatures generated: {result['output_file']}")
    else:
        print(f"Error: {result['error']}")
