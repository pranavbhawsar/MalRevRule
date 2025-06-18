import os
import json
from datetime import datetime
import logging
from weasyprint import HTML, CSS
from stix2 import Malware, Indicator, Report, File, Relationship, Bundle

# Setup logging
logging.basicConfig(filename=os.path.expanduser("~/Desktop/Tool/logs/analysis_log.db"),
                    level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

class ReportGenerator:
    def __init__(self, static_analysis_file, dynamic_analysis_file):
        """Initialize the report generator."""
        self.static_analysis_file = os.path.expanduser(static_analysis_file)
        self.dynamic_analysis_file = os.path.expanduser(dynamic_analysis_file)
        self.reports_dir = os.path.expanduser("~/Desktop/Tool/reports")
        self.pdf_file = os.path.join(self.reports_dir, "sample_analysis_report.pdf")
        self.stix_file = os.path.join(self.reports_dir, "sample_analysis_stix.json")
        self.yara_file = os.path.expanduser("~/Desktop/Tool/signatures/sample.yara")
        self.firewall_file = os.path.expanduser("~/Desktop/Tool/firewall_rules/sample_firewall_rules.txt")
        os.makedirs(self.reports_dir, exist_ok=True)
        self.classification = "WHITE"
        self.report_id = "MAR-20250615-001"

    def create_pdf(self, static_data, dynamic_data):
        """Create a professional PDF report using WeasyPrint."""
        # Read YARA and firewall rules
        try:
            with open(self.yara_file, "r") as f:
                yara_content = f.read().replace("\n", "<br>")
        except Exception as e:
            yara_content = f"Error loading YARA rules: {str(e)}"

        try:
            with open(self.firewall_file, "r") as f:
                firewall_content = f.read().replace("\n", "<br>")
        except Exception as e:
            firewall_content = f"Error loading firewall rules: {str(e)}"

        # HTML template with CSS styling
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: 'Helvetica', 'Arial', sans-serif;
                    margin: 0;
                    padding: 0;
                    color: #333;
                    font-size: 12pt;
                    line-height: 1.5;
                }}
                .container {{
                    width: 90%;
                    margin: 0 auto;
                    padding: 20px;
                }}
                .header-bar {{
                    background-color: #003087;
                    color: white;
                    padding: 15px;
                    text-align: center;
                    margin-bottom: 20px;
                }}
                h1 {{
                    font-size: 24pt;
                    color: #003087;
                    margin-bottom: 10px;
                }}
                h2 {{
                    font-size: 18pt;
                    color: #003087;
                    border-bottom: 2px solid #003087;
                    padding-bottom: 5px;
                    margin-top: 20px;
                }}
                h3 {{
                    font-size: 14pt;
                    color: #555;
                    margin-top: 15px;
                }}
                p {{
                    margin: 10px 0;
                    text-align: justify;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin: 10px 0;
                }}
                th, td {{
                    border: 1px solid #ccc;
                    padding: 8px;
                    text-align: left;
                }}
                th {{
                    background-color: #e0e0e0;
                    font-weight: bold;
                }}
                tr:nth-child(even) {{
                    background-color: #f9f9f9;
                }}
                .code-section {{
                    background-color: #f4f4f4;
                    padding: 15px;
                    border: 1px solid #ccc;
                    border-radius: 5px;
                    margin: 10px 0;
                }}
                .code-block {{
                    font-family: 'Courier New', Courier, monospace;
                    background-color: #ffffff;
                    padding: 10px;
                    border-left: 4px solid #003087;
                    margin: 10px 0;
                    white-space: pre-wrap;
                }}
                .page-break {{
                    page-break-before: always;
                }}
                @page {{
                    margin: 1in;
                    @top-center {{
                        content: "Report ID: {self.report_id} | Classification: {self.classification}";
                        font-size: 10pt;
                        color: white;
                        background-color: #003087;
                        padding: 5px;
                    }}
                    @bottom-center {{
                        content: "Page " counter(page) " | Date: {datetime.now().strftime('%Y-%m-%d')}";
                        font-size: 8pt;
                        color: #555;
                    }}
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <!-- Title Page -->
                <div class="header-bar">
                    <h1>Malware Analysis Report</h1>
                </div>
                <p><strong>Report ID:</strong> {self.report_id}</p>
                <p><strong>Sample:</strong> {static_data['filename']}</p>
                <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d')}</p>
                <p><strong>Classification:</strong> {self.classification}</p>
                <div class="page-break"></div>

                <!-- Table of Contents -->
                <h2>Table of Contents</h2>
                <table>
                    <tr><th>Section</th><th>Page</th></tr>
                    <tr><td>1. Scope and Purpose</td><td>2</td></tr>
                    <tr><td>2. Executive Summary</td><td>3</td></tr>
                    <tr><td>3. File Metadata</td><td>4</td></tr>
                    <tr><td>4. Static Analysis</td><td>5</td></tr>
                    <tr><td>5. Dynamic Analysis</td><td>6</td></tr>
                    <tr><td>6. Indicators of Compromise (IOCs)</td><td>7</td></tr>
                    <tr><td>7. Mitigations and Recommendations</td><td>8</td></tr>
                </table>
                <div class="page-break"></div>

                <!-- Section 1: Scope and Purpose -->
                <h2>1. Scope and Purpose</h2>
                <p>
                    This report provides a detailed analysis of a potentially malicious executable file. 
                    The analysis includes both static and dynamic techniques to identify indicators of compromise, 
                    behavioral patterns, and potential origins of the malware. The goal is to provide actionable intelligence 
                    for mitigating threats, including YARA signatures and firewall rules.
                </p>
                <div class="page-break"></div>

                <!-- Section 2: Executive Summary -->
                <h2>2. Executive Summary</h2>
                <p>
                    The file '{static_data['filename']}' (MD5: {static_data['md5']}) was analyzed on {datetime.now().strftime('%Y-%m-%d')}. 
                    It exhibits suspicious behavior, including the use of imports such as {', '.join(static_data['suspicious_imports']) or 'None'} 
                    and network activity involving IPs {', '.join(dynamic_data['network']['ips']) or 'None'}. 
                    Metadata suggests a possible origin of {static_data['origin']['possible_country']}, associated with {static_data['version_info'].get('CompanyName', 'Unknown')}. 
                    Recommendations include applying the provided YARA rules and firewall configurations to mitigate potential threats.
                </p>
                <table>
                    <tr><th>Key Finding</th><th>Details</th></tr>
                    <tr><td>Suspicious Imports</td><td>{', '.join(static_data['suspicious_imports']) or 'None'}</td></tr>
                    <tr><td>Network Activity</td><td>{', '.join(dynamic_data['network']['ips']) or 'None'}</td></tr>
                    <tr><td>Possible Origin</td><td>{static_data['origin']['possible_country']}</td></tr>
                </table>
                <div class="page-break"></div>

                <!-- Section 3: File Metadata -->
                <h2>3. File Metadata</h2>
                <table>
                    <tr><th>Attribute</th><th>Value</th></tr>
                    <tr><td>Filename</td><td>{static_data['filename']}</td></tr>
                    <tr><td>MD5</td><td>{static_data['md5']}</td></tr>
                    <tr><td>File Size</td><td>{os.path.getsize(os.path.expanduser('~/Desktop/Tool/input/sample.exe'))} bytes</td></tr>
                    <tr><td>Company Name</td><td>{static_data['version_info'].get('CompanyName', 'Unknown')}</td></tr>
                    <tr><td>Product Name</td><td>{static_data['version_info'].get('ProductName', 'Unknown')}</td></tr>
                    <tr><td>File Version</td><td>{static_data['version_info'].get('FileVersion', 'Unknown')}</td></tr>
                    <tr><td>Legal Copyright</td><td>{static_data['version_info'].get('LegalCopyright', 'Unknown')}</td></tr>
                    <tr><td>Possible Origin</td><td>{static_data['origin']['possible_country']}</td></tr>
                    <tr><td>Origin Indicators</td><td>{', '.join(static_data['origin']['indicators']) or 'None'}</td></tr>
                </table>
                <div class="page-break"></div>

                <!-- Section 4: Static Analysis -->
                <h2>4. Static Analysis</h2>
                <table>
                    <tr><th>Attribute</th><th>Value</th></tr>
                    <tr><td>Suspicious Strings</td><td>{', '.join(static_data['suspicious_strings']) or 'None'}</td></tr>
                    <tr><td>Suspicious Imports</td><td>{', '.join(static_data['suspicious_imports']) or 'None'}</td></tr>
                    <tr><td>IOCs (IPs)</td><td>{', '.join(static_data['iocs']['ips']) or 'None'}</td></tr>
                    <tr><td>Functions</td><td>{', '.join(static_data['functions'][:10]) + ('...' if len(static_data['functions']) > 10 else '') or 'None'}</td></tr>
                    <tr><td>Sections</td><td>{', '.join([s['name'] for s in static_data['sections']]) or 'None'}</td></tr>
                    <tr><td>Entry Point Bytes</td><td>{static_data['entry_bytes'] or 'None'}</td></tr>
                </table>
                <div class="page-break"></div>

                <!-- Section 5: Dynamic Analysis -->
                <h2>5. Dynamic Analysis</h2>
                <table>
                    <tr><th>Attribute</th><th>Value</th></tr>
                    <tr><td>DNS Requests</td><td>{', '.join(dynamic_data['network']['dns_requests']) or 'None'}</td></tr>
                    <tr><td>HTTP Requests</td><td>{'<br>'.join([f"{req['url']} (IP: {req['ip']})" for req in dynamic_data['network']['http_requests']]) or 'None'}</td></tr>
                    <tr><td>IPs Contacted</td><td>{', '.join(dynamic_data['network']['ips']) or 'None'}</td></tr>
                    <tr><td>File Changes</td><td>{'<br>'.join([f"{change['action']}: {change['path']}" for change in dynamic_data['file_changes']]) or 'None'}</td></tr>
                    <tr><td>Process Activity</td><td>{'<br>'.join([f"{proc['action']} into {proc['process']}: {proc['details']}" for proc in dynamic_data['process_activity']]) or 'None'}</td></tr>
                </table>
                <div class="page-break"></div>

                <!-- Section 6: Indicators of Compromise (IOCs) -->
                <h2>6. Indicators of Compromise (IOCs)</h2>
                <table>
                    <tr><th>Type</th><th>Value</th></tr>
                    <tr><td>IP Addresses (Static)</td><td>{', '.join(static_data['iocs']['ips']) or 'None'}</td></tr>
                    <tr><td>IP Addresses (Dynamic)</td><td>{', '.join(dynamic_data['network']['ips']) or 'None'}</td></tr>
                    <tr><td>Domains</td><td>{', '.join(dynamic_data['network']['dns_requests']) or 'None'}</td></tr>
                </table>
                <div class="page-break"></div>

                <!-- Section 7: Mitigations and Recommendations -->
                <h2>7. Mitigations and Recommendations</h2>
                <p>The following mitigations have been generated to address the identified threats:</p>
                
                <h3>7.1 Malware Signatures</h3>
                <p>These signatures can be used to detect the malware and its variants using tools like YARA.</p>
                <p><strong>Suspicious Strings:</strong> {', '.join(static_data['suspicious_strings']) or 'None'}</p>
                <p><strong>Suspicious Imports:</strong> {', '.join(static_data['suspicious_imports']) or 'None'}</p>
                <div class="code-section">
                    <div class="code-block">{yara_content}</div>
                </div>

                <h3>7.2 Firewall Rules</h3>
                <p>These firewall rules are designed to block malicious network activity associated with the malware.</p>
                <div class="code-section">
                    <div class="code-block">{firewall_content}</div>
                </div>
            </div>
        </body>
        </html>
        """

        # Generate PDF using WeasyPrint
        try:
            HTML(string=html_content).write_pdf(self.pdf_file)
            logging.info(f"PDF report generated: {self.pdf_file}")
        except Exception as e:
            logging.error(f"Failed to generate PDF with WeasyPrint: {str(e)}")
            raise

    def create_stix_report(self, static_data, dynamic_data):
        """Generate a STIX 2.1 JSON report."""
        try:
            file_obj = File(
                name=static_data['filename'],
                hashes={'MD5': static_data['md5']}
            )
            malware = Malware(
                name=f"Malware - {static_data['filename']}",
                description=f"Suspicious file with imports: {', '.join(static_data['suspicious_imports']) or 'None'}",
                is_family=False
            )
            indicators = []
            for ip in static_data['iocs']['ips'] + dynamic_data['network']['ips']:
                indicator = Indicator(
                    pattern=f"[ipv4-addr:value = '{ip}']",
                    pattern_type="stix",
                    description=f"IP address associated with {static_data['filename']}"
                )
                indicators.append(indicator)
            for domain in dynamic_data['network']['dns_requests']:
                indicator = Indicator(
                    pattern=f"[domain-name:value = '{domain}']",
                    pattern_type="stix",
                    description=f"Domain associated with {static_data['filename']}"
                )
                indicators.append(indicator)

            relationships = [Relationship(malware, 'uses', ind) for ind in indicators]
            relationships.append(Relationship(malware, 'targets', file_obj))

            report = Report(
                name=f"Analysis Report for {static_data['filename']}",
                published=datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                description="Malware analysis report generated by the pipeline.",
                object_refs=[file_obj, malware] + indicators + relationships
            )

            bundle = Bundle(objects=[file_obj, malware, report] + indicators + relationships)
            with open(self.stix_file, "w") as f:
                f.write(bundle.serialize(pretty=True))
            logging.info(f"STIX report generated: {self.stix_file}")

        except Exception as e:
            logging.error(f"STIX report generation failed: {str(e)}")
            raise

    def generate_reports(self):
        """Generate PDF and STIX reports."""
        try:
            with open(self.static_analysis_file, "r") as f:
                static_data = json.load(f)
            with open(self.dynamic_analysis_file, "r") as f:
                dynamic_data = json.load(f)

            self.create_pdf(static_data, dynamic_data)
            self.create_stix_report(static_data, dynamic_data)

            return {
                "success": True,
                "output_files": [self.pdf_file, self.stix_file]
            }
        except Exception as e:
            logging.error(f"Report generation failed: {str(e)}")
            return {"success": False, "error": str(e)}

def generate_reports(static_analysis_file, dynamic_analysis_file=None):
    """Entry point for report generation."""
    generator = ReportGenerator(static_analysis_file, dynamic_analysis_file)
    return generator.generate_reports()

if __name__ == "__main__":
    static_file = "~/Desktop/Tool/output/sample_analysis.json"
    dynamic_file = "~/Desktop/Tool/output/sample_dynamic.json"
    result = generate_reports(static_file, dynamic_file)
    if result["success"]:
        print(f"Reports generated: {result['output_files']}")
    else:
        print(f"Report generation failed: {result['error']}")
