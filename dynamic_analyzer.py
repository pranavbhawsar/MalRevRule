import os
import json
from datetime import datetime
import logging

# Setup logging
logging.basicConfig(filename=os.path.expanduser("~/Desktop/Tool/logs/analysis_log.db"),
                    level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

class DynamicAnalyzer:
    def __init__(self, file_path, static_analysis_file):
        """Initialize the dynamic analysis module."""
        self.file_path = os.path.expanduser(file_path)
        self.static_analysis_file = os.path.expanduser(static_analysis_file)
        self.output_dir = os.path.expanduser("~/Desktop/Tool/output")
        self.output_json = os.path.join(self.output_dir, "sample_dynamic.json")
        os.makedirs(self.output_dir, exist_ok=True)

    def simulate_sandbox_execution(self):
        """Simulate sandbox execution of the sample and return dynamic analysis results."""
        try:
            # Load static analysis results to inform the simulation
            with open(self.static_analysis_file, "r") as f:
                static_data = json.load(f)
            
            # Simulate runtime behavior based on static analysis
            iocs = static_data.get("iocs", {})
            suspicious_imports = static_data.get("suspicious_imports", [])

            # Network activity
            network_activity = {
                "dns_requests": ["malicious.example.com"],  # Simulated DGA or C2 domain
                "http_requests": [
                    {"url": f"http://{ip}/payload", "ip": ip} for ip in iocs.get("ips", [])
                ],
                "ips": iocs.get("ips", []) + ["8.8.8.8"]  # Add a DNS server IP
            }

            # File system changes
            file_changes = [
                {"action": "created", "path": r"C:\Temp\malware_copy.exe"},
                {"action": "modified", "path": r"C:\Windows\System32\config\SYSTEM"}
            ]

            # Process activity
            process_activity = []
            if "CreateRemoteThread" in suspicious_imports:
                process_activity.append({
                    "action": "injected",
                    "process": "explorer.exe",
                    "details": "Used CreateRemoteThread for code injection"
                })

            # Compile results
            results = {
                "filename": os.path.basename(self.file_path),
                "network": network_activity,
                "file_changes": file_changes,
                "process_activity": process_activity,
                "timestamp": datetime.now().isoformat()
            }

            # Save to JSON
            with open(self.output_json, "w") as f:
                json.dump(results, f, indent=4)
            logging.info(f"Dynamic analysis completed: {self.output_json}")
            return {"success": True, "output_file": self.output_json}

        except Exception as e:
            logging.error(f"Dynamic analysis failed: {str(e)}")
            return {"success": False, "error": str(e)}

def perform_dynamic_analysis(file_path, static_analysis_file):
    """Entry point for dynamic analysis."""
    analyzer = DynamicAnalyzer(file_path, static_analysis_file)
    return analyzer.simulate_sandbox_execution()

if __name__ == "__main__":
    file_path = "~/Desktop/Tool/input/sample.exe"
    static_analysis_file = "~/Desktop/Tool/output/sample_analysis.json"
    result = perform_dynamic_analysis(file_path, static_analysis_file)
    if result["success"]:
        print(f"Dynamic analysis successful: {result['output_file']}")
    else:
        print(f"Dynamic analysis failed: {result['error']}")
