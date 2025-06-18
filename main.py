import os
from file_input_validator import validate_input_file
from reverse_engineer import perform_static_analysis
from dynamic_analyzer import perform_dynamic_analysis
from report_generator import generate_reports
from signature_generator import generate_signatures
from firewall_generator import generate_firewall
import logging

# Get base directory (the directory where this script is located)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Define relative paths
LOGS_DIR = os.path.join(BASE_DIR, 'logs')
OUTPUT_DIR = os.path.join(BASE_DIR, 'output')
INPUT_DIR = os.path.join(BASE_DIR, 'input')

# Ensure necessary directories exist
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(INPUT_DIR, exist_ok=True)

# Setup logging with relative path
log_file_path = os.path.join(LOGS_DIR, 'analysis_log.db')
logging.basicConfig(
    filename=log_file_path,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def main(input_file_path):
    """Run the full malware analysis pipeline and return outputs."""
    try:
        # Step 1: Validate input
        logging.info(f"Starting validation for {input_file_path}")
        validation_result = validate_input_file(input_file_path)
        if not validation_result["success"]:
            logging.error(f"Validation failed: {validation_result['error']}")
            raise Exception(f"Validation failed: {validation_result['error']}")
        if not validation_result.get("output_file"):
            raise Exception("Validation failed: No output file path returned")

        # Step 2: Reverse engineering (static analysis)
        logging.info("Starting reverse engineering")
        static_output_path = os.path.join(OUTPUT_DIR, 'sample_analysis.json')
        static_analysis_result = perform_static_analysis(validation_result["output_file"], static_output_path)
        if not static_analysis_result["success"]:
            logging.error(f"Static analysis failed: {static_analysis_result['error']}")
            raise Exception(f"Static analysis failed: {static_analysis_result['error']}")
        if not static_analysis_result.get("output_file"):
            raise Exception("Static analysis failed: No output file path returned")

        # Step 3: Dynamic analysis
        logging.info("Starting dynamic analysis")
        dynamic_analysis_result = perform_dynamic_analysis(validation_result["output_file"], static_analysis_result["output_file"])
        if not dynamic_analysis_result["success"]:
            logging.error(f"Dynamic analysis failed: {dynamic_analysis_result['error']}")
            raise Exception(f"Dynamic analysis failed: {dynamic_analysis_result['error']}")
        if not dynamic_analysis_result.get("output_file"):
            raise Exception("Dynamic analysis failed: No output file path returned")

        # Step 4: Generate YARA signatures
        logging.info("Starting signature generation")
        signature_result = generate_signatures(static_analysis_result["output_file"], dynamic_analysis_result["output_file"])
        if not signature_result["success"]:
            logging.error(f"Signature generation failed: {signature_result['error']}")
            raise Exception(f"Signature generation failed: {signature_result['error']}")
        
        # Step 5: Generate firewall rules
        logging.info("Starting firewall rule generation")
        firewall_result = generate_firewall(static_analysis_result["output_file"], dynamic_analysis_result["output_file"])
        if not firewall_result["success"]:
            logging.error(f"Firewall rule generation failed: {firewall_result['error']}")
            raise Exception(f"Firewall rule generation failed: {firewall_result['error']}")
        
        # Step 6: Generate reports
        logging.info("Starting report generation")
        report_result = generate_reports(static_analysis_result["output_file"], dynamic_analysis_result["output_file"])
        if not report_result["success"]:
            logging.error(f"Report generation failed: {report_result['error']}")
            raise Exception(f"Report generation failed: {report_result['error']}")

        # Return outputs
        outputs = {
            "static_analysis": static_analysis_result["output_file"],
            "dynamic_analysis": dynamic_analysis_result["output_file"],
            "reports": report_result["output_files"],
            "signatures": signature_result["output_file"],
            "firewall_rules": firewall_result["output_file"]
        }
        logging.info(f"Pipeline completed: {outputs}")
        return outputs

    except Exception as e:
        logging.error(f"Pipeline error: {str(e)}")
        raise

if __name__ == "__main__":
    input_file = os.path.join(INPUT_DIR, 'sample.exe')
    try:
        outputs = main(input_file)
        print("Pipeline completed successfully:")
        print(f"Static Analysis: {outputs['static_analysis']}")
        print(f"Dynamic Analysis: {outputs['dynamic_analysis']}")
        print(f"Reports: {outputs['reports']}")
        print(f"Signatures: {outputs['signatures']}")
        print(f"Firewall Rules: {outputs['firewall_rules']}")
    except Exception as e:
        print(f"Pipeline error: {str(e)}")
