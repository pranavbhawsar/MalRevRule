import os
import shutil
import json  # Added import for json
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
from main import main as run_pipeline
import logging

# Setup logging
logging.basicConfig(filename=os.path.expanduser("~/Desktop/Tool/logs/analysis_log.db"),
                    level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

app = Flask(__name__, template_folder="ui/templates", static_folder="ui/static")
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Replace with a secure key
app.config['UPLOAD_FOLDER'] = os.path.expanduser("~/Desktop/Tool/input")
app.config['ALLOWED_EXTENSIONS'] = {'exe'}

def allowed_file(filename):
    """Check if the uploaded file is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    """Render the homepage."""
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Handle file uploads and trigger the pipeline."""
    if request.method == 'POST':
        # Check if a file was uploaded
        if 'file' not in request.files:
            flash('No file part', 'error')
            return render_template('upload.html')  # Stay on upload page
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return render_template('upload.html')  # Stay on upload page
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            logging.info(f"File uploaded: {file_path}")

            try:
                # Clear previous outputs
                for folder in ['output', 'reports', 'signatures', 'firewall_rules']:
                    folder_path = os.path.expanduser(f"~/Desktop/Tool/{folder}")
                    if os.path.exists(folder_path):
                        shutil.rmtree(folder_path)
                    os.makedirs(folder_path)

                # Run the pipeline
                outputs = run_pipeline(file_path)
                logging.info(f"Pipeline executed successfully: {outputs}")
                return redirect(url_for('results'))  # Redirect to results on success
            except Exception as e:
                logging.error(f"Pipeline failed: {str(e)}")
                flash(f"Analysis failed: {str(e)}", 'error')
                return render_template('upload.html')  # Stay on upload page with error
        else:
            flash('Invalid file type. Only .exe files are allowed.', 'error')
            return render_template('upload.html')  # Stay on upload page
    return render_template('upload.html')

@app.route('/results')
def results():
    """Display the analysis results."""
    try:
        # Load static analysis
        static_file = os.path.expanduser("~/Desktop/Tool/output/sample_analysis.json")
        with open(static_file, 'r') as f:
            static_data = json.load(f)

        # Load dynamic analysis
        dynamic_file = os.path.expanduser("~/Desktop/Tool/output/sample_dynamic.json")
        with open(dynamic_file, 'r') as f:
            dynamic_data = json.load(f)

        # Prepare data for visualization
        network_ips = dynamic_data['network']['ips']
        network_counts = {ip: network_ips.count(ip) for ip in set(network_ips)}

        return render_template('results.html',
                              static_data=static_data,
                              dynamic_data=dynamic_data,
                              network_counts=network_counts)
    except Exception as e:
        logging.error(f"Failed to load results: {str(e)}")
        flash(f"Error loading results: {str(e)}", 'error')
        return redirect(url_for('upload_file'))  # Redirect to upload page on error

@app.route('/download/<file_type>')
def download_file(file_type):
    """Allow downloading of generated files."""
    try:
        if file_type == 'pdf_report':
            path = os.path.expanduser("~/Desktop/Tool/reports/sample_analysis_report.pdf")
            return send_file(path, as_attachment=True)
        elif file_type == 'stix_report':
            path = os.path.expanduser("~/Desktop/Tool/reports/sample_analysis_stix.json")
            return send_file(path, as_attachment=True)
        elif file_type == 'yara_rule':
            path = os.path.expanduser("~/Desktop/Tool/signatures/sample.yara")
            return send_file(path, as_attachment=True)
        elif file_type == 'firewall_rules':
            path = os.path.expanduser("~/Desktop/Tool/firewall_rules/sample_firewall_rules.txt")
            return send_file(path, as_attachment=True)
        else:
            flash('Invalid file type requested', 'error')
            return redirect(url_for('results'))
    except Exception as e:
        logging.error(f"Failed to download file: {str(e)}")
        flash(f"Error downloading file: {str(e)}", 'error')
        return redirect(url_for('results'))

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)
