import os
import shutil
import json
import threading
import webbrowser
import time
import logging
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
from main import main as run_pipeline

# Setup logging
logging.basicConfig(filename=os.path.join("logs", "analysis_log.db"),
                    level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

app = Flask(__name__, template_folder=os.path.join("ui", "templates"), static_folder=os.path.join("ui", "static"))
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Replace with a secure key
app.config['UPLOAD_FOLDER'] = "input"
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
        if 'file' not in request.files:
            flash('No file part', 'error')
            return render_template('upload.html')
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return render_template('upload.html')
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            logging.info(f"File uploaded: {file_path}")

            try:
                # Clear previous outputs
                for folder in ['output', 'reports', 'signatures', 'firewall_rules']:
                    folder_path = folder
                    if os.path.exists(folder_path):
                        shutil.rmtree(folder_path)
                    os.makedirs(folder_path)

                # Run the pipeline
                outputs = run_pipeline(file_path)
                logging.info(f"Pipeline executed successfully: {outputs}")
                return redirect(url_for('results'))
            except Exception as e:
                logging.error(f"Pipeline failed: {str(e)}")
                flash(f"Analysis failed: {str(e)}", 'error')
                return render_template('upload.html')
        else:
            flash('Invalid file type. Only .exe files are allowed.', 'error')
            return render_template('upload.html')
    return render_template('upload.html')

@app.route('/results')
def results():
    """Display the analysis results."""
    try:
        static_file = os.path.join("output", "sample_analysis.json")
        with open(static_file, 'r') as f:
            static_data = json.load(f)

        dynamic_file = os.path.join("output", "sample_dynamic.json")
        with open(dynamic_file, 'r') as f:
            dynamic_data = json.load(f)

        network_ips = dynamic_data['network']['ips']
        network_counts = {ip: network_ips.count(ip) for ip in set(network_ips)}

        return render_template('results.html',
                               static_data=static_data,
                               dynamic_data=dynamic_data,
                               network_counts=network_counts)
    except Exception as e:
        logging.error(f"Failed to load results: {str(e)}")
        flash(f"Error loading results: {str(e)}", 'error')
        return redirect(url_for('upload_file'))

@app.route('/download/<file_type>')
def download_file(file_type):
    """Allow downloading of generated files."""
    try:
        if file_type == 'pdf_report':
            path = os.path.join("reports", "sample_analysis_report.pdf")
        elif file_type == 'stix_report':
            path = os.path.join("reports", "sample_analysis_stix.json")
        elif file_type == 'yara_rule':
            path = os.path.join("signatures", "malware_signature.yara")
        elif file_type == 'firewall_rules':
            path = os.path.join("firewall_rules", "firewall_rules.txt")
        else:
            flash('Invalid file type requested', 'error')
            return redirect(url_for('results'))

        return send_file(path, as_attachment=True)
    except Exception as e:
        logging.error(f"Failed to download file: {str(e)}")
        flash(f"Error downloading file: {str(e)}", 'error')
        return redirect(url_for('results'))

# Automatically open browser when server starts
if __name__ == "__main__":
    def open_browser():
        time.sleep(1)
        webbrowser.open("http://127.0.0.1:5000")

    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        threading.Thread(target=open_browser).start()

    app.run(debug=True, host='127.0.0.1', port=5000)