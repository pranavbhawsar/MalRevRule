import os
import hashlib
import sqlite3
import logging
import magic

# Setup logging
logging.basicConfig(filename=os.path.join("logs", "analysis_log.db"),
                    level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

def compute_hashes(file_path):
    """Compute MD5 and SHA-256 hashes of the file."""
    try:
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        return md5_hash.hexdigest(), sha256_hash.hexdigest()
    except Exception as e:
        logging.error(f"Hash computation failed for {file_path}: {str(e)}")
        raise

def log_metadata(file_path, size, file_type, md5, sha256):
    """Log file metadata to SQLite database."""
    try:
        db_path = os.path.join("logs", "analysis_log.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS file_metadata (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT,
                size INTEGER,
                file_type TEXT,
                md5 TEXT,
                sha256 TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cursor.execute("""
            INSERT INTO file_metadata (filename, size, file_type, md5, sha256)
            VALUES (?, ?, ?, ?, ?)
        """, (os.path.basename(file_path), size, file_type, md5, sha256))
        conn.commit()
        conn.close()
        logging.info(f"Metadata logged for {file_path}")
    except Exception as e:
        logging.error(f"Failed to log metadata for {file_path}: {str(e)}")
        raise

def validate_input_file(file_path):
    """Validate input file and log metadata."""
    try:
        file_path = os.path.join("input", os.path.basename(file_path))
        input_dir = "input"
        os.makedirs(input_dir, exist_ok=True)

        # Check if file exists and is readable
        if not os.path.isfile(file_path):
            return {"success": False, "error": f"File {file_path} does not exist or is not a file"}
        if not os.access(file_path, os.R_OK):
            return {"success": False, "error": f"File {file_path} is not readable"}

        # Check file size
        size = os.path.getsize(file_path)
        if size == 0:
            return {"success": False, "error": f"File {file_path} is empty"}

        # Check file type
        try:
            file_type = magic.from_file(file_path, mime=False)
        except Exception as e:
            return {"success": False, "error": f"Failed to determine file type: {str(e)}"}
        if "PE32" not in file_type and "executable" not in file_type.lower():
            return {"success": False, "error": f"File {file_path} is not a PE executable"}

        # Compute hashes
        md5, sha256 = compute_hashes(file_path)

        # Move file to input directory if not already there
        dest_path = os.path.join(input_dir, os.path.basename(file_path))
        if file_path != dest_path:
            try:
                with open(file_path, "rb") as src, open(dest_path, "wb") as dst:
                    dst.write(src.read())
                file_path = dest_path
            except Exception as e:
                return {"success": False, "error": f"Failed to move file to input directory: {str(e)}"}

        # Log metadata
        log_metadata(file_path, size, file_type, md5, sha256)

        return {"success": True, "output_file": file_path}
    except Exception as e:
        logging.error(f"Validation failed for {file_path}: {str(e)}")
        return {"success": False, "error": str(e)}

if __name__ == "__main__":
    input_file = os.path.join("input", "sample.exe")
    result = validate_input_file(input_file)
    if result["success"]:
        print(f"Validation successful: {result['output_file']}")
    else:
        print(f"Validation failed: {result['error']}")
