import os
import tarfile
import zipfile
from flask import Flask, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.abspath('/var/archive_uploads')
app.config['EXTRACT_FOLDER'] = os.path.abspath('/var/archive_contents')
app.config['ALLOWED_EXTENSIONS'] = {'zip', 'tar', 'gz', 'bz2'}
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB upload limit

def allowed_file(filename):
    """Check if the file has an allowed extension"""
    if not filename or '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in app.config['ALLOWED_EXTENSIONS']

def is_safe_path(base_path, requested_path):
    """Check if requested path is within base directory"""
    base_path = os.path.abspath(base_path)
    requested_path = os.path.abspath(requested_path)
    return requested_path.startswith(base_path + os.sep)

def safe_extract_zip(zip_path, extract_dir):
    """Safely extract zip file preventing path traversal"""
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for member in zip_ref.infolist():
            member_path = os.path.abspath(os.path.join(extract_dir, member.filename))
            if not is_safe_path(extract_dir, member_path):
                raise ValueError(f"Attempted path traversal in zip file: {member.filename}")
            zip_ref.extract(member, extract_dir)

def safe_extract_tar(tar_path, extract_dir):
    """Safely extract tar file preventing path traversal"""
    with tarfile.open(tar_path) as tar_ref:
        for member in tar_ref.getmembers():
            member_path = os.path.abspath(os.path.join(extract_dir, member.name))
            if not is_safe_path(extract_dir, member_path):
                raise ValueError(f"Attempted path traversal in tar file: {member.name}")
            tar_ref.extract(member, extract_dir)

@app.route('/')
def index():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_archive():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
        
    try:
        filename = secure_filename(file.filename)
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        if not is_safe_path(app.config['UPLOAD_FOLDER'], save_path):
            return jsonify({'error': 'Invalid file path'}), 400
            
        file.save(save_path)
        return jsonify({
            'message': 'File uploaded successfully',
            'path': os.path.basename(save_path)  # Only return filename, not full path
        })
    except Exception as e:
        app.logger.error(f"Upload error: {e}")
        return jsonify({'error': 'File upload failed'}), 500

@app.route('/extract', methods=['POST'])
def extract_archive():
    data = request.get_json()
    if not data or 'archive_path' not in data:
        return jsonify({'error': 'No archive path provided'}), 400
        
    try:
        archive_path = secure_filename(data['archive_path'])
        full_archive_path = os.path.join(app.config['UPLOAD_FOLDER'], archive_path)
        
        if not is_safe_path(app.config['UPLOAD_FOLDER'], full_archive_path):
            return jsonify({'error': 'Invalid archive path'}), 400
            
        if not os.path.exists(full_archive_path):
            return jsonify({'error': 'Archive not found'}), 404
            
        extract_dir_name = secure_filename(os.path.splitext(archive_path)[0])
        extract_dir = os.path.join(app.config['EXTRACT_FOLDER'], extract_dir_name)
        
        os.makedirs(extract_dir, mode=0o750, exist_ok=True)
        
        if zipfile.is_zipfile(full_archive_path):
            safe_extract_zip(full_archive_path, extract_dir)
        elif tarfile.is_tarfile(full_archive_path):
            safe_extract_tar(full_archive_path, extract_dir)
        else:
            return jsonify({'error': 'Unsupported archive format'}), 400
            
        return jsonify({
            'message': 'Archive extracted successfully',
            'extract_path': extract_dir_name  # Only return directory name, not full path
        })
    except ValueError as e:
        return jsonify({'error': 'Invalid archive contents'}), 400
    except Exception as e:
        app.logger.error(f"Extraction error: {e}")
        return jsonify({'error': 'Archive extraction failed'}), 500

@app.route('/download')
def download_file():
    file_path = request.args.get('path')
    if not file_path or not isinstance(file_path, str):
        return jsonify({'error': 'Invalid file path'}), 400
        
    try:
        safe_path = secure_filename(file_path)
        full_path = os.path.join(app.config['EXTRACT_FOLDER'], safe_path)
        
        if not is_safe_path(app.config['EXTRACT_FOLDER'], full_path):
            return jsonify({'error': 'Invalid file path'}), 400
            
        if not os.path.exists(full_path):
            return jsonify({'error': 'File not found'}), 404
            
        if not os.path.isfile(full_path):
            return jsonify({'error': 'Path is not a file'}), 400
            
        return send_file(full_path, as_attachment=True)
    except Exception as e:
        app.logger.error(f"Download error: {e}")
        return jsonify({'error': 'File download failed'}), 500

if __name__ == '__main__':
    # Create directories with secure permissions
    os.makedirs(app.config['UPLOAD_FOLDER'], mode=0o750, exist_ok=True)
    os.makedirs(app.config['EXTRACT_FOLDER'], mode=0o750, exist_ok=True)
    
    # Create sample archives
    sample_zips = ['docs.zip', 'backup.tar.gz']
    for archive in sample_zips:
        path = os.path.join(app.config['UPLOAD_FOLDER'], archive)
        if not os.path.exists(path):
            try:
                with open(path, 'wb') as f:
                    pass  # Create empty files
                os.chmod(path, 0o640)  # Secure file permissions
            except Exception as e:
                app.logger.error(f"Error creating sample archive {archive}: {e}")
    
    app.run(host='0.0.0.0', port=8000)