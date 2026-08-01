import os
import tarfile
import zipfile
from flask import Flask, request, jsonify, send_file, render_template

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = '/var/archive_uploads'
app.config['EXTRACT_FOLDER'] = '/var/archive_contents'
app.config['ALLOWED_EXTENSIONS'] = {'zip', 'tar', 'gz', 'bz2'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

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
        
    if file and allowed_file(file.filename):
        filename = file.filename
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)
        return jsonify({'message': 'File uploaded successfully', 'path': save_path})
        
    return jsonify({'error': 'File type not allowed'}), 400

@app.route('/extract', methods=['POST'])
def extract_archive():
    data = request.get_json()
    if not data or 'archive_path' not in data:
        return jsonify({'error': 'No archive path provided'}), 400
        
    archive_path = data['archive_path']
    try:
        # Vulnerable path traversal - archive_path not properly sanitized
        full_archive_path = os.path.join(app.config['UPLOAD_FOLDER'], archive_path)
        
        if not os.path.exists(full_archive_path):
            return jsonify({'error': 'Archive not found'}), 404
            
        extract_dir = os.path.join(app.config['EXTRACT_FOLDER'], 
                                 os.path.splitext(os.path.basename(archive_path))[0])
        os.makedirs(extract_dir, exist_ok=True)
        
        if zipfile.is_zipfile(full_archive_path):
            with zipfile.ZipFile(full_archive_path, 'r') as zip_ref:
                # Vulnerable extraction - allows path traversal in zip files
                zip_ref.extractall(extract_dir)
        elif tarfile.is_tarfile(full_archive_path):
            with tarfile.open(full_archive_path) as tar_ref:
                # Vulnerable extraction - allows path traversal in tar files
                tar_ref.extractall(extract_dir)
        else:
            return jsonify({'error': 'Unsupported archive format'}), 400
            
        return jsonify({
            'message': 'Archive extracted successfully',
            'extract_path': extract_dir
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download')
def download_file():
    file_path = request.args.get('path')
    if not file_path:
        return jsonify({'error': 'No file path provided'}), 400
        
    try:
        # Also vulnerable to path traversal
        full_path = os.path.join(app.config['EXTRACT_FOLDER'], file_path)
        
        if not os.path.exists(full_path):
            return jsonify({'error': 'File not found'}), 404
            
        if not os.path.isfile(full_path):
            return jsonify({'error': 'Path is not a file'}), 400
            
        return send_file(full_path, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['EXTRACT_FOLDER'], exist_ok=True)
    
    # Create sample archives
    sample_zips = ['docs.zip', 'backup.tar.gz']
    for archive in sample_zips:
        path = os.path.join(app.config['UPLOAD_FOLDER'], archive)
        if not os.path.exists(path):
            open(path, 'wb').close()
    
    app.run(host='0.0.0.0', port=8000)