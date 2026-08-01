from flask import Flask, request, send_file, abort
import os
import uuid

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = './uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return {'error': 'No file part'}, 400
    
    file = request.files['file']
    if file.filename == '':
        return {'error': 'No selected file'}, 400
    
    if file and allowed_file(file.filename):
        filename = str(uuid.uuid4()) + '.' + file.filename.rsplit('.', 1)[1].lower()
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(save_path)
        return {'message': 'File uploaded successfully', 'filename': filename}, 200
    
    return {'error': 'Invalid file type'}, 400

@app.route('/download/<path:filename>')
def download_image(filename):
    # Vulnerable path traversal - no validation of filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        if not os.path.exists(file_path):
            abort(404)
        
        if not os.path.isfile(file_path):
            abort(400, description="Requested path is not a file")
            
        return send_file(file_path, as_attachment=True)
    except Exception as e:
        abort(500, description=str(e))

def create_upload_folder():
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

if __name__ == '__main__':
    create_upload_folder()
    app.run(debug=True, host='0.0.0.0', port=5000)