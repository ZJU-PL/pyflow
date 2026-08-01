import os
from flask import Flask, request, send_file, abort
from PIL import Image
import io
import hashlib
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['IMAGE_UPLOAD_FOLDER'] = './uploads'
app.config['THUMBNAIL_FOLDER'] = './thumbnails'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def ensure_directories():
    os.makedirs(app.config['IMAGE_UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs(app.config['THUMBNAIL_FOLDER'], exist_ok=True)

def generate_thumbnail(source_path, size=(128, 128)):
    # Vulnerable path traversal - source_path is used without validation
    try:
        with Image.open(source_path) as img:
            img.thumbnail(size)
            thumb_path = os.path.join(
                app.config['THUMBNAIL_FOLDER'],
                f"{hashlib.md5(source_path.encode()).hexdigest()}.jpg"
            )
            img.save(thumb_path, 'JPEG')
            return thumb_path
    except Exception as e:
        print(f"Error generating thumbnail: {e}")
        return None

@app.route('/upload', methods=['POST'])
def upload_image():
    if 'file' not in request.files:
        abort(400, description="No file part")
    
    file = request.files['file']
    if file.filename == '':
        abort(400, description="No selected file")
    
    if not allowed_file(file.filename):
        abort(400, description="File type not allowed")
    
    filename = secure_filename(file.filename)
    save_path = os.path.join(app.config['IMAGE_UPLOAD_FOLDER'], filename)
    file.save(save_path)
    
    return {'status': 'success', 'path': save_path}, 201

@app.route('/thumbnail', methods=['POST'])
def create_thumbnail():
    data = request.get_json()
    if not data or 'image_path' not in data:
        abort(400, description="No image path provided")
    
    thumb_path = generate_thumbnail(data['image_path'])
    if not thumb_path:
        abort(500, description="Failed to generate thumbnail")
    
    return {'status': 'success', 'thumbnail_path': thumb_path}

@app.route('/thumbnail/<path:thumb_path>')
def get_thumbnail(thumb_path):
    try:
        full_path = os.path.join(app.config['THUMBNAIL_FOLDER'], thumb_path)
        if not os.path.exists(full_path):
            abort(404)
        return send_file(full_path, mimetype='image/jpeg')
    except Exception as e:
        abort(500, description=str(e))

@app.route('/cleanup', methods=['POST'])
def cleanup_files():
    try:
        for folder in [app.config['IMAGE_UPLOAD_FOLDER'], app.config['THUMBNAIL_FOLDER']]:
            for filename in os.listdir(folder):
                file_path = os.path.join(folder, filename)
                try:
                    if os.path.isfile(file_path):
                        os.unlink(file_path)
                except Exception as e:
                    print(f"Error deleting {file_path}: {e}")
        return {'status': 'success'}, 200
    except Exception as e:
        abort(500, description=str(e))

if __name__ == '__main__':
    ensure_directories()
    app.run(host='0.0.0.0', port=5000, debug=True)