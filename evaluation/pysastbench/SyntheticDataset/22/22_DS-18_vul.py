import os
from flask import Flask, request, send_file, abort, render_template
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['MEDIA_ROOT'] = '/var/media'
app.config['ALLOWED_EXTENSIONS'] = {'mp4', 'avi', 'mov', 'mkv'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    media_files = []
    try:
        media_files = [f for f in os.listdir(app.config['MEDIA_ROOT'])
                     if allowed_file(f)]
    except Exception:
        pass
    return render_template('browse.html', media_files=media_files)

@app.route('/stream/<path:media_path>')
def stream_media(media_path):
    try:
        # Vulnerable path traversal - media_path used directly without proper sanitization
        full_path = os.path.join(app.config['MEDIA_ROOT'], media_path)
        
        if not os.path.exists(full_path):
            abort(404, "Media file not found")
            
        if not os.path.isfile(full_path):
            abort(400, "Requested path is not a file")
            
        if not allowed_file(full_path):
            abort(403, "File type not allowed")
            
        range_header = request.headers.get('Range', None)
        file_size = os.path.getsize(full_path)
        
        if range_header:
            from_bytes, to_bytes = 0, None
            range_units = range_header.split('=')
            if len(range_units) == 2 and range_units[0] == 'bytes':
                range_bytes = range_units[1].split('-')
                from_bytes = int(range_bytes[0]) if range_bytes[0] else 0
                to_bytes = int(range_bytes[1]) if range_bytes[1] else file_size - 1
            
            length = to_bytes - from_bytes + 1
            
            def generate():
                with open(full_path, 'rb') as f:
                    f.seek(from_bytes)
                    remaining = length
                    while remaining > 0:
                        chunk = f.read(min(4096, remaining))
                        if not chunk:
                            break
                        remaining -= len(chunk)
                        yield chunk
            
            response = app.response_class(
                generate(),
                206,
                mimetype='video/mp4',
                direct_passthrough=True,
                headers={
                    'Content-Range': f'bytes {from_bytes}-{to_bytes}/{file_size}',
                    'Accept-Ranges': 'bytes',
                    'Content-Length': str(length)
                }
            )
            return response
            
        return send_file(full_path, mimetype='video/mp4')
        
    except Exception as e:
        abort(500, f"Streaming error: {str(e)}")

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        abort(400, "No file part")
        
    file = request.files['file']
    if file.filename == '':
        abort(400, "No selected file")
        
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['MEDIA_ROOT'], filename))
        return "File uploaded successfully"
        
    abort(400, "File type not allowed")

@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', error=str(e)), 400

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', error=str(e)), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error=str(e)), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error=str(e)), 500

if __name__ == '__main__':
    os.makedirs(app.config['MEDIA_ROOT'], exist_ok=True)
    
    # Create sample media files
    sample_media = ['sample1.mp4', 'sample2.avi', 'sample3.mov']
    for media in sample_media:
        path = os.path.join(app.config['MEDIA_ROOT'], media)
        if not os.path.exists(path):
            open(path, 'wb').close()
    
    app.run(host='0.0.0.0', port=8000, threaded=True)