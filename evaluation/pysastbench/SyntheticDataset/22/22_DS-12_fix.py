import os
from flask import Flask, send_file, render_template, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['GALLERY_ROOT'] = os.path.abspath(os.path.join(os.path.dirname(__file__), 'gallery'))
app.config['ALLOWED_EXTENSIONS'] = {'.png', '.jpg', '.jpeg'}

def is_safe_path(base_path, requested_path):
    """Check if requested path is within base directory"""
    base_path = os.path.abspath(base_path)
    requested_path = os.path.abspath(requested_path)
    return requested_path.startswith(base_path + os.sep)

def allowed_file(filename):
    """Check if the file has an allowed extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in {ext[1:] for ext in app.config['ALLOWED_EXTENSIONS']}

@app.route('/')
def index():
    images = []
    try:
        images = [f for f in os.listdir(app.config['GALLERY_ROOT']) 
                  if allowed_file(f) and 
                  is_safe_path(app.config['GALLERY_ROOT'], os.path.join(app.config['GALLERY_ROOT'], f))]
    except Exception as e:
        app.logger.error(f"Error listing images: {e}")
    return render_template('gallery.html', images=images)

@app.route('/image/<path:filename>')
def get_image(filename):
    try:
        # Validate filename
        if not allowed_file(filename):
            abort(400, 'Invalid file type')
            
        # Secure the filename and path
        safe_filename = secure_filename(filename)
        image_path = os.path.join(app.config['GALLERY_ROOT'], safe_filename)
        
        # Validate the path is safe
        if not is_safe_path(app.config['GALLERY_ROOT'], image_path):
            abort(403, 'Access denied')
            
        if not os.path.exists(image_path):
            abort(404)
            
        if not os.path.isfile(image_path):
            abort(400, 'Requested path is not a file')
            
        # Determine correct mimetype
        mimetype = None
        if filename.lower().endswith('.png'):
            mimetype = 'image/png'
        elif filename.lower().endswith('.jpg') or filename.lower().endswith('.jpeg'):
            mimetype = 'image/jpeg'
            
        return send_file(image_path, mimetype=mimetype)
        
    except Exception as e:
        app.logger.error(f"Error serving image: {e}")
        abort(500, 'Internal server error')

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error='Image not found'), 404

@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', error='Invalid request'), 400

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', error='Access denied'), 403

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error='Internal server error'), 500

if __name__ == '__main__':
    if not os.path.exists(app.config['GALLERY_ROOT']):
        os.makedirs(app.config['GALLERY_ROOT'], mode=0o750)  # Secure permissions
        sample_images = ['image1.jpg', 'image2.png', 'image3.jpeg']
        for img in sample_images:
            try:
                with open(os.path.join(app.config['GALLERY_ROOT'], img), 'wb') as f:
                    pass  # Create empty files
            except Exception as e:
                app.logger.error(f"Error creating sample image: {e}")
    
    app.run(port=5000)  # Removed debug=True