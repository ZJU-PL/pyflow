import os
from flask import Flask, send_file, render_template, abort

app = Flask(__name__)
app.config['GALLERY_ROOT'] = os.path.join(os.path.dirname(__file__), 'gallery')

@app.route('/')
def index():
    images = []
    try:
        images = [f for f in os.listdir(app.config['GALLERY_ROOT']) 
                  if f.lower().endswith(('.png', '.jpg', '.jpeg'))]
    except Exception:
        pass
    return render_template('gallery.html', images=images)

@app.route('/image/<path:filename>')
def get_image(filename):
    try:
        # Vulnerable path traversal - no validation of filename
        image_path = os.path.join(app.config['GALLERY_ROOT'], filename)
        
        if not os.path.exists(image_path):
            abort(404)
            
        if not os.path.isfile(image_path):
            abort(400, 'Requested path is not a file')
            
        return send_file(image_path, mimetype='image/jpeg')
        
    except Exception as e:
        abort(500, str(e))

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error='Image not found'), 404

@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', error=str(e)), 400

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error='Server error'), 500

if __name__ == '__main__':
    if not os.path.exists(app.config['GALLERY_ROOT']):
        os.makedirs(app.config['GALLERY_ROOT'])
        sample_images = ['image1.jpg', 'image2.png', 'image3.jpeg']
        for img in sample_images:
            open(os.path.join(app.config['GALLERY_ROOT'], img), 'w').close()
    
    app.run(debug=True, port=5000)