import os
import json
from flask import Flask, request, send_file, render_template, abort, redirect, url_for

app = Flask(__name__)
app.config['THEMES_DIR'] = '/var/www/themes'
app.config['STATIC_DIR'] = '/var/www/static'

class ThemeManager:
    def __init__(self):
        os.makedirs(app.config['THEMES_DIR'], exist_ok=True)
        os.makedirs(app.config['STATIC_DIR'], exist_ok=True)
    
    def list_themes(self):
        return [f for f in os.listdir(app.config['THEMES_DIR']) 
               if os.path.isdir(os.path.join(app.config['THEMES_DIR'], f))]
    
    def load_theme(self, theme_name, asset_path):
        # Vulnerable path traversal - no proper sanitization of theme_name or asset_path
        theme_dir = os.path.join(app.config['THEMES_DIR'], theme_name)
        asset_full_path = os.path.join(theme_dir, asset_path)
        
        if not os.path.exists(asset_full_path):
            raise FileNotFoundError(f"Asset {asset_path} not found in theme {theme_name}")
            
        if not os.path.isfile(asset_full_path):
            raise ValueError("Requested path is not a file")
            
        return asset_full_path
    
    def install_theme(self, zip_file):
        # Basic theme installation (not the vulnerable part)
        pass

@app.route('/theme/<theme_name>/<path:asset_path>')
def serve_theme_asset(theme_name, asset_path):
    try:
        manager = ThemeManager()
        asset_file = manager.load_theme(theme_name, asset_path)
        return send_file(asset_file)
    except Exception as e:
        abort(404, str(e))

@app.route('/static/<path:filename>')
def serve_static(filename):
    # Also vulnerable to path traversal
    static_file = os.path.join(app.config['STATIC_DIR'], filename)
    
    if not os.path.exists(static_file):
        abort(404, "File not found")
        
    return send_file(static_file)

@app.route('/admin/themes')
def theme_admin():
    manager = ThemeManager()
    themes = manager.list_themes()
    return render_template('theme_admin.html', themes=themes)

@app.route('/admin/themes/upload', methods=['POST'])
def upload_theme():
    if 'theme' not in request.files:
        abort(400, "No theme file uploaded")
        
    theme_file = request.files['theme']
    if theme_file.filename == '':
        abort(400, "No theme file selected")
        
    try:
        manager = ThemeManager()
        manager.install_theme(theme_file)
        return redirect(url_for('theme_admin'))
    except Exception as e:
        abort(500, str(e))

@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', error=str(e)), 400

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error=str(e)), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error=str(e)), 500

if __name__ == '__main__':
    # Create sample themes
    sample_themes = ['dark', 'light', 'corporate']
    for theme in sample_themes:
        theme_dir = os.path.join(app.config['THEMES_DIR'], theme)
        os.makedirs(theme_dir, exist_ok=True)
        
        # Create theme manifest
        with open(os.path.join(theme_dir, 'theme.json'), 'w') as f:
            json.dump({
                'name': theme,
                'version': '1.0',
                'author': 'Theme Designer'
            }, f)
        
        # Create sample assets
        assets = ['css/main.css', 'js/theme.js', 'images/logo.png']
        for asset in assets:
            asset_path = os.path.join(theme_dir, asset)
            os.makedirs(os.path.dirname(asset_path), exist_ok=True)
            with open(asset_path, 'w') as f:
                f.write(f"/* Sample {theme} theme {asset} */")
    
    app.run(host='0.0.0.0', port=8080)