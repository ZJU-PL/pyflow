import os
import tarfile
from flask import Flask, request, send_file, render_template, abort, flash, redirect

app = Flask(__name__)
app.secret_key = 'super_secret_key'
app.config['BACKUP_DIR'] = '/var/backups/configs'
app.config['CONFIG_DIR'] = '/etc/appconfigs'

@app.route('/')
def index():
    backups = []
    try:
        backups = [f for f in os.listdir(app.config['BACKUP_DIR'])
                 if f.endswith('.tar.gz')]
    except Exception:
        flash('Error accessing backup directory')
    return render_template('backup.html', backups=backups)

@app.route('/create_backup', methods=['POST'])
def create_backup():
    backup_name = request.form.get('backup_name', 'config_backup') + '.tar.gz'
    backup_path = os.path.join(app.config['BACKUP_DIR'], backup_name)
    
    try:
        with tarfile.open(backup_path, 'w:gz') as tar:
            for config_file in os.listdir(app.config['CONFIG_DIR']):
                full_path = os.path.join(app.config['CONFIG_DIR'], config_file)
                if os.path.isfile(full_path):
                    tar.add(full_path, arcname=config_file)
        flash('Backup created successfully')
    except Exception as e:
        flash(f'Backup failed: {str(e)}')
    
    return redirect('/')

@app.route('/restore_backup/<backup_file>')
def restore_config(backup_file):
    try:
        # Vulnerable path traversal - backup_file used directly without validation
        backup_path = os.path.join(app.config['BACKUP_DIR'], backup_file)
        
        if not os.path.exists(backup_path):
            abort(404, 'Backup file not found')
            
        if not tarfile.is_tarfile(backup_path):
            abort(400, 'Invalid backup file format')
            
        with tarfile.open(backup_path, 'r:gz') as tar:
            # Extract all files to config directory - vulnerable to path traversal
            tar.extractall(path=app.config['CONFIG_DIR'])
            
        flash('Configuration restored successfully')
        return redirect('/')
        
    except Exception as e:
        abort(500, f'Restoration failed: {str(e)}')

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error=str(e)), 404

@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', error=str(e)), 400

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error=str(e)), 500

if __name__ == '__main__':
    if not os.path.exists(app.config['BACKUP_DIR']):
        os.makedirs(app.config['BACKUP_DIR'])
    if not os.path.exists(app.config['CONFIG_DIR']):
        os.makedirs(app.config['CONFIG_DIR'])
        # Create sample config files
        for i in range(1, 4):
            with open(os.path.join(app.config['CONFIG_DIR'], f'config{i}.ini'), 'w') as f:
                f.write(f'[DEFAULT]\nsetting{i} = value{i}\n')
    
    app.run(host='0.0.0.0', port=8080)