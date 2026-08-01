import os
import tarfile
from flask import Flask, request, send_file, render_template, abort, flash, redirect
from werkzeug.utils import secure_filename
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Generate secure random key
app.config['BACKUP_DIR'] = os.path.abspath('/var/backups/configs')
app.config['CONFIG_DIR'] = os.path.abspath('/etc/appconfigs')
app.config['MAX_BACKUP_SIZE'] = 10 * 1024 * 1024  # 10MB limit

def is_safe_path(base_path, requested_path):
    """Check if requested path is within base directory"""
    base_path = os.path.abspath(base_path)
    requested_path = os.path.abspath(requested_path)
    return requested_path.startswith(base_path + os.sep)

def validate_backup_filename(filename):
    """Validate backup filename meets security requirements"""
    if not filename or not isinstance(filename, str):
        return False
    if not filename.endswith('.tar.gz'):
        return False
    if '../' in filename or '~' in filename:
        return False
    return True

def safe_extract(tar, path):
    """Safely extract tar file ensuring no path traversal"""
    for member in tar.getmembers():
        member_path = os.path.abspath(os.path.join(path, member.name))
        if not is_safe_path(path, member_path):
            raise ValueError(f"Attempted path traversal in tar file: {member.name}")
        tar.extract(member, path)

@app.route('/')
def index():
    backups = []
    try:
        backups = [f for f in os.listdir(app.config['BACKUP_DIR'])
                 if f.endswith('.tar.gz') and 
                 is_safe_path(app.config['BACKUP_DIR'], os.path.join(app.config['BACKUP_DIR'], f))]
    except Exception as e:
        app.logger.error(f"Error accessing backup directory: {e}")
        flash('Error accessing backup directory')
    return render_template('backup.html', backups=backups)

@app.route('/create_backup', methods=['POST'])
def create_backup():
    backup_name = secure_filename(request.form.get('backup_name', 'config_backup')) + '.tar.gz'
    backup_path = os.path.join(app.config['BACKUP_DIR'], backup_name)
    
    if not is_safe_path(app.config['BACKUP_DIR'], backup_path):
        flash('Invalid backup name')
        return redirect('/')
    
    try:
        with tarfile.open(backup_path, 'w:gz') as tar:
            for config_file in os.listdir(app.config['CONFIG_DIR']):
                full_path = os.path.join(app.config['CONFIG_DIR'], config_file)
                if os.path.isfile(full_path) and is_safe_path(app.config['CONFIG_DIR'], full_path):
                    tar.add(full_path, arcname=config_file)
        
        # Verify backup size
        if os.path.getsize(backup_path) > app.config['MAX_BACKUP_SIZE']:
            os.remove(backup_path)
            flash('Backup too large')
            return redirect('/')
            
        flash('Backup created successfully')
    except Exception as e:
        app.logger.error(f"Backup failed: {e}")
        flash('Backup failed')
    
    return redirect('/')

@app.route('/restore_backup/<backup_file>')
def restore_config(backup_file):
    try:
        # Validate backup filename
        if not validate_backup_filename(backup_file):
            abort(400, 'Invalid backup file')
            
        backup_path = os.path.join(app.config['BACKUP_DIR'], backup_file)
        
        # Validate path is safe
        if not is_safe_path(app.config['BACKUP_DIR'], backup_path):
            abort(403, 'Access denied')
            
        if not os.path.exists(backup_path):
            abort(404, 'Backup file not found')
            
        if not tarfile.is_tarfile(backup_path):
            abort(400, 'Invalid backup file format')
            
        # Safe extraction
        with tarfile.open(backup_path, 'r:gz') as tar:
            safe_extract(tar, path=app.config['CONFIG_DIR'])
            
        flash('Configuration restored successfully')
        return redirect('/')
        
    except ValueError as e:
        app.logger.error(f"Security violation during restore: {e}")
        abort(400, 'Invalid backup contents')
    except Exception as e:
        app.logger.error(f"Restoration failed: {e}")
        abort(500, 'Restoration failed')

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error='Resource not found'), 404

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
    # Secure directory creation
    os.makedirs(app.config['BACKUP_DIR'], mode=0o750, exist_ok=True)
    os.makedirs(app.config['CONFIG_DIR'], mode=0o750, exist_ok=True)
    
    # Create sample config files
    for i in range(1, 4):
        config_path = os.path.join(app.config['CONFIG_DIR'], f'config{i}.ini')
        try:
            with open(config_path, 'w') as f:
                f.write(f'[DEFAULT]\nsetting{i} = value{i}\n')
            os.chmod(config_path, 0o640)  # Secure file permissions
        except Exception as e:
            app.logger.error(f"Error creating sample config: {e}")
    
    app.run(host='0.0.0.0', port=8080)