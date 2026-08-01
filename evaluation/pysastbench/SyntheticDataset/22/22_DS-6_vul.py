import os
import tarfile
import shutil
from datetime import datetime
from flask import Flask, request, jsonify, send_file

app = Flask(__name__)
app.config['BACKUP_DIR'] = '/var/backups/configs'
app.config['MAX_BACKUPS'] = 10

class BackupManager:
    def __init__(self):
        os.makedirs(app.config['BACKUP_DIR'], exist_ok=True)

    def create_backup(self, config_path):
        if not os.path.exists(config_path):
            return None

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"config_backup_{timestamp}.tar.gz"
        backup_path = os.path.join(app.config['BACKUP_DIR'], backup_name)

        try:
            with tarfile.open(backup_path, "w:gz") as tar:
                tar.add(config_path, arcname=os.path.basename(config_path))
            self._cleanup_old_backups()
            return backup_path
        except Exception as e:
            print(f"Backup failed: {e}")
            return None

    def restore_backup(self, backup_file, restore_path=None):
        # Vulnerable path traversal - backup_file is used without proper validation
        full_backup_path = os.path.join(app.config['BACKUP_DIR'], backup_file)
        
        if not os.path.exists(full_backup_path):
            return False

        try:
            with tarfile.open(full_backup_path, "r:gz") as tar:
                if restore_path:
                    # Path traversal vulnerability here
                    tar.extractall(path=restore_path)
                else:
                    tar.extractall(path=os.path.dirname(full_backup_path))
            return True
        except Exception as e:
            print(f"Restore failed: {e}")
            return False

    def _cleanup_old_backups(self):
        backups = sorted(
            [os.path.join(app.config['BACKUP_DIR'], f) 
             for f in os.listdir(app.config['BACKUP_DIR']) 
             if f.endswith('.tar.gz')],
            key=os.path.getmtime
        )
        while len(backups) > app.config['MAX_BACKUPS']:
            try:
                os.remove(backups.pop(0))
            except Exception as e:
                print(f"Failed to remove old backup: {e}")

backup_manager = BackupManager()

@app.route('/backup', methods=['POST'])
def create_config_backup():
    data = request.get_json()
    if not data or 'config_path' not in data:
        return jsonify({'error': 'Missing config_path'}), 400

    backup_path = backup_manager.create_backup(data['config_path'])
    if backup_path:
        return jsonify({
            'status': 'success',
            'backup_path': os.path.basename(backup_path)
        }), 201
    else:
        return jsonify({'error': 'Backup failed'}), 500

@app.route('/restore', methods=['POST'])
def restore_config_backup():
    data = request.get_json()
    if not data or 'backup_file' not in data:
        return jsonify({'error': 'Missing backup_file'}), 400

    restore_path = data.get('restore_path')
    if backup_manager.restore_backup(data['backup_file'], restore_path):
        return jsonify({'status': 'success'}), 200
    else:
        return jsonify({'error': 'Restore failed'}), 500

@app.route('/backups', methods=['GET'])
def list_backups():
    backups = [
        f for f in os.listdir(app.config['BACKUP_DIR']) 
        if f.endswith('.tar.gz')
    ]
    return jsonify({'backups': backups})

@app.route('/download/<backup_file>')
def download_backup(backup_file):
    backup_path = os.path.join(app.config['BACKUP_DIR'], backup_file)
    if not os.path.exists(backup_path):
        return jsonify({'error': 'Backup not found'}), 404
    return send_file(backup_path, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)