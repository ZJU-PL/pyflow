import os
from flask import Flask, request, render_template, abort, send_file, Response
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['LOG_DIR'] = os.path.abspath('/var/log')
app.config['MAX_LOG_SIZE'] = 1024 * 1024  # 1MB
app.config['ALLOWED_LOG_PREFIXES'] = ['system', 'application', 'security']  # Whitelist allowed log prefixes

def is_safe_log_path(path):
    """Validate log path meets security requirements"""
    # Convert to absolute path and normalize
    abs_path = os.path.abspath(path)
    
    # Ensure path is within LOG_DIR
    if not abs_path.startswith(app.config['LOG_DIR'] + os.sep):
        return False
    
    # Check file extension
    if not abs_path.endswith('.log'):
        return False
    
    # Check filename prefix against whitelist
    filename = os.path.basename(abs_path)
    if not any(filename.startswith(prefix) for prefix in app.config['ALLOWED_LOG_PREFIXES']):
        return False
    
    # Prevent symlink attacks
    if os.path.islink(abs_path):
        return False
        
    return True

@app.route('/')
def index():
    log_files = []
    try:
        log_files = [f for f in os.listdir(app.config['LOG_DIR']) 
                    if f.endswith('.log') and
                    any(f.startswith(prefix) for prefix in app.config['ALLOWED_LOG_PREFIXES'])]
    except Exception as e:
        app.logger.error(f"Error listing log files: {e}")
    return render_template('logs.html', log_files=log_files)

@app.route('/view')
def view_log():
    log_file = request.args.get('file')
    if not log_file or not isinstance(log_file, str):
        abort(400, 'Invalid log file request')

    try:
        # Secure the filename and validate path
        safe_filename = secure_filename(log_file)
        log_path = os.path.join(app.config['LOG_DIR'], safe_filename)
        
        if not is_safe_log_path(log_path):
            abort(403, 'Access denied')
            
        if not os.path.exists(log_path):
            abort(404, 'Log file not found')
            
        if not os.path.isfile(log_path):
            abort(400, 'Invalid log file')
            
        file_size = os.path.getsize(log_path)
        if file_size > app.config['MAX_LOG_SIZE']:
            return Response("Log file too large", mimetype='text/plain')
            
        with open(log_path, 'r') as f:
            content = f.read()
            
        return render_template('view_log.html', 
                            log_name=safe_filename,
                            log_content=content)
        
    except PermissionError:
        abort(403, 'Permission denied')
    except Exception as e:
        app.logger.error(f"Error reading log: {e}")
        abort(500, 'Internal server error')

@app.route('/download')
def download_log():
    log_file = request.args.get('file')
    if not log_file or not isinstance(log_file, str):
        abort(400, 'Invalid log file request')

    try:
        # Secure the filename and validate path
        safe_filename = secure_filename(log_file)
        log_path = os.path.join(app.config['LOG_DIR'], safe_filename)
        
        if not is_safe_log_path(log_path):
            abort(403, 'Access denied')
            
        if not os.path.exists(log_path):
            abort(404, 'Log file not found')
            
        if not os.path.isfile(log_path):
            abort(400, 'Invalid log file')
            
        return send_file(log_path, as_attachment=True)
        
    except PermissionError:
        abort(403, 'Permission denied')
    except Exception as e:
        app.logger.error(f"Error downloading log: {e}")
        abort(500, 'Internal server error')

@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', error='Invalid request'), 400

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', error='Access denied'), 403

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error='Resource not found'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error='Internal server error'), 500

if __name__ == '__main__':
    # Create sample log directory with secure permissions
    os.makedirs(app.config['LOG_DIR'], mode=0o750, exist_ok=True)
    
    sample_logs = ['system.log', 'application.log', 'security.log']
    for log in sample_logs:
        log_path = os.path.join(app.config['LOG_DIR'], log)
        if not os.path.exists(log_path):
            try:
                with open(log_path, 'w') as f:
                    f.write(f"Sample log entries for {log}\n" + "Log line\n"*20)
                os.chmod(log_path, 0o640)  # Secure file permissions
            except Exception as e:
                app.logger.error(f"Error creating sample log {log}: {e}")
    
    app.run(host='0.0.0.0', port=8000)