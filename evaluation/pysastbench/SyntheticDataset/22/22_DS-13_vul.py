import os
from flask import Flask, request, send_file, render_template, abort, redirect, url_for

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'documents')
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'doc', 'docx'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    documents = []
    try:
        documents = [f for f in os.listdir(app.config['UPLOAD_FOLDER']) 
                    if os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], f))]
    except Exception:
        pass
    return render_template('index.html', documents=documents)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        return redirect(url_for('index'))
    
    if file and allowed_file(file.filename):
        filename = file.filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return redirect(url_for('index'))
    
    return redirect(url_for('index'))

@app.route('/download/<document_id>')
def download_document(document_id):
    try:
        # Vulnerable path traversal - document_id used directly without sanitization
        doc_path = os.path.join(app.config['UPLOAD_FOLDER'], document_id)
        
        if not os.path.exists(doc_path):
            abort(404, 'Document not found')
            
        if not os.path.isfile(doc_path):
            abort(400, 'Requested path is not a file')
            
        return send_file(doc_path, as_attachment=True)
        
    except Exception as e:
        abort(500, str(e))

@app.errorhandler(404)
def not_found(e):
    return render_template('error.html', error=str(e)), 404

@app.errorhandler(400)
def bad_request(e):
    return render_template('error.html', error=str(e)), 400

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error='Internal server error'), 500

if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
        sample_docs = ['sample1.txt', 'sample2.pdf', 'sample3.docx']
        for doc in sample_docs:
            open(os.path.join(app.config['UPLOAD_FOLDER'], doc), 'w').close()
    
    app.run(debug=True, port=5001)