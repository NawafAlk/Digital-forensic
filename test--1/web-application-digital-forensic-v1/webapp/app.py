import os
import sys
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, flash
from werkzeug.utils import secure_filename

# Ensure project root is on sys.path so we can import managers/* when running from any CWD
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Reuse investigation logic
from managers.evidence_utils import ImageHandler


class DemoImageHandler:
    """Demo handler for testing without forensic libraries"""
    def __init__(self, image_path):
        self.image_path = image_path
        self.is_wiped_image = False
    
    def get_partitions(self):
        return [(1, "Demo Partition", 2048, 1000000)]
    
    def is_wiped(self):
        return False
    
    def get_directory_contents(self, start_offset, inode_number=None):
        return [
            {
                "name": "demo_file.txt",
                "is_directory": False,
                "inode_number": 12345,
                "size": "1.2 KB",
                "accessed": "2024-01-01 12:00:00 UTC",
                "modified": "2024-01-01 12:00:00 UTC",
                "created": "2024-01-01 12:00:00 UTC",
                "changed": "2024-01-01 12:00:00 UTC"
            },
            {
                "name": "demo_folder",
                "is_directory": True,
                "inode_number": 12346,
                "size": "0 B",
                "accessed": "2024-01-01 12:00:00 UTC",
                "modified": "2024-01-01 12:00:00 UTC",
                "created": "2024-01-01 12:00:00 UTC",
                "changed": "2024-01-01 12:00:00 UTC"
            }
        ]
    
    def get_file_content(self, inode_number, offset):
        return b"This is a demo file content for testing purposes.", None
    
    def detect_file_type(self, content):
        return {'type': 'text', 'extension': 'txt', 'description': 'Text File'}
    
    def carve_files_by_type(self, file_type='all'):
        return [
            {
                "name": "demo_carved_file.txt",
                "path": "/demo_carved_file.txt",
                "size": "512 B",
                "inode": 12347,
                "type": "text",
                "extension": "txt",
                "description": "Text File",
                "accessed": "2024-01-01 12:00:00 UTC",
                "modified": "2024-01-01 12:00:00 UTC",
                "created": "2024-01-01 12:00:00 UTC",
                "changed": "2024-01-01 12:00:00 UTC"
            }
        ]
    
    def search_files(self, query):
        return [
            {
                "name": f"demo_search_{query}.txt",
                "path": f"/demo_search_{query}.txt",
                "size": "256 B",
                "accessed": "2024-01-01 12:00:00 UTC",
                "modified": "2024-01-01 12:00:00 UTC",
                "created": "2024-01-01 12:00:00 UTC",
                "changed": "2024-01-01 12:00:00 UTC",
                "inode_item": "12348"
            }
        ]


UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
ALLOWED_EXTENSIONS = {'.e01', '.E01', '.s01', '.S01', '.l01', '.L01', '.raw', '.RAW', '.img', '.IMG', '.dd', '.DD', '.iso', '.ISO', '.ad1', '.AD1', '.001', '.ex01', '.dmg', '.sparse', '.sparseimage'}


def allowed_file(filename: str) -> bool:
    _, ext = os.path.splitext(filename)
    return ext in ALLOWED_EXTENSIONS


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'dev'
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

    os.makedirs(UPLOAD_FOLDER, exist_ok=True)

    # In-memory handlers keyed by a simple token (filepath basename)
    image_handlers = {}

    @app.route('/')
    def index():
        return render_template('index.html')

    @app.route('/upload', methods=['POST'])
    def upload():
        if 'image' not in request.files:
            flash('No file part')
            return redirect(url_for('index'))
        file = request.files['image']
        if file.filename == '':
            flash('No selected file')
            return redirect(url_for('index'))
        if not allowed_file(file.filename):
            flash('Unsupported file type')
            return redirect(url_for('index'))

        filename = secure_filename(file.filename)
        saved_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(saved_path)

        try:
            handler = ImageHandler(saved_path)
            token = os.path.basename(saved_path)
            image_handlers[token] = handler
            return redirect(url_for('browse', token=token))
        except ImportError as e:
            # Create a demo handler for testing without forensic libraries
            flash(f'Forensic libraries not installed. Running in demo mode. Error: {str(e)}')
            demo_handler = DemoImageHandler(saved_path)
            token = os.path.basename(saved_path)
            image_handlers[token] = demo_handler
            return redirect(url_for('browse', token=token))
        except Exception as e:
            flash(f'Error processing image: {str(e)}')
            return redirect(url_for('index'))

    @app.route('/browse/<token>')
    def browse(token):
        handler = image_handlers.get(token)
        if not handler:
            flash('Session expired. Re-upload the image.')
            return redirect(url_for('index'))

        partitions = handler.get_partitions()
        return render_template('browse.html', token=token, partitions=partitions, wiped=handler.is_wiped())

    @app.route('/api/list', methods=['GET'])
    def api_list():
        token = request.args.get('token')
        start_offset = int(request.args.get('start_offset', '0'))
        inode = request.args.get('inode')
        inode_num = int(inode) if inode is not None else None
        handler = image_handlers.get(token)
        if not handler:
            return jsonify({'error': 'invalid token'}), 400
        entries = handler.get_directory_contents(start_offset, inode_num)
        return jsonify({'entries': entries})

    @app.route('/api/file', methods=['GET'])
    def api_file():
        token = request.args.get('token')
        inode = int(request.args.get('inode'))
        start_offset = int(request.args.get('start_offset', '0'))
        handler = image_handlers.get(token)
        if not handler:
            return jsonify({'error': 'invalid token'}), 400
        content, meta = handler.get_file_content(inode, start_offset)
        if content is None:
            return jsonify({'error': 'not found'}), 404
        
        # Create a temporary file to serve the content properly
        import tempfile
        import io
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.write(content)
        temp_file.close()
        
        try:
            return send_file(
                temp_file.name,
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=f'inode_{inode}.bin'
            )
        finally:
            # Clean up the temporary file
            import os
            try:
                os.unlink(temp_file.name)
            except:
                pass

    @app.route('/view/<token>/<int:inode>')
    def view_file(token, inode):
        start_offset = int(request.args.get('start_offset', '0'))
        handler = image_handlers.get(token)
        if not handler:
            flash('Session expired. Re-upload the image.')
            return redirect(url_for('index'))
        
        content, meta = handler.get_file_content(inode, start_offset)
        if content is None:
            flash('File not found or could not be read.')
            return redirect(url_for('browse', token=token))
        
        # Try to decode as text for display
        try:
            text_content = content.decode('utf-8')
            is_text = True
        except UnicodeDecodeError:
            text_content = content[:1000].hex()  # Show first 1000 bytes as hex
            is_text = False
        
        return render_template('view_file.html', 
                             token=token, 
                             inode=inode, 
                             content=text_content, 
                             is_text=is_text,
                             file_size=len(content))

    @app.route('/carve/<token>')
    def carve_files(token):
        handler = image_handlers.get(token)
        if not handler:
            flash('Session expired. Re-upload the image.')
            return redirect(url_for('index'))
        
        file_type = request.args.get('type', 'all')
        carved_files = handler.carve_files_by_type(file_type)
        
        return render_template('carve.html', 
                             token=token, 
                             carved_files=carved_files, 
                             file_type=file_type)

    @app.route('/api/carve', methods=['POST'])
    def api_carve():
        token = request.json.get('token')
        file_type = request.json.get('type', 'all')
        handler = image_handlers.get(token)
        
        if not handler:
            return jsonify({'error': 'invalid token'}), 400
        
        carved_files = handler.carve_files_by_type(file_type)
        return jsonify({'files': carved_files})

    @app.route('/preview/<token>/<int:inode>')
    def preview_file(token, inode):
        start_offset = int(request.args.get('start_offset', '0'))
        handler = image_handlers.get(token)
        if not handler:
            flash('Session expired. Re-upload the image.')
            return redirect(url_for('index'))
        
        content, meta = handler.get_file_content(inode, start_offset)
        if content is None:
            flash('File not found or could not be read.')
            return redirect(url_for('browse', token=token))
        
        # Detect file type and prepare preview
        file_info = handler.detect_file_type(content)
        
        return render_template('preview.html', 
                             token=token, 
                             inode=inode, 
                             content=content, 
                             file_info=file_info,
                             file_size=len(content))

    @app.route('/search')
    def search():
        token = request.args.get('token')
        query = request.args.get('q', '')
        handler = image_handlers.get(token)
        if not handler:
            return jsonify({'error': 'invalid token'}), 400
        results = handler.search_files(query)
        return render_template('search.html', token=token, results=results, query=query)

    return app


if __name__ == '__main__':
    app = create_app()
    port = int(os.getenv('PORT', '8000'))
    app.run(host='0.0.0.0', port=port, debug=True)


