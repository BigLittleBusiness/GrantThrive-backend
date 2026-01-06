from flask import Blueprint, request, jsonify, send_file, current_app
from werkzeug.utils import secure_filename
from src.routes.auth import verify_token
from src.models.user import User
import os
import uuid
from datetime import datetime
import mimetypes

files_bp = Blueprint('files', __name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
MAX_FILE_SIZE = 16 * 1024 * 1024  # 16MB
ALLOWED_EXTENSIONS = {
    'pdf', 'doc', 'docx', 'txt', 'rtf',  # Documents
    'jpg', 'jpeg', 'png', 'gif', 'bmp',  # Images
    'xls', 'xlsx', 'csv',  # Spreadsheets
    'zip', 'rar'  # Archives
}

def require_auth(f):
    """Decorator to require authentication"""
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401
        
        token = auth_header.split(' ')[1]
        user_id = verify_token(token)
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        
        user = User.query.get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 401
        
        request.current_user = user
        return f(*args, **kwargs)
    
    decorated_function.__name__ = f.__name__
    return decorated_function

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_type(filename):
    """Get file type category"""
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    
    if ext in ['pdf', 'doc', 'docx', 'txt', 'rtf']:
        return 'document'
    elif ext in ['jpg', 'jpeg', 'png', 'gif', 'bmp']:
        return 'image'
    elif ext in ['xls', 'xlsx', 'csv']:
        return 'spreadsheet'
    elif ext in ['zip', 'rar']:
        return 'archive'
    else:
        return 'other'

def ensure_upload_directory():
    """Ensure upload directory exists"""
    upload_path = os.path.join(current_app.root_path, UPLOAD_FOLDER)
    if not os.path.exists(upload_path):
        os.makedirs(upload_path)
    return upload_path

@files_bp.route('/files/upload', methods=['POST'])
@require_auth
def upload_file():
    """Upload file endpoint"""
    try:
        # Check if file is in request
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        # Check if file is selected
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Check file size
        if request.content_length > MAX_FILE_SIZE:
            return jsonify({'error': f'File too large. Maximum size is {MAX_FILE_SIZE // (1024*1024)}MB'}), 400
        
        # Check file extension
        if not allowed_file(file.filename):
            return jsonify({'error': 'File type not allowed'}), 400
        
        # Generate secure filename
        original_filename = secure_filename(file.filename)
        file_extension = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
        unique_filename = f"{uuid.uuid4().hex}.{file_extension}"
        
        # Ensure upload directory exists
        upload_path = ensure_upload_directory()
        
        # Save file
        file_path = os.path.join(upload_path, unique_filename)
        file.save(file_path)
        
        # Get file info
        file_size = os.path.getsize(file_path)
        file_type = get_file_type(original_filename)
        mime_type = mimetypes.guess_type(original_filename)[0] or 'application/octet-stream'
        
        # Create file record (in a full implementation, you'd save this to database)
        file_info = {
            'id': unique_filename,
            'original_name': original_filename,
            'filename': unique_filename,
            'file_path': file_path,
            'file_size': file_size,
            'file_type': file_type,
            'mime_type': mime_type,
            'uploaded_by': request.current_user.id,
            'uploaded_at': datetime.utcnow().isoformat(),
            'url': f'/api/files/{unique_filename}'
        }
        
        return jsonify({
            'message': 'File uploaded successfully',
            'file': file_info
        }), 201
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@files_bp.route('/files/<filename>', methods=['GET'])
def download_file(filename):
    """Download file endpoint"""
    try:
        # Validate filename
        if not filename or '..' in filename:
            return jsonify({'error': 'Invalid filename'}), 400
        
        upload_path = ensure_upload_directory()
        file_path = os.path.join(upload_path, filename)
        
        # Check if file exists
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Get original filename (in a full implementation, this would come from database)
        # For now, we'll use the stored filename
        return send_file(file_path, as_attachment=True, download_name=filename)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@files_bp.route('/files/<filename>/info', methods=['GET'])
@require_auth
def get_file_info(filename):
    """Get file information"""
    try:
        upload_path = ensure_upload_directory()
        file_path = os.path.join(upload_path, filename)
        
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Get file stats
        file_stats = os.stat(file_path)
        file_size = file_stats.st_size
        created_time = datetime.fromtimestamp(file_stats.st_ctime)
        
        file_info = {
            'filename': filename,
            'file_size': file_size,
            'file_type': get_file_type(filename),
            'created_at': created_time.isoformat(),
            'url': f'/api/files/{filename}'
        }
        
        return jsonify(file_info), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@files_bp.route('/files/<filename>', methods=['DELETE'])
@require_auth
def delete_file(filename):
    """Delete file endpoint"""
    try:
        # Validate filename
        if not filename or '..' in filename:
            return jsonify({'error': 'Invalid filename'}), 400
        
        upload_path = ensure_upload_directory()
        file_path = os.path.join(upload_path, filename)
        
        # Check if file exists
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        # Delete file
        os.remove(file_path)
        
        return jsonify({'message': 'File deleted successfully'}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@files_bp.route('/files/user/<int:user_id>', methods=['GET'])
@require_auth
def get_user_files(user_id):
    """Get files uploaded by specific user"""
    try:
        # Check permissions
        if request.current_user.id != user_id and not request.current_user.is_admin:
            return jsonify({'error': 'Permission denied'}), 403
        
        upload_path = ensure_upload_directory()
        
        # In a full implementation, you'd query the database for files by user
        # For now, we'll return a placeholder response
        files = []
        
        return jsonify({
            'files': files,
            'count': len(files)
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@files_bp.route('/files/config', methods=['GET'])
def get_upload_config():
    """Get upload configuration"""
    return jsonify({
        'max_file_size': MAX_FILE_SIZE,
        'max_file_size_mb': MAX_FILE_SIZE // (1024 * 1024),
        'allowed_extensions': list(ALLOWED_EXTENSIONS),
        'allowed_types': {
            'documents': ['pdf', 'doc', 'docx', 'txt', 'rtf'],
            'images': ['jpg', 'jpeg', 'png', 'gif', 'bmp'],
            'spreadsheets': ['xls', 'xlsx', 'csv'],
            'archives': ['zip', 'rar']
        }
    }), 200

