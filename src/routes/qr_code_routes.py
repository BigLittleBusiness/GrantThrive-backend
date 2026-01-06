"""
QR Code API Routes for GrantThrive Platform
Handles QR code generation and management for grant programs
"""

from flask import Blueprint, request, jsonify, send_file
import os
from ..services.qr_code_service import QRCodeService

qr_code_bp = Blueprint('qr_code_bp', __name__)

# Initialize QR code service
qr_service = QRCodeService()

@qr_code_bp.route('/qr-codes/generate', methods=['POST'])
def generate_qr_code():
    """
    Generate QR code for a grant program
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                "status": "error",
                "message": "No grant data provided"
            }), 400
        
        # Validate required fields
        if 'grant_id' not in data:
            return jsonify({
                "status": "error",
                "message": "Grant ID is required"
            }), 400
        
        # Get optional parameters
        style = data.get('style', 'professional')
        include_logo = data.get('include_logo', True)
        
        # Generate QR code
        success, result = qr_service.generate_grant_qr_code(data, style, include_logo)
        
        if success:
            return jsonify({
                "status": "success",
                "message": "QR code generated successfully",
                "data": result
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": result
            }), 500
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error generating QR code: {str(e)}"
        }), 500

@qr_code_bp.route('/qr-codes/generate-base64', methods=['POST'])
def generate_qr_code_base64():
    """
    Generate QR code as base64 string for embedding
    """
    try:
        data = request.get_json()
        
        if not data or 'grant_id' not in data:
            return jsonify({
                "status": "error",
                "message": "Grant ID is required"
            }), 400
        
        style = data.get('style', 'professional')
        
        success, result = qr_service.generate_qr_code_base64(data, style)
        
        if success:
            return jsonify({
                "status": "success",
                "message": "QR code generated as base64",
                "data": {
                    "grant_id": data['grant_id'],
                    "base64_image": result,
                    "style": style
                }
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": result
            }), 500
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error generating base64 QR code: {str(e)}"
        }), 500

@qr_code_bp.route('/qr-codes/bulk-generate', methods=['POST'])
def generate_bulk_qr_codes():
    """
    Generate QR codes for multiple grants
    """
    try:
        data = request.get_json()
        
        if not data or 'grants' not in data:
            return jsonify({
                "status": "error",
                "message": "Grants list is required"
            }), 400
        
        grants_list = data['grants']
        style = data.get('style', 'professional')
        
        if not isinstance(grants_list, list) or len(grants_list) == 0:
            return jsonify({
                "status": "error",
                "message": "Grants must be a non-empty list"
            }), 400
        
        success, result = qr_service.generate_bulk_qr_codes(grants_list, style)
        
        if success:
            return jsonify({
                "status": "success",
                "message": f"Bulk QR code generation completed",
                "data": result
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": result
            }), 500
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error generating bulk QR codes: {str(e)}"
        }), 500

@qr_code_bp.route('/qr-codes/styles', methods=['GET'])
def get_qr_code_styles():
    """
    Get available QR code styles
    """
    try:
        styles = qr_service.get_qr_code_styles()
        
        return jsonify({
            "status": "success",
            "data": {
                "styles": styles
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error retrieving QR code styles: {str(e)}"
        }), 500

@qr_code_bp.route('/qr-codes/analytics/<grant_id>', methods=['GET'])
def get_qr_code_analytics(grant_id):
    """
    Get QR code analytics for a specific grant
    """
    try:
        analytics = qr_service.get_qr_code_analytics(grant_id)
        
        return jsonify({
            "status": "success",
            "data": analytics
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error retrieving QR code analytics: {str(e)}"
        }), 500

@qr_code_bp.route('/qr-codes/cleanup', methods=['POST'])
def cleanup_old_qr_codes():
    """
    Clean up old QR code files
    """
    try:
        data = request.get_json() or {}
        days_old = data.get('days_old', 30)
        
        success, result = qr_service.cleanup_old_qr_codes(days_old)
        
        if success:
            return jsonify({
                "status": "success",
                "message": "QR code cleanup completed",
                "data": result
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": result
            }), 500
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error during QR code cleanup: {str(e)}"
        }), 500

@qr_code_bp.route('/qr-codes/download/<filename>', methods=['GET'])
def download_qr_code(filename):
    """
    Download a specific QR code file
    """
    try:
        qr_codes_dir = os.path.join(os.path.dirname(__file__), '..', 'static', 'qr_codes')
        file_path = os.path.join(qr_codes_dir, filename)
        
        if not os.path.exists(file_path):
            return jsonify({
                "status": "error",
                "message": "QR code file not found"
            }), 404
        
        return send_file(file_path, as_attachment=True, download_name=filename)
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error downloading QR code: {str(e)}"
        }), 500

@qr_code_bp.route('/qr-codes/preview', methods=['POST'])
def preview_qr_code():
    """
    Generate a preview QR code without saving to disk
    """
    try:
        data = request.get_json()
        
        if not data or 'grant_id' not in data:
            return jsonify({
                "status": "error",
                "message": "Grant ID is required"
            }), 400
        
        # Generate base64 version for preview
        style = data.get('style', 'professional')
        success, result = qr_service.generate_qr_code_base64(data, style)
        
        if success:
            return jsonify({
                "status": "success",
                "message": "QR code preview generated",
                "data": {
                    "grant_id": data['grant_id'],
                    "preview_base64": result,
                    "style": style,
                    "target_url": f"{qr_service.base_url}/grants/{data['grant_id']}"
                }
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": result
            }), 500
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error generating QR code preview: {str(e)}"
        }), 500

@qr_code_bp.route('/qr-codes/regenerate/<grant_id>', methods=['POST'])
def regenerate_qr_code(grant_id):
    """
    Regenerate QR code for an existing grant
    """
    try:
        data = request.get_json() or {}
        
        # Add grant_id to data
        data['grant_id'] = grant_id
        
        # Get style preference
        style = data.get('style', 'professional')
        include_logo = data.get('include_logo', True)
        
        # Generate new QR code
        success, result = qr_service.generate_grant_qr_code(data, style, include_logo)
        
        if success:
            return jsonify({
                "status": "success",
                "message": "QR code regenerated successfully",
                "data": result
            }), 200
        else:
            return jsonify({
                "status": "error",
                "message": result
            }), 500
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error regenerating QR code: {str(e)}"
        }), 500

@qr_code_bp.route('/qr-codes/batch-download', methods=['POST'])
def batch_download_qr_codes():
    """
    Create a ZIP file containing multiple QR codes for download
    """
    try:
        import zipfile
        import tempfile
        from datetime import datetime
        
        data = request.get_json()
        
        if not data or 'grant_ids' not in data:
            return jsonify({
                "status": "error",
                "message": "Grant IDs list is required"
            }), 400
        
        grant_ids = data['grant_ids']
        
        if not isinstance(grant_ids, list) or len(grant_ids) == 0:
            return jsonify({
                "status": "error",
                "message": "Grant IDs must be a non-empty list"
            }), 400
        
        # Create temporary ZIP file
        temp_dir = tempfile.mkdtemp()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        zip_filename = f"grant_qr_codes_{timestamp}.zip"
        zip_path = os.path.join(temp_dir, zip_filename)
        
        qr_codes_dir = os.path.join(os.path.dirname(__file__), '..', 'static', 'qr_codes')
        
        with zipfile.ZipFile(zip_path, 'w') as zip_file:
            for grant_id in grant_ids:
                # Find QR code files for this grant
                for filename in os.listdir(qr_codes_dir):
                    if filename.startswith(f"grant_{grant_id}_") and filename.endswith('.png'):
                        file_path = os.path.join(qr_codes_dir, filename)
                        zip_file.write(file_path, filename)
                        break  # Only include the most recent QR code for each grant
        
        return send_file(zip_path, as_attachment=True, download_name=zip_filename)
        
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": f"Error creating batch download: {str(e)}"
        }), 500

